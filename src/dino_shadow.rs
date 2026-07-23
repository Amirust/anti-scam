use std::sync::Arc;

use poise::serenity_prelude as serenity;
use serenity::all::{CreateAttachment, CreateMessage};

use crate::config::CONFIG;
use crate::db::{Database, DinoObservation};
use crate::detection::Verdict;
use crate::dino::DinoRuntime;
use crate::dino_dataset::{self, RefKind};
use crate::embeds::get_dino_shadow_embed;
use crate::interactions;

/// hash pipeline verdict stored with every observation: "clean" rows build
/// the negative distribution, "ban"/"review" rows are positive-band samples
pub fn verdict_tag(verdict: &Verdict) -> &'static str {
    match verdict {
        Verdict::Ban { .. } => "ban",
        Verdict::Review { .. } => "review",
        Verdict::Clean => "clean",
    }
}

/// one embedding measurement against the reference dataset
pub struct ShadowMatch {
    pub entry_name: String,
    pub similarity: f32,
    /// closest negative reference, when any exist
    pub negative: Option<(String, f32)>,
}

/// embed the image and rank it against the current snapshot; `None` while the
/// scam reference list is empty
pub async fn measure(
    runtime: Arc<DinoRuntime>,
    bytes: bytes::Bytes,
) -> Result<Option<ShadowMatch>, crate::Error> {
    tokio::task::spawn_blocking(move || {
        let refs = runtime.store.snapshot();
        let Some(_) = refs.scams.first() else {
            return Ok(None);
        };

        let embedding = runtime.embedder.embed(&bytes)?;
        let Some((best, similarity)) = dino_dataset::best_match(&embedding, &refs.scams) else {
            return Ok(None);
        };
        let negative = dino_dataset::best_match(&embedding, &refs.negatives)
            .map(|(entry, similarity)| (entry.name.clone(), similarity));

        Ok(Some(ShadowMatch {
            entry_name: best.name.clone(),
            similarity,
            negative,
        }))
    })
    .await?
}

/// review gate: close enough to a scam reference and not explained away by a
/// negative reference
pub fn exceeds_review_gate(shadow_match: &ShadowMatch) -> bool {
    let dino = &CONFIG.dino;
    if shadow_match.similarity < dino.review_threshold {
        return false;
    }
    shadow_match
        .negative
        .as_ref()
        .is_none_or(|(_, negative)| shadow_match.similarity > negative + dino.negative_margin)
}

/// shadow mode: measure, log the observation, and — only when the hash
/// pipeline saw nothing but the embedding gate trips — post a labeling card;
/// never bans, never deletes
pub async fn shadow_pass(
    ctx: &serenity::Context,
    message: &serenity::Message,
    db: &Database,
    runtime: Arc<DinoRuntime>,
    bytes: bytes::Bytes,
    filename: &str,
    hash_verdict: &'static str,
) {
    if let Err(e) = try_shadow_pass(ctx, message, db, runtime, bytes, filename, hash_verdict).await
    {
        tracing::warn!("dino shadow pass failed for message {}: {e}", message.id);
    }
}

async fn try_shadow_pass(
    ctx: &serenity::Context,
    message: &serenity::Message,
    db: &Database,
    runtime: Arc<DinoRuntime>,
    bytes: bytes::Bytes,
    filename: &str,
    hash_verdict: &'static str,
) -> Result<(), crate::Error> {
    let Some(guild_id) = message.guild_id else {
        // observations are per-guild rows and cards need an admin channel
        tracing::info!("message {} is not in a guild, dino shadow skipped", message.id);
        return Ok(());
    };

    let Some(shadow_match) = measure(runtime, bytes.clone()).await? else {
        tracing::debug!("dino scam reference list is empty, message {} skipped", message.id);
        return Ok(());
    };

    let observation_id = db
        .insert_dino_observation(&DinoObservation {
            guild_id: guild_id.to_string(),
            channel_id: message.channel_id.to_string(),
            message_id: message.id.to_string(),
            author_id: message.author.id.to_string(),
            entry_name: shadow_match.entry_name.clone(),
            similarity: shadow_match.similarity as f64,
            best_negative_similarity: shadow_match.negative.as_ref().map(|(_, s)| *s as f64),
            hash_verdict,
        })
        .await?;

    let negative_note = shadow_match
        .negative
        .as_ref()
        .map(|(name, similarity)| format!(", closest negative \"{name}\" at {similarity:.4}"))
        .unwrap_or_default();
    tracing::info!(
        "dino shadow: message {} best-matches \"{}\" at {:.4}{negative_note} \
         (hash verdict: {hash_verdict}, observation {observation_id})",
        message.id,
        shadow_match.entry_name,
        shadow_match.similarity,
    );

    // hash-flagged images already produced a human-facing report
    if hash_verdict != "clean" {
        return Ok(());
    }
    if !exceeds_review_gate(&shadow_match) {
        if shadow_match.similarity >= CONFIG.dino.review_threshold {
            tracing::info!("dino observation {observation_id}: card suppressed by negative margin");
        }
        return Ok(());
    }

    let Some(channel) = notification_channel(db, guild_id).await? else {
        tracing::debug!("guild {guild_id} has no notification channel, shadow card dropped");
        return Ok(());
    };

    let card = CreateMessage::new()
        .embed(get_dino_shadow_embed(
            &message.author,
            message.link(),
            &shadow_match,
            filename,
        ))
        .components(interactions::dino_label_buttons(observation_id))
        .add_file(CreateAttachment::bytes(bytes.to_vec(), filename.to_string()));
    channel.send_message(&ctx.http, card).await?;

    Ok(())
}

async fn notification_channel(
    db: &Database,
    guild_id: serenity::GuildId,
) -> Result<Option<serenity::ChannelId>, crate::Error> {
    let channel = db
        .get_notification_channel(&guild_id.to_string())
        .await?
        .and_then(|id| id.parse::<u64>().ok())
        .map(serenity::ChannelId::new);
    Ok(channel)
}

/// full handling of a card label: keep the pixels (re-exports and eval need
/// them) and feed the dataset — a confirmed scam becomes a scam reference, a
/// hard negative becomes a negative reference
pub async fn process_label(
    http: &reqwest::Client,
    image_url: &str,
    runtime: Option<Arc<DinoRuntime>>,
    observation_id: i64,
    label: &'static str,
    add_kind: Option<RefKind>,
) -> Result<(), crate::Error> {
    let bytes = http
        .get(image_url)
        .send()
        .await?
        .error_for_status()?
        .bytes()
        .await?;

    let path = save_capture(label, &format!("{observation_id}"), &extension_from_url(image_url), &bytes)?;
    tracing::info!("dino observation {observation_id} image captured to {}", path.display());

    let (Some(kind), Some(runtime)) = (add_kind, runtime) else {
        return Ok(());
    };

    let name = match kind {
        RefKind::Scam => format!("card_tp_{observation_id}"),
        RefKind::Negative => format!("card_hn_{observation_id}"),
    };
    let embedding = tokio::task::spawn_blocking({
        let bytes = bytes.clone();
        move || runtime.embedder.embed(&bytes).map(|embedding| (runtime, embedding))
    })
    .await?;
    let (runtime, embedding) = embedding?;

    let outcome = runtime.store.add(kind, name, embedding).await?;
    tracing::info!("dino observation {observation_id}: {}", outcome.describe(kind));
    Ok(())
}

/// save reference pixels under the captures dir as `<group>/<name>.<ext>`
pub fn save_capture(
    group: &str,
    name: &str,
    extension: &str,
    bytes: &[u8],
) -> Result<std::path::PathBuf, crate::Error> {
    let safe_name = name.replace(['/', '\\'], "_");
    let dir = std::path::Path::new(&CONFIG.dino.captures_dir).join(group);
    std::fs::create_dir_all(&dir)?;

    let path = dir.join(format!("{safe_name}.{extension}"));
    std::fs::write(&path, bytes)?;
    Ok(path)
}

/// image extension from a CDN url path, query string stripped; captures are
/// consumed by the extension-filtering `dino-export`, so unknown ones fall
/// back to jpg
pub fn extension_from_url(url: &str) -> String {
    url.rsplit('/')
        .next()
        .and_then(|segment| segment.split('?').next())
        .and_then(|name| name.rsplit_once('.').map(|(_, ext)| ext))
        .filter(|ext| !ext.is_empty() && ext.len() <= 5 && ext.chars().all(char::is_alphanumeric))
        .map(str::to_lowercase)
        .unwrap_or_else(|| "jpg".to_string())
}

#[cfg(test)]
mod tests {
    use super::*;

    fn shadow_match(similarity: f32, negative: Option<f32>) -> ShadowMatch {
        ShadowMatch {
            entry_name: "scam".to_string(),
            similarity,
            negative: negative.map(|s| ("legit".to_string(), s)),
        }
    }

    #[test]
    fn gate_passes_above_threshold_without_negatives() {
        assert!(exceeds_review_gate(&shadow_match(0.8, None)));
    }

    #[test]
    fn gate_rejects_below_threshold() {
        assert!(!exceeds_review_gate(&shadow_match(0.5, None)));
    }

    #[test]
    fn gate_rejects_when_negative_is_closer() {
        // 0.8 scam vs 0.78 negative: within the default 0.05 margin
        assert!(!exceeds_review_gate(&shadow_match(0.8, Some(0.78))));
    }

    #[test]
    fn gate_passes_when_scam_beats_negative_by_margin() {
        assert!(exceeds_review_gate(&shadow_match(0.9, Some(0.6))));
    }

    #[test]
    fn extension_from_cdn_url_strips_query() {
        let url = "https://cdn.discordapp.com/attachments/1/2/scam.PNG?ex=abc&is=def";

        assert_eq!(extension_from_url(url), "png");
    }

    #[test]
    fn extension_falls_back_to_jpg() {
        assert_eq!(extension_from_url("https://cdn.discordapp.com/attachments/1/2/noext"), "jpg");
        assert_eq!(extension_from_url("https://x.example/a.b/"), "jpg");
    }
}
