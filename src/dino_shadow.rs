use std::sync::Arc;

use poise::serenity_prelude as serenity;
use serenity::all::{CreateAttachment, CreateMessage};

use crate::config::CONFIG;
use crate::db::{Database, DinoObservation};
use crate::detection::Verdict;
use crate::dino::DinoRuntime;
use crate::embeds::get_dino_shadow_embed;
use crate::interactions;

/// how the hashing pipeline judged the image, stored with every observation:
/// "ban"/"review" rows are free positive-band calibration data, "clean" rows
/// build the negative distribution the dataset lacks
pub fn verdict_tag(verdict: &Verdict) -> &'static str {
    match verdict {
        Verdict::Ban { .. } => "ban",
        Verdict::Review { .. } => "review",
        Verdict::Clean => "clean",
    }
}

/// shadow mode: embed the image, log the observation, and — only when the
/// hash pipeline saw nothing but the embedding looks close — post a labeling
/// card to the admin channel; never bans, never deletes
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

    let image_bytes = bytes.clone();
    let (entry_name, similarity) = tokio::task::spawn_blocking(move || {
        let embedding = runtime.embedder.embed(&bytes)?;
        // refs are validated non-empty at startup
        let (best, similarity) = crate::dino_dataset::best_match(&embedding, &runtime.refs)
            .ok_or("dino reference dataset is empty")?;
        Ok::<_, crate::Error>((best.name.clone(), similarity))
    })
    .await??;

    let observation_id = db
        .insert_dino_observation(&DinoObservation {
            guild_id: guild_id.to_string(),
            channel_id: message.channel_id.to_string(),
            message_id: message.id.to_string(),
            author_id: message.author.id.to_string(),
            entry_name: entry_name.clone(),
            similarity: similarity as f64,
            hash_verdict,
        })
        .await?;

    tracing::info!(
        "dino shadow: message {} best-matches \"{entry_name}\" at {similarity:.4} \
         (hash verdict: {hash_verdict}, observation {observation_id})",
        message.id
    );

    // hash-flagged images already produced a human-facing report
    if hash_verdict != "clean" || similarity < CONFIG.dino.review_threshold {
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
            &entry_name,
            similarity,
            filename,
        ))
        .components(interactions::dino_label_buttons(observation_id))
        .add_file(CreateAttachment::bytes(image_bytes.to_vec(), filename.to_string()));
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

/// keep the pixels of every labeled card: the similarity scalar is enough to
/// tune the threshold, but growing the datasets (true positives) and building
/// an eval set (hard negatives) needs the images themselves — the Discord CDN
/// copy dies with the card message
pub async fn capture_labeled_image(
    http: &reqwest::Client,
    image_url: &str,
    observation_id: i64,
    label: &str,
) -> Result<std::path::PathBuf, crate::Error> {
    let bytes = http
        .get(image_url)
        .send()
        .await?
        .error_for_status()?
        .bytes()
        .await?;

    let dir = std::path::Path::new(&CONFIG.dino.captures_dir).join(label);
    std::fs::create_dir_all(&dir)?;

    let path = dir.join(format!("{observation_id}.{}", extension_from_url(image_url)));
    std::fs::write(&path, &bytes)?;
    Ok(path)
}

/// image extension from a CDN url path, query string stripped; the capture
/// folder is consumed by the recursive `dino-export`, which filters by
/// extension, so unknown ones fall back to jpg
fn extension_from_url(url: &str) -> String {
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
