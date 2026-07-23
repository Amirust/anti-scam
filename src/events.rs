use std::sync::Arc;

use poise::serenity_prelude as serenity;
use serenity::all::{CreateAttachment, CreateMessage};
use crate::dataset::Dataset;
use crate::detection::Verdict;
use crate::images as images_utils;
use crate::{db, detection, dino_shadow, interactions, Data, Error, InflightSet};
use crate::embeds::{
    describe_reason, get_ban_dm_embed, get_ban_server_embed, get_cannot_ban_embed,
    get_review_embed,
};
use crate::utils::bot_can_ban;

/// attachments bigger than this are ignored, real scam screenshots are tiny
pub const MAX_ATTACHMENT_BYTES: u32 = 20 * 1024 * 1024;

struct InflightGuard {
    set: InflightSet,
    key: ([u8; 32], u64),
}

impl Drop for InflightGuard {
    fn drop(&mut self) {
        self.set.lock().unwrap().remove(&self.key);
    }
}

pub async fn handle_event(
    ctx: &serenity::Context,
    event: &serenity::FullEvent,
    framework: poise::FrameworkContext<'_, Data, Error>,
    data: &Data,
) -> Result<(), Error> {
    match event {
        serenity::FullEvent::Message { new_message } => {
            handle_message(ctx, new_message, data).await
        }
        serenity::FullEvent::MessageUpdate { new, event, .. } => {
            handle_message_update(ctx, new.as_ref(), event, data).await
        }
        serenity::FullEvent::InteractionCreate {
            interaction: serenity::Interaction::Component(component),
        } => {
            interactions::handle_component(ctx, component, &framework.options().owners, data).await
        }
        serenity::FullEvent::InteractionCreate {
            interaction: serenity::Interaction::Modal(modal),
        } => {
            interactions::handle_modal(ctx, modal, &framework.options().owners, data).await
        }
        _ => Ok(()),
    }
}

/// a single image the detector downloads and classifies
struct ScanTarget {
    url: String,
    filename: String,
}

/// everything scannable in a message: direct attachments, attachments of
/// forwarded messages (they live in `message_snapshots`) and link-preview
/// embeds of both
fn scan_targets(message: &serenity::Message) -> Vec<ScanTarget> {
    let snapshot_attachments = message
        .message_snapshots
        .iter()
        .flat_map(|snapshot| snapshot.attachments.iter());
    let snapshot_embeds = message
        .message_snapshots
        .iter()
        .flat_map(|snapshot| snapshot.embeds.iter());

    attachment_targets(message.attachments.iter().chain(snapshot_attachments))
        .chain(embed_targets(message.embeds.iter().chain(snapshot_embeds)))
        .collect()
}

fn attachment_targets<'a>(
    attachments: impl Iterator<Item = &'a serenity::Attachment> + 'a,
) -> impl Iterator<Item = ScanTarget> + 'a {
    attachments
        .filter(|a| {
            a.content_type
                .as_deref()
                .is_some_and(|ct| ct.starts_with("image/"))
        })
        .filter(|a| a.size <= MAX_ATTACHMENT_BYTES)
        .map(|a| ScanTarget {
            url: a.url.clone(),
            filename: a.filename.clone(),
        })
}

/// link previews: only the Discord media proxy is downloaded, never the
/// original third-party URL — the bot must not fetch arbitrary hosts
fn embed_targets<'a>(
    embeds: impl Iterator<Item = &'a serenity::Embed> + 'a,
) -> impl Iterator<Item = ScanTarget> + 'a {
    embeds.filter_map(|embed| {
        let proxied = embed
            .image
            .as_ref()
            .and_then(|image| image.proxy_url.as_deref())
            .or_else(|| {
                embed
                    .thumbnail
                    .as_ref()
                    .and_then(|thumbnail| thumbnail.proxy_url.as_deref())
            })?;

        Some(ScanTarget {
            url: proxied.to_string(),
            filename: embed_filename(proxied),
        })
    })
}

/// report attachments need an image-looking name for `attachment://` embeds
fn embed_filename(url: &str) -> String {
    url.rsplit('/')
        .next()
        .and_then(|segment| segment.split('?').next())
        .filter(|name| name.contains('.'))
        .map(str::to_string)
        .unwrap_or_else(|| "embed.png".to_string())
}

async fn handle_message(
    ctx: &serenity::Context,
    message: &serenity::Message,
    data: &Data,
) -> Result<(), Error> {
    if message.author.bot {
        return Ok(());
    }

    scan_message(ctx, message, data, scan_targets(message)).await
}

/// link previews resolve after MESSAGE_CREATE: Discord delivers them in a
/// follow-up MESSAGE_UPDATE, which is the only reliable place to scan them
async fn handle_message_update(
    ctx: &serenity::Context,
    cached: Option<&serenity::Message>,
    event: &serenity::MessageUpdateEvent,
    data: &Data,
) -> Result<(), Error> {
    let has_embeds = event.embeds.as_ref().is_some_and(|embeds| !embeds.is_empty());
    if !has_embeds {
        return Ok(());
    }
    if event.author.as_ref().is_some_and(|author| author.bot) {
        return Ok(());
    }

    let message = match cached {
        Some(message) => message.clone(),
        None => {
            // REST message objects carry no guild_id, recover it from the event
            let mut message = ctx.http.get_message(event.channel_id, event.id).await?;
            message.guild_id = message.guild_id.or(event.guild_id);
            message
        }
    };
    if message.author.bot {
        return Ok(());
    }

    // attachments were already scanned on MESSAGE_CREATE, only embeds are new;
    // an embed re-delivered by an edit re-classifies harmlessly
    let targets: Vec<ScanTarget> = embed_targets(message.embeds.iter()).collect();
    scan_message(ctx, &message, data, targets).await
}

async fn scan_message(
    ctx: &serenity::Context,
    message: &serenity::Message,
    data: &Data,
    targets: Vec<ScanTarget>,
) -> Result<(), Error> {
    if targets.is_empty() {
        return Ok(());
    }

    tracing::info!(
        "processing {} image(s) from message {}",
        targets.len(),
        message.id
    );

    for target in targets {
        let http = data.http.clone();
        let inflight = Arc::clone(&data.inflight);
        let scam_db = Arc::clone(&data.scam_db);
        let settings_db = Arc::clone(&data.db);
        let dino = data.dino.clone();
        let ctx = ctx.clone();
        let message = message.clone();
        let filename = target.filename.clone();

        tokio::spawn(async move {
            match process_target(target, message.author.id, http, inflight, scam_db).await {
                // the guard stays alive until the verdict is fully handled, so
                // repeated copies of the image stay deduplicated during the ban
                Ok(Some((verdict, bytes, _guard))) => {
                    let hash_verdict = dino_shadow::verdict_tag(&verdict);
                    let handled = handle_verdict(
                        &ctx,
                        &message,
                        &settings_db,
                        verdict,
                        bytes.clone(),
                        &filename,
                    )
                    .await;
                    if let Err(e) = handled {
                        tracing::warn!("verdict handling failed for message {}: {e}", message.id);
                    }

                    // shadow mode observes every image, still under the guard
                    if let Some(runtime) = dino {
                        dino_shadow::shadow_pass(
                            &ctx, &message, &settings_db, runtime, bytes, &filename, hash_verdict,
                        )
                        .await;
                    }
                }
                // same image already in flight, that task owns the verdict
                Ok(None) => {}
                Err(e) => tracing::warn!("image pipeline failed: {e}"),
            }
        });
    }

    Ok(())
}

/// returns `None` when the same image is already being processed by another task;
/// on success the downloaded bytes and the inflight guard ride along
async fn process_target(
    target: ScanTarget,
    author_id: serenity::UserId,
    http: reqwest::Client,
    inflight: InflightSet,
    scam_db: Arc<Dataset>,
) -> Result<Option<(Verdict, bytes::Bytes, InflightGuard)>, Error> {
    let bytes = http
        .get(&target.url)
        .send()
        .await?
        .error_for_status()?
        .bytes()
        .await?;

    // embeds declare no size upfront, enforce the cap after the download
    if bytes.len() > MAX_ATTACHMENT_BYTES as usize {
        tracing::debug!(
            "image {} is too large ({} bytes), skipping",
            target.url,
            bytes.len()
        );
        return Ok(None);
    }

    let key = (images_utils::sha256_hash(&bytes), author_id.get());

    let is_first = inflight.lock().unwrap().insert(key);
    if !is_first {
        tracing::debug!("image {} already in flight, skipping", target.url);
        return Ok(None);
    }
    let guard = InflightGuard {
        set: inflight,
        key,
    };

    let verdict = detection::process_image(bytes.clone(), scam_db.snapshot()).await?;
    Ok(Some((verdict, bytes, guard)))
}

async fn handle_verdict(
    ctx: &serenity::Context,
    message: &serenity::Message,
    db: &db::Database,
    verdict: Verdict,
    image_bytes: bytes::Bytes,
    filename: &str,
) -> Result<(), Error> {
    if verdict == Verdict::Clean {
        tracing::info!("image in message {} is clean", message.id);
        return Ok(());
    }

    let guild_id = match message.guild_id {
        Some(guild_id) => guild_id,
        None => {
            tracing::warn!(
                "message {} is not in a guild, cannot send ban report",
                message.id
            );
            return Ok(());
        }
    };

    let notification_channel = db
        .get_notification_channel(&guild_id.to_string())
        .await?
        .and_then(|id| id.parse::<u64>().ok())
        .map(serenity::ChannelId::new);

    tracing::warn!(
        "message {} in guild {:?}: verdict {verdict:?}, notification channel {notification_channel:?}",
        message.id,
        guild_id,
    );

    // re-upload the image: original CDN links expire and the scam message gets deleted
    let report_image = CreateAttachment::bytes(image_bytes.to_vec(), filename.to_string());

    match verdict {
        Verdict::Ban { entry_name, reason } => {
            tracing::info!(
                "message {} matched banned entry \"{entry_name}\": {reason:?}",
                message.id
            );

            let Some(channel) = notification_channel else {
                tracing::warn!(
                    "guild {:?} has no notification channel configured, ban report dropped",
                    guild_id
                );
                return Ok(());
            };

            if !bot_can_ban(ctx, guild_id, message.author.id).await {
                tracing::warn!(
                    "bot cannot ban users in guild {:?}, ban report dropped",
                    guild_id
                );

                let report = CreateMessage::new()
                    .embed(get_cannot_ban_embed(
                        &message.author,
                        message.link(),
                        &entry_name,
                        reason,
                        filename,
                    ))
                    .add_file(report_image);
                channel.send_message(&ctx, report).await?;

                return Ok(());
            }

            let Some(guild) = message.guild(&ctx.cache).map(|g| g.clone()) else {
                tracing::warn!("guild {guild_id} is not in cache, ban skipped");
                return Ok(());
            };

            let ban_message = CreateMessage::new()
                .embed(get_ban_server_embed(&message.author, &entry_name, reason, filename))
                .components(interactions::ban_report_buttons())
                .add_file(report_image);
            let dm_message = CreateMessage::new().embed(get_ban_dm_embed(&guild));

            if let Err(e) = message.author.dm(&ctx, dm_message).await {
                tracing::warn!("failed to DM user {}: {e}", message.author.id);
            }

            guild
                .ban_with_reason(
                    &ctx,
                    message.author.id,
                    1,
                    format!("Posted a banned image, {}", describe_reason(reason))
                )
                .await?;

            // Send ban report to notification channel
            channel.send_message(&ctx, ban_message).await?;
        }
        Verdict::Review { entry_name, matched, informative } => {
            tracing::info!(
                "message {} is flagged for review: {matched}/{informative} tiles matched entry \"{entry_name}\"",
                message.id
            );

            let Some(channel) = notification_channel else {
                tracing::warn!(
                    "guild {:?} has no notification channel configured, review report dropped",
                    guild_id
                );
                return Ok(());
            };

            let report = CreateMessage::new()
                .embed(get_review_embed(
                    &message.author,
                    message.link(),
                    &entry_name,
                    matched,
                    informative,
                    filename,
                ))
                .components(interactions::review_buttons(
                    message.author.id,
                    message.timestamp,
                ))
                .add_file(report_image);
            channel.send_message(&ctx, report).await?;
        }
        Verdict::Clean => {}
    }

    Ok(())
}
