use std::sync::Arc;

use poise::serenity_prelude as serenity;
use serenity::all::{CreateAttachment, CreateMessage};
use crate::dataset::Dataset;
use crate::detection::Verdict;
use crate::images as images_utils;
use crate::{db, detection, interactions, Data, Error, InflightSet};
use crate::embeds::{
    describe_reason, get_ban_dm_embed, get_ban_server_embed, get_cannot_ban_embed,
    get_review_embed,
};
use crate::utils::bot_can_ban;

/// attachments bigger than this are ignored, real scam screenshots are tiny
const MAX_ATTACHMENT_BYTES: u32 = 20 * 1024 * 1024;

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
        serenity::FullEvent::InteractionCreate {
            interaction: serenity::Interaction::Component(component),
        } => {
            interactions::handle_component(ctx, component, &framework.options().owners).await
        }
        serenity::FullEvent::InteractionCreate {
            interaction: serenity::Interaction::Modal(modal),
        } => {
            interactions::handle_modal(ctx, modal, &framework.options().owners, data).await
        }
        _ => Ok(()),
    }
}

async fn handle_message(
    ctx: &serenity::Context,
    message: &serenity::Message,
    data: &Data,
) -> Result<(), Error> {
    if message.author.bot {
        return Ok(());
    }

    let images: Vec<serenity::Attachment> = message
        .attachments
        .iter()
        .filter(|a| {
            a.content_type
                .as_deref()
                .is_some_and(|ct| ct.starts_with("image/"))
        })
        .filter(|a| a.size <= MAX_ATTACHMENT_BYTES)
        .cloned()
        .collect();

    if images.is_empty() {
        return Ok(());
    }

    tracing::info!(
        "processing {} image(s) from message {}",
        images.len(),
        message.id
    );

    for attachment in images {
        let http = data.http.clone();
        let inflight = Arc::clone(&data.inflight);
        let scam_db = Arc::clone(&data.scam_db);
        let settings_db = Arc::clone(&data.db);
        let ctx = ctx.clone();
        let message = message.clone();
        let filename = attachment.filename.clone();

        tokio::spawn(async move {
            match process_attachment(attachment, message.author.id, http, inflight, scam_db).await {
                // the guard stays alive until the verdict is fully handled, so
                // repeated copies of the image stay deduplicated during the ban
                Ok(Some((verdict, bytes, _guard))) => {
                    let handled =
                        handle_verdict(&ctx, &message, &settings_db, verdict, bytes, &filename)
                            .await;
                    if let Err(e) = handled {
                        tracing::warn!("verdict handling failed for message {}: {e}", message.id);
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
async fn process_attachment(
    attachment: serenity::Attachment,
    author_id: serenity::UserId,
    http: reqwest::Client,
    inflight: InflightSet,
    scam_db: Arc<Dataset>,
) -> Result<Option<(Verdict, bytes::Bytes, InflightGuard)>, Error> {
    let bytes = http
        .get(&attachment.url)
        .send()
        .await?
        .error_for_status()?
        .bytes()
        .await?;

    let key = (images_utils::sha256_hash(&bytes), author_id.get());

    let is_first = inflight.lock().unwrap().insert(key);
    if !is_first {
        tracing::debug!("image {} already in flight, skipping", attachment.url);
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
