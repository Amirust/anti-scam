use std::sync::Arc;
use std::time::Duration;

use poise::serenity_prelude as serenity;
use crate::dataset::normalize_name;
use crate::dino_dataset::{DinoAddOutcome, RefKind};
use crate::{dino_shadow, events, images, img_config, Context, Data, Error};

/// how long the add-to-dataset modals wait for input before giving up
const MODAL_TIMEOUT: Duration = Duration::from_secs(300);
/// length of the sha256 hex prefix used to name auto-named dino references
const AUTO_NAME_HEX_CHARS: usize = 8;
/// keep names embed-friendly; modals cap input too, but payloads are
/// client-supplied
const MAX_NAME_LENGTH: usize = 64;
/// `DINO: check image` scores at most this many images per message
const MAX_CHECK_IMAGES: usize = 4;

#[poise::command(
    slash_command,
    subcommands("set_notification_channel"),
    default_member_permissions = "ADMINISTRATOR"
)]
pub async fn settings(ctx: Context<'_>) -> Result<(), Error> {
    ctx.say("How?").await?;
    Ok(())
}

#[poise::command(
    slash_command,
    required_permissions = "ADMINISTRATOR"
)]
pub async fn set_notification_channel(
    ctx: Context<'_>,
    #[description = "Channel to send notifications to"]
    #[channel_types("Text", "Voice", "News", "PublicThread")]
    channel_id: serenity::ChannelId,
) -> Result<(), Error> {
    let guild_id = match ctx.guild_id() {
        Some(guild_id) => guild_id,
        None => {
            ctx.say("This command can only be used in a server.").await?;
            return Ok(());
        }
    };

    let db = &ctx.data().db;
    db.set_settings(&guild_id.to_string(), &channel_id.to_string()).await?;

    ctx.say(format!("Notification channel set to <#{}>.", channel_id)).await?;
    Ok(())
}

#[derive(Debug, poise::Modal)]
#[name = "Add image to dataset"]
struct AddToDatasetModal {
    #[name = "Image number (1 = first image)"]
    #[placeholder = "1"]
    image_number: Option<String>,
    #[name = "Entry name"]
    #[placeholder = "Leave empty for an auto-generated name"]
    #[max_length = 64]
    entry_name: Option<String>,
}

/// right-click a message -> Apps -> Add image to dataset; shown to admins,
/// executable only by the bot owner
#[poise::command(
    context_menu_command = "Add image to dataset",
    owners_only,
    default_member_permissions = "ADMINISTRATOR"
)]
pub async fn add_image_to_dataset(
    ctx: poise::ApplicationContext<'_, Data, Error>,
    message: serenity::Message,
) -> Result<(), Error> {
    let images = message_images(&message);
    if images.is_empty() {
        return reply_ephemeral(ctx, "This message has no image attachments.").await;
    }

    // the modal must be the first response to the interaction
    let Some(input) = poise::execute_modal(ctx, None::<AddToDatasetModal>, Some(MODAL_TIMEOUT))
        .await?
    else {
        return Ok(());
    };

    let image_number = match parse_image_number(input.image_number.as_deref(), images.len()) {
        Ok(number) => number,
        Err(reason) => return reply_ephemeral(ctx, &reason).await,
    };

    let attachment = images[image_number - 1];
    let result = async {
        let bytes = fetch_image(&ctx.data.http, &attachment.url).await?;
        ctx.data.scam_db.add_image(bytes, input.entry_name).await
    }
    .await;

    let feedback = match result {
        Ok(outcome) => outcome.describe(),
        Err(e) => {
            tracing::warn!("add to dataset via context menu failed: {e}");
            format!("Failed to add the image: {e}")
        }
    };

    reply_ephemeral(ctx, &feedback).await
}

#[derive(Debug, poise::Modal)]
#[name = "Add image to DINO dataset"]
struct DinoAddModal {
    #[name = "Image number (1 = first image)"]
    #[placeholder = "1"]
    image_number: Option<String>,
    #[name = "Entry name"]
    #[placeholder = "Leave empty for an auto-generated name"]
    #[max_length = 64]
    entry_name: Option<String>,
}

/// right-click a message -> Apps -> DINO: add as scam; the image becomes a
/// scam reference of the embedding stage
#[poise::command(
    context_menu_command = "DINO: add as scam",
    owners_only,
    default_member_permissions = "ADMINISTRATOR"
)]
pub async fn dino_add_scam(
    ctx: poise::ApplicationContext<'_, Data, Error>,
    message: serenity::Message,
) -> Result<(), Error> {
    dino_add(ctx, message, RefKind::Scam).await
}

/// right-click a message -> Apps -> DINO: add as negative; the image becomes
/// a known legit look-alike that suppresses shadow cards via the margin rule
#[poise::command(
    context_menu_command = "DINO: add as negative",
    owners_only,
    default_member_permissions = "ADMINISTRATOR"
)]
pub async fn dino_add_negative(
    ctx: poise::ApplicationContext<'_, Data, Error>,
    message: serenity::Message,
) -> Result<(), Error> {
    dino_add(ctx, message, RefKind::Negative).await
}

async fn dino_add(
    ctx: poise::ApplicationContext<'_, Data, Error>,
    message: serenity::Message,
    kind: RefKind,
) -> Result<(), Error> {
    let Some(runtime) = ctx.data.dino.clone() else {
        return reply_ephemeral(ctx, "DINO shadow mode is disabled (dino.enabled).").await;
    };
    let images = message_images(&message);
    if images.is_empty() {
        return reply_ephemeral(ctx, "This message has no image attachments.").await;
    }

    // the modal must be the first response to the interaction
    let Some(input) = poise::execute_modal(ctx, None::<DinoAddModal>, Some(MODAL_TIMEOUT)).await?
    else {
        return Ok(());
    };

    let image_number = match parse_image_number(input.image_number.as_deref(), images.len()) {
        Ok(number) => number,
        Err(reason) => return reply_ephemeral(ctx, &reason).await,
    };
    let attachment = images[image_number - 1];

    let feedback = match add_dino_reference(&ctx, runtime, attachment, input.entry_name, kind).await
    {
        Ok(feedback) => feedback,
        Err(e) => {
            tracing::warn!("dino add via context menu failed: {e}");
            format!("Failed to add the image: {e}")
        }
    };

    reply_ephemeral(ctx, &feedback).await
}

async fn add_dino_reference(
    ctx: &poise::ApplicationContext<'_, Data, Error>,
    runtime: Arc<crate::dino::DinoRuntime>,
    attachment: &serenity::Attachment,
    entry_name: Option<String>,
    kind: RefKind,
) -> Result<String, Error> {
    let bytes = fetch_image(&ctx.data.http, &attachment.url).await?;

    let name = match normalize_name(entry_name) {
        Some(name) => name,
        None => auto_reference_name(kind, &bytes),
    };
    if name.len() > MAX_NAME_LENGTH {
        return Err(format!("entry name is longer than {MAX_NAME_LENGTH} characters").into());
    }

    let embedding = tokio::task::spawn_blocking({
        let runtime = Arc::clone(&runtime);
        let bytes = bytes.clone();
        move || runtime.embedder.embed(&bytes)
    })
    .await??;

    let outcome = runtime.store.add(kind, name.clone(), embedding).await?;
    if matches!(outcome, DinoAddOutcome::Added { .. }) {
        let group = match kind {
            RefKind::Scam => "scam_ref",
            RefKind::Negative => "negative_ref",
        };
        let extension = dino_shadow::extension_from_url(&attachment.filename);
        if let Err(e) = dino_shadow::save_capture(group, &name, &extension, &bytes) {
            tracing::warn!("failed to keep pixels of dino reference \"{name}\": {e}");
        }
    }

    Ok(outcome.describe(kind))
}

fn auto_reference_name(kind: RefKind, bytes: &[u8]) -> String {
    let sha_hex = img_config::hex_encode(&images::sha256_hash(bytes));
    let prefix = match kind {
        RefKind::Scam => "manual",
        RefKind::Negative => "neg",
    };
    format!("{prefix}_{}", &sha_hex[..AUTO_NAME_HEX_CHARS])
}

/// right-click a message -> Apps -> DINO: check image; ephemeral similarity
/// diagnostics without touching the dataset
#[poise::command(
    context_menu_command = "DINO: check image",
    required_permissions = "BAN_MEMBERS",
    default_member_permissions = "BAN_MEMBERS"
)]
pub async fn dino_check(
    ctx: poise::ApplicationContext<'_, Data, Error>,
    message: serenity::Message,
) -> Result<(), Error> {
    let Some(runtime) = ctx.data.dino.clone() else {
        return reply_ephemeral(ctx, "DINO shadow mode is disabled (dino.enabled).").await;
    };
    let images = message_images(&message);
    if images.is_empty() {
        return reply_ephemeral(ctx, "This message has no image attachments.").await;
    }

    ctx.defer_ephemeral().await?;

    let mut lines = Vec::new();
    for (index, attachment) in images.iter().take(MAX_CHECK_IMAGES).enumerate() {
        let line = check_one_image(&ctx, Arc::clone(&runtime), attachment).await;
        lines.push(format!("{}. {}", index + 1, line.unwrap_or_else(|e| format!("failed: {e}"))));
    }
    if images.len() > MAX_CHECK_IMAGES {
        lines.push(format!("(first {MAX_CHECK_IMAGES} of {} images)", images.len()));
    }

    reply_ephemeral(ctx, &lines.join("\n")).await
}

async fn check_one_image(
    ctx: &poise::ApplicationContext<'_, Data, Error>,
    runtime: Arc<crate::dino::DinoRuntime>,
    attachment: &serenity::Attachment,
) -> Result<String, Error> {
    let bytes = fetch_image(&ctx.data.http, &attachment.url).await?;
    let Some(shadow_match) = dino_shadow::measure(runtime, bytes).await? else {
        return Ok("no scam references in the dataset yet".to_string());
    };

    let negative = shadow_match
        .negative
        .as_ref()
        .map(|(name, similarity)| format!(", closest negative `{name}` {similarity:.4}"))
        .unwrap_or_default();
    let verdict = if dino_shadow::exceeds_review_gate(&shadow_match) {
        "🟥 would get a card"
    } else if shadow_match.similarity >= crate::config::CONFIG.dino.review_threshold {
        "🟨 suppressed by negative margin"
    } else {
        "🟩 below threshold"
    };

    Ok(format!(
        "best `{}` {:.4}{negative} — {verdict}",
        shadow_match.entry_name, shadow_match.similarity,
    ))
}

/// direct attachments plus attachments of forwarded messages (those live in
/// message_snapshots)
fn message_images(message: &serenity::Message) -> Vec<&serenity::Attachment> {
    message
        .attachments
        .iter()
        .chain(
            message
                .message_snapshots
                .iter()
                .flat_map(|snapshot| snapshot.attachments.iter()),
        )
        .filter(|a| {
            a.content_type
                .as_deref()
                .is_some_and(|ct| ct.starts_with("image/"))
        })
        .filter(|a| a.size <= events::MAX_ATTACHMENT_BYTES)
        .collect()
}

async fn fetch_image(http: &reqwest::Client, url: &str) -> Result<bytes::Bytes, Error> {
    Ok(http.get(url).send().await?.error_for_status()?.bytes().await?)
}

async fn reply_ephemeral(
    ctx: poise::ApplicationContext<'_, Data, Error>,
    text: &str,
) -> Result<(), Error> {
    ctx.send(poise::CreateReply::default().content(text).ephemeral(true))
        .await?;
    Ok(())
}

fn parse_image_number(input: Option<&str>, image_count: usize) -> Result<usize, String> {
    let input = input.map(str::trim).filter(|s| !s.is_empty());

    let number: usize = match input {
        None => 1,
        Some(text) => text
            .parse()
            .map_err(|_| format!("`{text}` is not a valid image number."))?,
    };

    if number == 0 || number > image_count {
        return Err(format!(
            "Image number {number} is out of range: the message has {image_count} image(s)."
        ));
    }

    Ok(number)
}