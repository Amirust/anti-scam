use std::time::Duration;

use poise::serenity_prelude as serenity;
use crate::{events, Context, Data, Error};

/// how long the add-to-dataset modal waits for input before giving up
const MODAL_TIMEOUT: Duration = Duration::from_secs(300);

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
    // forwarded messages carry their attachments in message_snapshots
    let images: Vec<&serenity::Attachment> = message
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
        .collect();

    if images.is_empty() {
        ctx.send(
            poise::CreateReply::default()
                .content("This message has no image attachments.")
                .ephemeral(true),
        )
        .await?;
        return Ok(());
    }

    // the modal must be the first response to the interaction
    let Some(input) = poise::execute_modal(ctx, None::<AddToDatasetModal>, Some(MODAL_TIMEOUT))
        .await?
    else {
        return Ok(());
    };

    let image_number = match parse_image_number(input.image_number.as_deref(), images.len()) {
        Ok(number) => number,
        Err(reason) => {
            ctx.send(poise::CreateReply::default().content(reason).ephemeral(true))
                .await?;
            return Ok(());
        }
    };

    let attachment = images[image_number - 1];
    let result = async {
        let bytes = ctx
            .data
            .http
            .get(&attachment.url)
            .send()
            .await?
            .error_for_status()?
            .bytes()
            .await?;
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

    ctx.send(poise::CreateReply::default().content(feedback).ephemeral(true))
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