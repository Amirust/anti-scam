use std::collections::HashSet;

use poise::serenity_prelude as serenity;
use serenity::all::{
    ActionRowComponent, ButtonStyle, ComponentInteraction, CreateActionRow, CreateButton,
    CreateInputText, CreateInteractionResponse, CreateInteractionResponseMessage, CreateModal,
    EditInteractionResponse, InputTextStyle, Message, ModalInteraction, ModalInteractionData,
    Timestamp, UserId,
};

use crate::{Data, Error};

const BAN_BUTTON_PREFIX: &str = "ban:";
/// custom_id of the ban button after it has been used (never matches the parser)
const BAN_DONE_ID: &str = "ban:done";
const ADD_TO_DATASET_ID: &str = "dataset:add";
const DATASET_MODAL_ID: &str = "dataset:modal";
const DATASET_NAME_INPUT_ID: &str = "dataset:name";

const SECONDS_PER_DAY: i64 = 86_400;
/// Discord caps message deletion on ban at 7 days
const MAX_DELETE_DAYS: i64 = 7;

/// button row for a review report: ban (admins) + add to dataset (owner)
/// state lives entirely in the custom_id, so buttons survive bot restarts
pub fn review_buttons(author: UserId, posted_at: Timestamp) -> Vec<CreateActionRow> {
    let ban_id = format!("{BAN_BUTTON_PREFIX}{author}:{}", posted_at.unix_timestamp());

    vec![CreateActionRow::Buttons(vec![
        CreateButton::new(ban_id)
            .label("Ban user")
            .style(ButtonStyle::Danger),
        add_to_dataset_button(),
    ])]
}

/// button row for a ban report: the user is already banned, only dataset add
pub fn ban_report_buttons() -> Vec<CreateActionRow> {
    vec![CreateActionRow::Buttons(vec![add_to_dataset_button()])]
}

fn add_to_dataset_button() -> CreateButton {
    CreateButton::new(ADD_TO_DATASET_ID)
        .label("Add to dataset")
        .style(ButtonStyle::Secondary)
}

pub async fn handle_component(
    ctx: &serenity::Context,
    interaction: &ComponentInteraction,
    owners: &HashSet<UserId>,
) -> Result<(), Error> {
    match parse_custom_id(&interaction.data.custom_id) {
        Some(Action::Ban { user_id, posted_at }) => {
            handle_ban_button(ctx, interaction, user_id, posted_at).await
        }
        Some(Action::AddToDataset) => handle_dataset_button(ctx, interaction, owners).await,
        None => Ok(()),
    }
}

enum Action {
    Ban { user_id: UserId, posted_at: i64 },
    AddToDataset,
}

fn parse_custom_id(id: &str) -> Option<Action> {
    if id == ADD_TO_DATASET_ID {
        return Some(Action::AddToDataset);
    }

    let rest = id.strip_prefix(BAN_BUTTON_PREFIX)?;
    let (user, timestamp) = rest.split_once(':')?;
    let user: u64 = user.parse().ok()?;
    if user == 0 {
        return None;
    }

    Some(Action::Ban {
        user_id: UserId::new(user),
        posted_at: timestamp.parse().ok()?,
    })
}

/// days of message history to delete with the ban: everything since the scam
/// was posted, clamped to Discords 1..7 day range
fn delete_message_days(now: i64, posted_at: i64) -> u8 {
    let elapsed = (now - posted_at).max(0);
    let days = (elapsed + SECONDS_PER_DAY - 1) / SECONDS_PER_DAY;
    days.clamp(1, MAX_DELETE_DAYS) as u8
}

async fn handle_ban_button(
    ctx: &serenity::Context,
    interaction: &ComponentInteraction,
    target: UserId,
    posted_at: i64,
) -> Result<(), Error> {
    let Some(guild_id) = interaction.guild_id else {
        return respond_ephemeral(ctx, interaction, "This button only works in a server.").await;
    };

    let presser_can_ban = interaction
        .member
        .as_ref()
        .and_then(|member| member.permissions)
        .is_some_and(|permissions| permissions.ban_members());
    if !presser_can_ban {
        return respond_ephemeral(
            ctx,
            interaction,
            "You need the Ban Members permission to use this button.",
        )
        .await;
    }

    let days = delete_message_days(Timestamp::now().unix_timestamp(), posted_at);

    if let Err(e) = guild_id
        .ban_with_reason(
            &ctx.http,
            target,
            days,
            "Posted a banned image (approved from admin review)",
        )
        .await
    {
        tracing::warn!("review ban of {target} in guild {guild_id} failed: {e}");
        return respond_ephemeral(ctx, interaction, &format!("Ban failed: {e}")).await;
    }

    tracing::info!(
        "user {target} banned in guild {guild_id} via review button, \
         {days} day(s) of messages deleted"
    );

    // disable the ban button so it cannot be pressed twice
    let used_row = vec![CreateActionRow::Buttons(vec![
        CreateButton::new(BAN_DONE_ID)
            .label(format!("Banned by {}", interaction.user.name))
            .style(ButtonStyle::Danger)
            .disabled(true),
        add_to_dataset_button(),
    ])];

    interaction
        .create_response(
            &ctx.http,
            CreateInteractionResponse::UpdateMessage(
                CreateInteractionResponseMessage::new().components(used_row),
            ),
        )
        .await?;

    Ok(())
}

/// the button only opens a name-entry modal; the actual work happens on submit
async fn handle_dataset_button(
    ctx: &serenity::Context,
    interaction: &ComponentInteraction,
    owners: &HashSet<UserId>,
) -> Result<(), Error> {
    if !owners.contains(&interaction.user.id) {
        return respond_ephemeral(
            ctx,
            interaction,
            "Only the bot owner can add images to the dataset.",
        )
        .await;
    }

    if report_image_url(&interaction.message).is_none() {
        return respond_ephemeral(ctx, interaction, "This report has no image attached.").await;
    }

    let name_input = CreateInputText::new(InputTextStyle::Short, "Entry name", DATASET_NAME_INPUT_ID)
        .placeholder("Leave empty for an auto-generated name")
        .required(false)
        .max_length(64);
    let modal = CreateModal::new(DATASET_MODAL_ID, "Add image to dataset")
        .components(vec![CreateActionRow::InputText(name_input)]);

    interaction
        .create_response(&ctx.http, CreateInteractionResponse::Modal(modal))
        .await?;

    Ok(())
}

pub async fn handle_modal(
    ctx: &serenity::Context,
    interaction: &ModalInteraction,
    owners: &HashSet<UserId>,
    data: &Data,
) -> Result<(), Error> {
    if interaction.data.custom_id != DATASET_MODAL_ID {
        return Ok(());
    }

    // re-check: interaction payloads are client-supplied input
    if !owners.contains(&interaction.user.id) {
        return modal_respond_ephemeral(
            ctx,
            interaction,
            "Only the bot owner can add images to the dataset.",
        )
        .await;
    }

    let url = interaction.message.as_deref().and_then(report_image_url);
    let Some(url) = url else {
        return modal_respond_ephemeral(ctx, interaction, "This report has no image attached.")
            .await;
    };

    let entry_name = submitted_entry_name(&interaction.data);

    // download + hashing can exceed the 3s interaction window: defer first
    interaction
        .create_response(
            &ctx.http,
            CreateInteractionResponse::Defer(
                CreateInteractionResponseMessage::new().ephemeral(true),
            ),
        )
        .await?;

    let result = async {
        let bytes = data
            .http
            .get(&url)
            .send()
            .await?
            .error_for_status()?
            .bytes()
            .await?;
        data.scam_db.add_image(bytes, entry_name).await
    }
    .await;

    let feedback = match result {
        Ok(outcome) => outcome.describe(),
        Err(e) => {
            tracing::warn!("add to dataset failed: {e}");
            format!("Failed to add the image: {e}")
        }
    };

    interaction
        .edit_response(&ctx.http, EditInteractionResponse::new().content(feedback))
        .await?;

    Ok(())
}

/// the report image is a plain attachment on ban reports, but on review
/// reports it is consumed by the embed's `attachment://` reference and only
/// survives as the embed image CDN url
fn report_image_url(message: &Message) -> Option<String> {
    if let Some(attachment) = message.attachments.first() {
        return Some(attachment.url.clone());
    }

    message
        .embeds
        .first()
        .and_then(|embed| embed.image.as_ref())
        .map(|image| image.url.clone())
}

fn submitted_entry_name(data: &ModalInteractionData) -> Option<String> {
    data.components
        .iter()
        .flat_map(|row| &row.components)
        .find_map(|component| match component {
            ActionRowComponent::InputText(input)
                if input.custom_id == DATASET_NAME_INPUT_ID =>
            {
                input.value.clone()
            }
            _ => None,
        })
}

async fn respond_ephemeral(
    ctx: &serenity::Context,
    interaction: &ComponentInteraction,
    text: &str,
) -> Result<(), Error> {
    interaction
        .create_response(&ctx.http, ephemeral_message(text))
        .await?;

    Ok(())
}

async fn modal_respond_ephemeral(
    ctx: &serenity::Context,
    interaction: &ModalInteraction,
    text: &str,
) -> Result<(), Error> {
    interaction
        .create_response(&ctx.http, ephemeral_message(text))
        .await?;

    Ok(())
}

fn ephemeral_message(text: &str) -> CreateInteractionResponse {
    CreateInteractionResponse::Message(
        CreateInteractionResponseMessage::new()
            .content(text)
            .ephemeral(true),
    )
}
