use poise::serenity_prelude as serenity;
use crate::{Context, Error};

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