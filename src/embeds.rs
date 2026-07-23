use poise::serenity_prelude::{Color, CreateEmbed, CreateEmbedFooter};
use serenity::all::{Guild, Timestamp, User};
use crate::detection::MatchReason;

/// Get embed that is sent to admin channel of guild when a user is banned
pub fn get_ban_server_embed(
    user: &User,
    entry_name: &str,
    reason: MatchReason,
    filename: &str,
) -> CreateEmbed {
    CreateEmbed::default()
        .title(format!("User {} banned", user.name))
        .description(format!(
            "User <@{}> ({}) posted a banned image.\n\n\
             **Dataset entry:** `{entry_name}`\n\
             **Match:** {}",
            user.id, user.name,
            describe_reason(reason)
        ))
        .color(Color::RED)
        .image(format!("attachment://{filename}"))
        .thumbnail(user.avatar_url().unwrap_or(user.default_avatar_url()))
        .footer(CreateEmbedFooter::new(format!("User ID: {}", user.id)))
        .timestamp(Timestamp::now())
}

// Get embed that is sent to user when they are banned
pub fn get_ban_dm_embed(guild: &Guild) -> CreateEmbed {
    CreateEmbed::default()
        .title("You have been banned")
        .description(format!("You posted a banned image on {}.", guild.name))
        .color(Color::RED)
        .timestamp(Timestamp::now())
}

// Get embed that is sent to admin channel of guild when bot cannot ban user
pub fn get_cannot_ban_embed(
    user: &User,
    message_url: String,
    entry_name: &str,
    reason: MatchReason,
    filename: &str,
) -> CreateEmbed {
    CreateEmbed::default()
        .title(format!("Cannot ban {}", user.name))
        .description(format!(
            "User <@{}> ({}) posted a banned image {}, but the bot cannot ban them.\n\n\
             **Dataset entry:** `{entry_name}`\n\
             **Match:** {}",
            user.id, user.name, message_url,
            describe_reason(reason)
        ))
        .color(Color::ORANGE)
        .image(format!("attachment://{filename}"))
        .thumbnail(user.avatar_url().unwrap_or(user.default_avatar_url()))
        .footer(CreateEmbedFooter::new(format!("User ID: {}", user.id)))
        .timestamp(Timestamp::now())
}

// Get embed that is sent to admin channel when an image needs manual review
pub fn get_review_embed(
    user: &User,
    message_url: String,
    entry_name: &str,
    matched: u32,
    informative: u32,
    filename: &str,
) -> CreateEmbed {
    CreateEmbed::default()
        .title("Suspicious image needs review")
        .description(format!(
            "User <@{}> ({}) posted an image {} that resembles a banned one, \
             but scored below the auto-ban threshold.\n\n\
             **Dataset entry:** `{entry_name}`\n\
             **Match:** {matched}/{informative} informative tiles",
            user.id, user.name, message_url,
        ))
        .color(Color::GOLD)
        .image(format!("attachment://{filename}"))
        .thumbnail(user.avatar_url().unwrap_or(user.default_avatar_url()))
        .footer(CreateEmbedFooter::new(format!("User ID: {}", user.id)))
        .timestamp(Timestamp::now())
}

pub fn describe_reason(reason: MatchReason) -> String {
    match reason {
        MatchReason::WholeImage { distance } => {
            format!("whole-image pHash, distance {distance}")
        }
        MatchReason::Tiles { matched, informative } => {
            format!("{matched}/{informative} informative tiles matched")
        }
    }
}
