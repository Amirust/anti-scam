use serenity::all::{GuildId, UserId};
use poise::serenity_prelude::Context;

use crate::Error;

/// write via a temp file + rename so a crash mid-write cannot corrupt the file
pub fn write_atomically(path: &str, contents: &str) -> Result<(), Error> {
    let tmp = format!("{path}.tmp");
    std::fs::write(&tmp, contents)?;
    std::fs::rename(&tmp, path)?;
    Ok(())
}

pub async fn bot_can_ban(ctx: &Context, guild_id: GuildId, target: UserId) -> bool {
    let bot_id = ctx.cache.current_user().id;

    let bot_member = match guild_id.member(ctx, bot_id).await {
        Ok(member) => member,
        Err(_) => return false,
    };

    let Some(guild) = guild_id.to_guild_cached(&ctx.cache) else {
        return false;
    };

    guild.member_permissions(&bot_member).ban_members() &&
    guild.greater_member_hierarchy(
        ctx, bot_id, target
    ) == Some(bot_id)
}