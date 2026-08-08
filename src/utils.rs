use serenity::all::{GuildId, Member, UserId};
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

    let Ok(bot_member) = guild_id.member(ctx, bot_id).await else {
        return false;
    };
    let target_member = guild_id.member(ctx, target).await.ok();

    let Some(guild) = guild_id.to_guild_cached(&ctx.cache) else {
        return false;
    };

    if !guild.member_permissions(&bot_member).ban_members() {
        return false;
    }
    if target == guild.owner_id {
        return false;
    }
    if bot_id == guild.owner_id {
        return true;
    }
    let Some(target_member) = target_member else {
        return true;
    };

    let position =
        |m: &Member| guild.member_highest_role(m).map_or(0, |r| r.position);
    position(&bot_member) > position(&target_member)
}