use serenity::all::{Guild, GuildId, Member, UserId};
use serenity::http::StatusCode;
use poise::serenity_prelude::Context;

/// position of the member's highest role, 0 when they only have @everyone
fn highest_role_position(guild: &Guild, member: &Member) -> u16 {
    member
        .roles
        .iter()
        .filter_map(|id| guild.roles.get(id))
        .map(|role| role.position)
        .max()
        .unwrap_or(0)
}

pub async fn bot_can_ban(ctx: &Context, guild_id: GuildId, target: UserId) -> bool {
    let bot_id = ctx.cache.current_user().id;

    let bot_member = match guild_id.member(ctx, bot_id).await {
        Ok(member) => member,
        Err(_) => return false,
    };

    // fetched over HTTP: without the GUILD_MEMBERS intent the message author is
    // never in the cache, so a cache-only hierarchy check always says no
    let target_member = match guild_id.member(ctx, target).await {
        Ok(member) => Some(member),
        // already left the server: no roles to outrank, the ban still works
        Err(serenity::Error::Http(e)) if e.status_code() == Some(StatusCode::NOT_FOUND) => None,
        Err(_) => return false,
    };

    let Some(guild) = guild_id.to_guild_cached(&ctx.cache) else {
        return false;
    };

    if target == guild.owner_id || !guild.member_permissions(&bot_member).ban_members() {
        return false;
    }

    let target_position = target_member.map_or(0, |member| highest_role_position(&guild, &member));
    highest_role_position(&guild, &bot_member) > target_position
}
