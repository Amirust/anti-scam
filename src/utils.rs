use serenity::all::{GuildId, UserId};
use poise::serenity_prelude::Context;

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