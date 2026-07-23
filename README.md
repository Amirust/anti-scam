# Mr Beast / Melstroy anti-scam Discord bot

🇷🇺 [Русская версия](README.ru.md)

A Discord bot that catches known scam images (fake giveaways, casino spam and
similar) posted by compromised accounts, bans the sender, and reports to an
admin channel.

Scammers hijack an account and blast the same screenshot into dozens of
channels. Byte-level comparison does not work — every copy is re-encoded,
resized, or slightly edited — so the bot uses perceptual hashing calibrated to
survive exactly those transformations.

## What it does

When a message with an image attachment arrives, the bot:

1. Downloads the image (identical images from the same author being processed
   concurrently are deduplicated in flight).
2. Runs it through the detection pipeline (below) against a dataset of known
   scam images.
3. Acts on the verdict:
   - **Ban** — DMs the user an explanation (best-effort), bans them with the
     matched dataset entry in the audit-log reason, deletes their recent
     messages, and posts a report embed with the image to the guild's admin
     channel. If the bot lacks ban permissions, it posts a "cannot ban" report
     instead.
   - **Review** — a weaker match; posts a report with the image to the admin
     channel, with a **Ban user** button (for moderators with the Ban Members
     permission; also deletes the user's messages back to the flagged post, up
     to Discord's 7-day limit). Buttons keep their state in the message itself,
     so they keep working across bot restarts.
   - **Clean** — nothing happens.

Every report also carries an **Add to dataset** button — one of the ways to
grow the dataset straight from Discord, see
[Adding entries from Discord](#adding-entries-from-discord).

## How detection works

Raw hashes (sha256) are useless here: scammers re-encode every copy, so the
bytes always differ. Instead:

**0. Normalization.** Every image is resized to 256×256 (Lanczos) and converted
to grayscale.

**1. Whole-image perceptual hash.** An 8×8 DCT median pHash of the full image
is compared against every dataset entry. A Hamming distance of ≤ 10 out of
64 bits is a hard match. Calibrated on the reference set: re-encoded copies of
the same image score 0–6, unrelated pairs 18+.

**2. Tile matching.** If the whole image did not match, the bot checks for
partially redrawn variants. The image is split into a 4×4 grid of 64×64 tiles,
each hashed separately. Tile hashes break from as little as a 2 px shift while
re-encoded copies drift by ~5 px, so the incoming image is first tried at every
shift within ±6 px in 2 px steps (49 alignments) and the best-aligned grid
wins.

**3. Tile informativeness.** A tile only counts if its brightness variance
exceeds 150 — flat backgrounds score below ~120, real content above ~200. This
stops empty margins from voting.

**4. Scoring.** For each dataset entry, a tile is *informative* if it is
informative in both images, and *matched* if its Hamming distance is ≤ 13.
With more than 6 informative tiles compared:

- matched ≥ 75% of informative → **Ban**
- matched ≥ 60% → **Review**
- otherwise → **Clean**

All thresholds are tunable via [`config.toml`](#configuration).

## Banned image dataset

At startup the bot loads `banned.json` (override the path with the
`BANNED_CONFIG` env var). A missing file logs a warning and starts the bot with
an empty dataset. The file contains only hashes — the original images cannot be
reconstructed from it.

Two ways to get one:

- **Download the official dataset:** `./get-config.sh` fetches the JSON from
  the repository releases and verifies its sha256 against
  `banned.json.sha256`. If a local `banned.json` already exists, the script
  asks before overwriting it (local additions would be lost). Review the
  script before running it.
- **Build your own:** put scam screenshots into a folder and run
  `anti-scam export <folder> [banned.json]`. Each image is run through the
  hashing pipeline; the command writes the config and prints its sha256 for
  the checksum file. One or two reference images per scam type are usually
  enough.

The dataset is bound to a hashing pipeline version (`pipeline_version`). If
the hashing algorithm changes, the bot rejects old configs — download a fresh
one or regenerate with `anti-scam export`.

### Adding entries from Discord

New scam templates show up faster than anyone re-runs `export`, so the dataset
can be grown without touching the server:

- **From a report** — every ban/review report in the admin channel carries an
  **Add to dataset** button. It opens a modal asking for an entry name
  (optional — leave it empty for an auto-generated one).
- **From any message** — right-click a message → **Apps** → **Add image to
  dataset**. The modal additionally asks which image to take when the message
  has several (defaults to the first one).
- **From the bot's DM** — the context menu command works in direct messages
  too. Spotted a fresh scam somewhere else? Forward the message (or send the
  image) to the bot in DM, right-click it, add. Forwarded messages are fully
  supported.

Both paths are owner-only: the context menu entry is visible to
administrators, but only the bot owner can execute it. New entries are
appended to the local `banned.json` and picked up on the fly — no restart
needed. Images that already hard-match an existing entry are rejected as
duplicates, and entry names must be unique.

## Setup

Requirements: Rust (edition 2024).

```sh
export DISCORD_TOKEN=your-bot-token
cargo run --release
```

The sqlite database (`data.db`) is created and migrated automatically on first
start.

The bot needs the **Message Content** gateway intent (enable it in the Discord
developer portal) and the **Ban Members**, **Send Messages** and
**Embed Links** permissions in the guild.

Then, in each guild, an administrator sets the channel for reports:

```
/settings set_notification_channel #channel
```

Guild settings are stored in sqlite and served from an in-memory LRU cache, so
regular message processing does not touch the database.

### Docker

```sh
cp .env.example .env          # put your DISCORD_TOKEN there
mkdir -p config data
cp config.toml config/        # optional, defaults are used without it
cp banned.json config/        # or fetch it with ./get-config.sh config/banned.json
docker compose up -d --build
```

`banned.json` and `config.toml` live on the host in `./config` and are mounted
into the container as a directory — entries added via the **Add to dataset**
button land in the host file. The sqlite database persists in `./data`.

## Configuration

Optional. The bot reads `config.toml` from the working directory (override
with the `CONFIG_PATH` env var); missing keys or a missing file fall back to
defaults. The file is read once at startup.

| Key | Default | Meaning |
|-----|---------|---------|
| `detection.whole_match_threshold` | 10 | Max Hamming distance (of 64 bits) for a whole-image match |
| `detection.tile_match_threshold` | 13 | Max Hamming distance for a tile match |
| `detection.min_informative_tiles` | 6 | Minimum informative tiles for a trusted tile verdict |
| `detection.hard_match_percent` | 75 | Matched-tile percentage for an auto ban |
| `detection.review_percent` | 60 | Matched-tile percentage to escalate for review |
| `cache.guild_settings_capacity` | 100 | Guilds kept in the settings LRU cache |

These are matching-time thresholds only — tuning them never invalidates an
existing `banned.json`.

### Environment variables

| Variable | Default | Meaning |
|----------|---------|---------|
| `DISCORD_TOKEN` | — (required) | Bot token |
| `BANNED_CONFIG` | `./banned.json` | Path to the banned image dataset |
| `CONFIG_PATH` | `./config.toml` | Path to the runtime config |
