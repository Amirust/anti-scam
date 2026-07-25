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

When a message with an image arrives — a direct attachment, an attachment of
a forwarded message, or a link whose preview Discord resolves into an embed —
the bot:

1. Downloads the image (identical images from the same author being processed
   concurrently are deduplicated in flight). Link previews are fetched through
   the Discord media proxy only, the bot never contacts third-party hosts.
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
is compared against every dataset entry. Two cheap evasion tricks are
compensated with extra trial views of the incoming image: tilted screenshots
(hashes at rotations within ±12° in 3° steps) and added margins — white
padding, dark frames, a screenshot-of-a-screenshot (a hash of the image with
near-uniform borders trimmed away). The minimum distance across all views
counts. A Hamming distance of ≤ 12 out of 64 bits is a hard match. Calibrated
on the reference set: re-encoded copies of the same image score 0–6, tilted /
padded / re-framed copies stay within the threshold, unrelated pairs 18+.

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

## DINOv2 shadow mode (experimental)

Perceptual hashes catch re-encodes of a known image but cannot bridge
different crops, scales or re-rendered variants of the same scam template.
The embedding stage is meant to close that gap: every image is encoded with
DINOv2-S into a 384-dim vector and compared by cosine similarity against
embeddings of the known scam set.

It runs in **shadow mode**: it never bans, never deletes, and does not affect
the hash pipeline verdict. It exists to collect calibration data first:

- Every scanned image gets a row in sqlite (`dino_observations`): best-matching
  dataset entry, cosine similarity, and what the hash pipeline said
  (`ban`/`review`/`clean`). Rows for clean traffic build the negative
  similarity distribution the threshold needs; rows for hash-confirmed bans are
  free positive samples.
- When the hash pipeline says clean and the review gate trips, a labeling
  card is posted to the admin channel: **✅ Scam (hash missed it)** /
  **❌ Not a scam** / **⚠️ Legit but similar**. Labeling requires the Ban
  Members permission; the first label wins and is stored with the
  observation.
- Labels feed the dataset on the spot: a confirmed scam becomes a new **scam
  reference**, a "legit but similar" becomes a **negative reference** — a
  known legit look-alike. The review gate is comparative: a card is posted
  only if the best scam similarity beats the best negative similarity by
  `dino.negative_margin`, so one labeled false alarm suppresses its whole
  look-alike class without touching scam recall. Plain "not a scam" labels
  only calibrate the threshold.
- Pixels are kept for every label and reference under `dino.captures_dir`
  (`<group>/<name>.<ext>`) — re-exports after a pipeline bump and threshold
  eval runs need images, not scalars. Clean traffic is never saved to disk.
- The card also carries the usual **Add to dataset** button (owner only) to
  close the hash-side gap immediately.

Manual dataset control from Discord (right-click a message → Apps):

- **DINO: add as scam** / **DINO: add as negative** — add an image to the
  embedding dataset directly (owner only, shown to administrators).
  Near-duplicate embeddings and taken names are rejected.
- **DINO: check image** — ephemeral similarity diagnostics for a message's
  images: best match, closest negative, and what the review gate would do.
  Requires Ban Members, touches nothing.

Setup:

```sh
# 1. the encoder (Xenova/dinov2-small ONNX export, ~85 MB, fp32)
curl -L -o dinov2s.onnx \
  https://huggingface.co/Xenova/dinov2-small/resolve/main/onnx/model.onnx

# 2. reference embeddings from your scam image folder (recursive);
#    --negatives seeds known legit look-alikes, e.g. from collected captures
anti-scam dino-export ./images [dino.json] [--negatives ./dino_captures/hard_negative]

# 3. enable in config.toml
#    [dino]
#    enabled = true
```

Calibration without live traffic: `anti-scam dino-classify <folder>
[dino.json]` scores every image in a folder against the dataset and prints a
TSV (best + second-best match) with a summary on stderr. Variants of a known
template typically land at 0.7–1.0, the same image at ~1.0; genuinely
different layouts score lower and should become their own dataset entries,
same as in the hash pipeline.

Notes: additions from Discord (labels and context commands) update the
dataset file and the running bot on the fly; a restart is only needed when
the file is rebuilt externally with `dino-export` (don't run it while the
bot is writing the same file). The dataset is bound to its own pipeline
version — anything that changes how embeddings are computed requires a
re-export. A missing dataset file starts shadow mode empty (grow it from
Discord); a broken model or dataset fails startup. The hash dataset
(`banned.json`) and the embedding dataset are separate — the **Add to
dataset** button feeds the former, the DINO commands feed the latter.

## HTTP API (experimental)

External services can submit images for a check over HTTP. The caller always
gets an immediate `200 {"status":"accepted"}` — classification runs in the
background and the result never reaches the caller. When the DINO stage flags
the image (primary signal) or the hash pipeline matches it, a report card
with both signals and the image lands in the configured channel
(`api.report_guild_id` / `api.report_channel_id`). Nothing is banned or
deleted. Cards carry the usual DINO labeling buttons, so API submissions feed
calibration and the reference dataset like any other card.

```sh
# server side: secret in the environment, endpoint in config.toml ([api])
export API_JWT_SECRET=<random string, 32+ chars>

# mint a client token (HS256 JWT; same secret as the server)
anti-scam issue-token my-client 365

# client side: raw image bytes, Bearer auth
curl -X POST http://127.0.0.1:8080/v1/check \
  -H "Authorization: Bearer <token>" \
  --data-binary @image.jpg
```

Responses: `200` accepted, `401` bad/expired token, `400` empty body, `413`
over the 20 MB cap, `429` too many submissions in flight (each one costs an
inference — retry later). The endpoint serves plain HTTP; keep `api.bind` on
loopback and terminate TLS / do rate limiting in a reverse proxy when
exposing it.

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

For shadow mode, put `dinov2s.onnx` and `dino.json` into `./config` too and
point `dino.model_path` / `dino.dataset_path` in `config.toml` at
`/config/...`.

## Configuration

Optional. The bot reads `config.toml` from the working directory (override
with the `CONFIG_PATH` env var); missing keys or a missing file fall back to
defaults. The file is read once at startup.

| Key | Default | Meaning |
|-----|---------|---------|
| `detection.whole_match_threshold` | 12 | Max Hamming distance (of 64 bits) for a whole-image match |
| `detection.tile_match_threshold` | 13 | Max Hamming distance for a tile match |
| `detection.min_informative_tiles` | 6 | Minimum informative tiles for a trusted tile verdict |
| `detection.hard_match_percent` | 75 | Matched-tile percentage for an auto ban |
| `detection.review_percent` | 60 | Matched-tile percentage to escalate for review |
| `cache.guild_settings_capacity` | 100 | Guilds kept in the settings LRU cache |
| `dino.enabled` | `false` | Embedding shadow mode ([details](#dinov2-shadow-mode-experimental)) |
| `dino.model_path` | `./dinov2s.onnx` | DINOv2-S ONNX encoder |
| `dino.dataset_path` | `./dino.json` | Embedding dataset built by `dino-export` |
| `dino.review_threshold` | 0.6 | Min cosine similarity to post a labeling card |
| `dino.negative_margin` | 0.05 | Scam similarity must beat the best negative by this much |
| `dino.intra_threads` | 2 | ONNX Runtime threads per inference |
| `dino.captures_dir` | `./dino_captures` | Where labeled card and reference images are saved |
| `api.enabled` | `false` | HTTP check endpoint ([details](#http-api-experimental)) |
| `api.bind` | `127.0.0.1:8080` | API bind address |
| `api.report_guild_id` | — | Guild of the report channel (required when enabled) |
| `api.report_channel_id` | — | Channel receiving reports for flagged submissions |

These are matching-time thresholds only — tuning them never invalidates an
existing `banned.json`.

### Environment variables

| Variable | Default | Meaning |
|----------|---------|---------|
| `DISCORD_TOKEN` | — (required) | Bot token |
| `BANNED_CONFIG` | `./banned.json` | Path to the banned image dataset |
| `CONFIG_PATH` | `./config.toml` | Path to the runtime config |
| `API_JWT_SECRET` | — (required with `api.enabled`) | HS256 secret for API tokens, 32+ chars |
