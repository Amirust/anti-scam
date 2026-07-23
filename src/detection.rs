use std::sync::Arc;

use crate::Error;
use crate::config::CONFIG;
use crate::img_config::ImageData;
use crate::images::{self, TileGrid};

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum Verdict {
    Ban { entry_name: String, reason: MatchReason },
    Review { entry_name: String, matched: u32, informative: u32 },
    Clean,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum MatchReason {
    WholeImage { distance: u32 },
    Tiles { matched: u32, informative: u32 },
}

pub async fn process_image(bytes: bytes::Bytes, db: Arc<Vec<ImageData>>) -> Result<Verdict, Error> {
    // decode + resize + hashing are pure CPU
    tokio::task::spawn_blocking(move || classify_image(&bytes, &db)).await?
}

/// stage 1: whole-image pHash against every DB entry (survives re-encoding and small shifts),
/// stage 2: only if stage 1 missed - shift-aligned tile matching
pub fn classify_image(bytes: &[u8], entries: &[ImageData]) -> Result<Verdict, Error> {
    let normalized = images::normalize_image(bytes)?;
    let whole_hash = images::whole_image_hash(&normalized)?;

    if let Some(verdict) = whole_verdict(&whole_hash, entries) {
        return Ok(verdict);
    }

    let shifted_grids = images::shifted_tile_grids(&normalized)?;
    Ok(tiles_verdict(&shifted_grids, entries))
}

fn whole_verdict(hash: &[u8; images::HASH_BYTES], entries: &[ImageData]) -> Option<Verdict> {
    entries
        .iter()
        .map(|entry| (images::hamming_distance(hash, &entry.whole_hash), entry))
        .filter(|&(distance, _)| distance <= CONFIG.detection.whole_match_threshold)
        .min_by_key(|&(distance, _)| distance)
        .map(|(distance, entry)| Verdict::Ban {
            entry_name: entry.name.clone(),
            reason: MatchReason::WholeImage { distance },
        })
}

fn tiles_verdict(shifted_grids: &[TileGrid], entries: &[ImageData]) -> Verdict {
    entries
        .iter()
        .map(|entry| entry_tiles_verdict(shifted_grids, entry))
        .fold(Verdict::Clean, more_severe)
}

fn entry_tiles_verdict(shifted_grids: &[TileGrid], entry: &ImageData) -> Verdict {
    let best = shifted_grids
        .iter()
        .map(|grid| match_grids(grid, &entry.grid))
        .max_by(|a, b| {
            a.matched
                .cmp(&b.matched)
                .then(b.total_distance.cmp(&a.total_distance))
        })
        .unwrap_or_default();

    let TileMatch { matched, informative, .. } = best;
    let thresholds = &CONFIG.detection;

    if informative <= thresholds.min_informative_tiles {
        return Verdict::Clean;
    }
    if matched * 100 >= informative * thresholds.hard_match_percent {
        return Verdict::Ban {
            entry_name: entry.name.clone(),
            reason: MatchReason::Tiles { matched, informative },
        };
    }
    if matched * 100 >= informative * thresholds.review_percent {
        return Verdict::Review { entry_name: entry.name.clone(), matched, informative };
    }

    Verdict::Clean
}

#[derive(Debug, Default, Clone, Copy)]
struct TileMatch {
    matched: u32,
    informative: u32,
    total_distance: u32,
}

fn match_grids(income: &TileGrid, db: &TileGrid) -> TileMatch {
    (0..images::TILE_COUNT)
        .filter(|&i| income.informative[i] && db.informative[i])
        .map(|i| images::hamming_distance(&income.hashes[i], &db.hashes[i]))
        .fold(TileMatch::default(), |acc, distance| TileMatch {
            matched: acc.matched
                + u32::from(distance <= CONFIG.detection.tile_match_threshold),
            informative: acc.informative + 1,
            total_distance: acc.total_distance + distance,
        })
}

fn more_severe(a: Verdict, b: Verdict) -> Verdict {
    // match on references: Verdict carries a String now, so it is no longer Copy
    match (&a, &b) {
        (Verdict::Ban { .. }, _) => a,
        (_, Verdict::Ban { .. }) => b,
        (
            Verdict::Review { matched: a_matched, informative: a_informative, .. },
            Verdict::Review { matched: b_matched, informative: b_informative, .. },
        ) => {
            // cross-multiply to compare match ratios without floats
            if a_matched * b_informative >= b_matched * a_informative { a } else { b }
        }
        (Verdict::Review { .. }, Verdict::Clean) => a,
        (Verdict::Clean, Verdict::Review { .. }) => b,
        (Verdict::Clean, Verdict::Clean) => a,
    }
}
