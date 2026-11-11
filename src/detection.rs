use std::sync::Arc;

use crate::Error;
use crate::config::CONFIG;
use crate::img_config::ImageData;
use crate::images::{self, TileGrid};

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum Verdict {
    Ban { entry_name: String, reason: MatchReason },
    Review { entry_name: String, reason: MatchReason },
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

/// stage 1: whole-image pHash under trial rotations and a border-trim trial
/// against every DB entry (survives re-encoding, small shifts, slight tilts
/// and added margins); a hit bans when it is strong or confirmed by tiles,
/// otherwise it goes to review. stage 2: shift-aligned tile matching
pub fn classify_image(bytes: &[u8], entries: &[ImageData]) -> Result<Verdict, Error> {
    let normalized = images::normalize_image(bytes)?;
    let views = images::stage1_views(&normalized);
    let whole_hashes = images::stage1_hashes(&views)?;
    let hits = whole_hits(&whole_hashes, entries);

    // cheap path: a strong hit needs no tiles at all
    if let Some(hit) = hits.first().filter(|hit| whole_hit_bans(hit.distance, 0)) {
        return Ok(hit.verdict(true));
    }

    let shifted_grids = images::shifted_tile_grids(&normalized)?;
    for hit in &hits {
        if whole_hit_bans(hit.distance, confirming_tiles(hit, &views, &shifted_grids)?) {
            return Ok(hit.verdict(true));
        }
    }

    // an unconfirmed whole-image hit is left to a moderator
    let unconfirmed = hits.first().map_or(Verdict::Clean, |hit| hit.verdict(false));
    Ok(more_severe(tiles_verdict(&shifted_grids, entries), unconfirmed))
}

struct WholeHit<'a> {
    entry: &'a ImageData,
    distance: u32,
    /// index into the stage 1 views of the closest one
    view: usize,
}

impl WholeHit<'_> {
    fn verdict(&self, ban: bool) -> Verdict {
        let entry_name = self.entry.name.clone();
        let reason = MatchReason::WholeImage { distance: self.distance };
        if ban { Verdict::Ban { entry_name, reason } } else { Verdict::Review { entry_name, reason } }
    }
}

/// entries within the whole-match threshold, closest first
fn whole_hits<'a>(hashes: &[[u8; images::HASH_BYTES]], entries: &'a [ImageData]) -> Vec<WholeHit<'a>> {
    let mut hits: Vec<WholeHit> = entries
        .iter()
        .filter_map(|entry| {
            hashes
                .iter()
                .enumerate()
                .map(|(view, hash)| (images::hamming_distance(hash, &entry.whole_hash), view))
                .min()
                .map(|(distance, view)| WholeHit { entry, distance, view })
        })
        .filter(|hit| hit.distance <= CONFIG.detection.whole_match_threshold)
        .collect();
    hits.sort_by_key(|hit| hit.distance);
    hits
}

/// a 64-bit pHash only captures the coarse brightness layout, and trying 18
/// views gives an unrelated image 18 chances to land in the threshold: smooth,
/// low-contrast pictures (faces, skin, gradients) and different screenshots of
/// one page template do. so only a near-exact hit bans on its own; a looser
/// one needs tiles that agree with the entry
fn whole_hit_bans(distance: u32, confirming_tiles: u32) -> bool {
    let thresholds = &CONFIG.detection;
    distance <= thresholds.whole_match_threshold
        && (distance <= thresholds.whole_strong_threshold
            || confirming_tiles >= thresholds.whole_confirm_tiles)
}

/// matched tiles backing a whole-image hit: on the image itself, or on the
/// view that matched, where a counter-rotated or trimmed copy lines up with the
/// entry again
fn confirming_tiles(hit: &WholeHit, views: &[Vec<u8>], shifted_grids: &[TileGrid]) -> Result<u32, Error> {
    let on_image = best_tile_match(shifted_grids, &hit.entry.grid).matched;
    if on_image >= CONFIG.detection.whole_confirm_tiles {
        return Ok(on_image);
    }

    let view_grids = images::shifted_tile_grids(&views[hit.view])?;
    Ok(on_image.max(best_tile_match(&view_grids, &hit.entry.grid).matched))
}

fn tiles_verdict(shifted_grids: &[TileGrid], entries: &[ImageData]) -> Verdict {
    entries
        .iter()
        .map(|entry| entry_tiles_verdict(shifted_grids, entry))
        .fold(Verdict::Clean, more_severe)
}

fn entry_tiles_verdict(shifted_grids: &[TileGrid], entry: &ImageData) -> Verdict {
    let TileMatch { matched, informative, .. } = best_tile_match(shifted_grids, &entry.grid);
    let thresholds = &CONFIG.detection;

    if informative <= thresholds.min_informative_tiles {
        return Verdict::Clean;
    }
    let entry_name = entry.name.clone();
    let reason = MatchReason::Tiles { matched, informative };
    if matched * 100 >= informative * thresholds.hard_match_percent {
        return Verdict::Ban { entry_name, reason };
    }
    if matched * 100 >= informative * thresholds.review_percent {
        return Verdict::Review { entry_name, reason };
    }

    Verdict::Clean
}

#[derive(Debug, Default, Clone, Copy)]
struct TileMatch {
    matched: u32,
    informative: u32,
    total_distance: u32,
}

/// the best-aligned trial shift: most matched tiles, then lowest total distance
fn best_tile_match(shifted_grids: &[TileGrid], db: &TileGrid) -> TileMatch {
    shifted_grids
        .iter()
        .map(|grid| match_grids(grid, db))
        .max_by(|a, b| {
            a.matched
                .cmp(&b.matched)
                .then(b.total_distance.cmp(&a.total_distance))
        })
        .unwrap_or_default()
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
        (Verdict::Review { reason: a_reason, .. }, Verdict::Review { reason: b_reason, .. }) => {
            if stronger_review(*a_reason, *b_reason) { a } else { b }
        }
        (Verdict::Review { .. }, Verdict::Clean) => a,
        (Verdict::Clean, Verdict::Review { .. }) => b,
        (Verdict::Clean, Verdict::Clean) => a,
    }
}

/// whether review reason `a` is at least as strong as `b`
fn stronger_review(a: MatchReason, b: MatchReason) -> bool {
    match (a, b) {
        (
            MatchReason::Tiles { matched: a_matched, informative: a_informative },
            MatchReason::Tiles { matched: b_matched, informative: b_informative },
        ) => {
            // cross-multiply to compare match ratios without floats
            a_matched * b_informative >= b_matched * a_informative
        }
        (MatchReason::WholeImage { distance: a_distance }, MatchReason::WholeImage { distance: b_distance }) => {
            a_distance <= b_distance
        }
        // most tiles agreeing is direct evidence, an unconfirmed whole-image hit is not
        (MatchReason::Tiles { .. }, MatchReason::WholeImage { .. }) => true,
        (MatchReason::WholeImage { .. }, MatchReason::Tiles { .. }) => false,
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::img_config;

    /// coarse blocks of different brightness: every 64x64 tile is informative
    fn block_pattern_png() -> Vec<u8> {
        let image = image::GrayImage::from_fn(512, 384, |x, y| {
            image::Luma([((x / 64) * 28 + (y / 48) * 9 + (x / 16 % 2) * 40) as u8])
        });
        let mut png = std::io::Cursor::new(Vec::new());
        image.write_to(&mut png, image::ImageFormat::Png).unwrap();
        png.into_inner()
    }

    fn review(reason: MatchReason) -> Verdict {
        Verdict::Review { entry_name: "x".into(), reason }
    }

    #[test]
    fn whole_hit_bans_only_when_strong_or_confirmed() {
        let thresholds = &CONFIG.detection;
        let strong = thresholds.whole_strong_threshold;
        let loose = thresholds.whole_match_threshold;
        let needed = thresholds.whole_confirm_tiles;

        assert!(whole_hit_bans(strong, 0));
        assert!(!whole_hit_bans(strong + 1, needed - 1));
        assert!(whole_hit_bans(loose, needed));
        assert!(!whole_hit_bans(loose + 1, images::TILE_COUNT as u32));
    }

    #[test]
    fn exact_copy_is_banned() {
        let png = block_pattern_png();
        let entries = vec![img_config::image_data_from_bytes("pattern", &png).unwrap()];

        assert_eq!(
            classify_image(&png, &entries).unwrap(),
            Verdict::Ban {
                entry_name: "pattern".into(),
                reason: MatchReason::WholeImage { distance: 0 },
            }
        );
    }

    /// the false-positive shape: the whole-image hash is close, the tiles say
    /// it is a different picture
    #[test]
    fn unconfirmed_whole_image_hit_goes_to_review() {
        let png = block_pattern_png();
        let mut entry = img_config::image_data_from_bytes("look-alike", &png).unwrap();
        entry.whole_hash[0] ^= 0xff; // 8 bits off: past the strong threshold, within the match threshold
        entry.grid.hashes.iter_mut().flatten().for_each(|byte| *byte = !*byte);

        let verdict = classify_image(&png, &[entry]).unwrap();
        assert!(
            matches!(verdict, Verdict::Review { reason: MatchReason::WholeImage { .. }, .. }),
            "{verdict:?}"
        );
    }

    #[test]
    fn confirmed_whole_image_hit_is_banned() {
        let png = block_pattern_png();
        let mut entry = img_config::image_data_from_bytes("tilted copy", &png).unwrap();
        entry.whole_hash[0] ^= 0xff;

        let verdict = classify_image(&png, &[entry]).unwrap();
        assert!(
            matches!(verdict, Verdict::Ban { reason: MatchReason::WholeImage { .. }, .. }),
            "{verdict:?}"
        );
    }

    #[test]
    fn tile_review_outranks_whole_image_review() {
        let tiles = review(MatchReason::Tiles { matched: 5, informative: 8 });
        let whole = review(MatchReason::WholeImage { distance: 6 });

        assert_eq!(more_severe(whole.clone(), tiles.clone()), tiles);
        assert_eq!(more_severe(tiles.clone(), whole), tiles);
    }

    #[test]
    fn closer_whole_image_review_wins() {
        let near = review(MatchReason::WholeImage { distance: 6 });
        let far = review(MatchReason::WholeImage { distance: 11 });

        assert_eq!(more_severe(far, near.clone()), near);
    }
}
