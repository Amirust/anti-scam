use crate::Error;
use image::GrayImage;
use image_hasher::{HashAlg, Hasher, HasherConfig};
use rayon::prelude::*;
use sha2::{Digest, Sha256};

/// in pixels
const IMAGE_SIZE: usize = 256;
/// in pixels
const TILE_SIZE: usize = 64;
const TILES_PER_SIDE: usize = IMAGE_SIZE / TILE_SIZE; // 4
pub const TILE_COUNT: usize = TILES_PER_SIDE * TILES_PER_SIDE; // 16
/// in bytes
const BYTES_PER_PIXEL: usize = 1; // grayscale
/// perceptual hash dimensions in bits per side
const HASH_SIZE: u32 = 8;
/// perceptual hash output size in bytes (8x8 bits = 8 bytes)
pub const HASH_BYTES: usize = (HASH_SIZE * HASH_SIZE) as usize / 8;

const INFORMATIVE_VARIANCE_THRESHOLD: f32 = 150.0;

/// max |shift| in px tried when aligning an incoming image before tiling re-encoded scam copies drift by ~5px at 256x256 scale
const SHIFT_RANGE: i32 = 6;
/// step between trial shifts, the residual +-1px misalignment costs ~6 bits of tile distance
const SHIFT_STEP: usize = 2;

/// max |angle| in degrees tried when counter-rotating an incoming image for the whole-image hash; screenshots tilted a few degrees are a cheap fingerprint-evasion trick
const ROTATION_RANGE_DEG: i32 = 12;
/// step between trial rotations, a residual +-1.5 deg misrotation costs ~4-8 bits of whole-hash distance
const ROTATION_STEP_DEG: usize = 3;

/// rows/columns flatter than this variance count as digital padding; photo content carries sensor noise and stays well above
const BORDER_VARIANCE_THRESHOLD: f32 = 30.0;
/// skip the trimmed view unless at least this many border px (all four sides summed) went away
const MIN_TRIM_PX: usize = 8;
/// a trim must leave at least this many px per axis, tighter crops are a different image
const MIN_TRIMMED_SIZE: usize = 96;

#[derive(Debug, Clone)]
pub struct TileGrid {
    pub hashes: [[u8; HASH_BYTES]; TILE_COUNT],
    pub informative: [bool; TILE_COUNT],
}

pub fn get_hasher() -> Hasher {
    HasherConfig::new()
        .hash_size(HASH_SIZE, HASH_SIZE)
        .preproc_dct()
        .hash_alg(HashAlg::Median)
        .to_hasher()
}

pub fn hamming_distance(a: &[u8; HASH_BYTES], b: &[u8; HASH_BYTES]) -> u32 {
    a.iter().zip(b).map(|(x, y)| (x ^ y).count_ones()).sum()
}

pub fn sha256_hash(data: &[u8]) -> [u8; 32] {
    Sha256::digest(data).into()
}

pub fn normalize_image(bytes: &[u8]) -> Result<Vec<u8>, image::ImageError> {
    let img = image::load_from_memory(bytes)?;
    let normalized = img
        .resize_exact(256, 256, image::imageops::FilterType::Lanczos3)
        .grayscale()
        .into_luma8();

    Ok(normalized.into_raw())
}

pub fn is_informative(tile: &[u8]) -> bool {
    variance_of(tile) > INFORMATIVE_VARIANCE_THRESHOLD
}

fn variance_of(pixels: &[u8]) -> f32 {
    let n = pixels.len() as f32;

    let mean = pixels.iter().map(|&p| p as f32).sum::<f32>() / n;
    pixels.iter()
        .map(|&p| (p as f32 - mean).powi(2))
        .sum::<f32>() / n
}

pub fn whole_image_hash(normalized: &[u8]) -> Result<[u8; HASH_BYTES], Error> {
    let image = GrayImage::from_raw(IMAGE_SIZE as u32, IMAGE_SIZE as u32, normalized.to_vec())
        .ok_or("failed to create GrayImage from normalized image data")?;

    hash_gray_image(&get_hasher(), &image)
}

/// translate the normalized image by (dy, dx), replicating edge pixels instead of wrapping, so border tiles are not polluted by the opposite side
pub fn shift_image(normalized: &[u8], dy: i32, dx: i32) -> Vec<u8> {
    debug_assert_eq!(normalized.len(), IMAGE_SIZE * IMAGE_SIZE * BYTES_PER_PIXEL);

    let size = IMAGE_SIZE as i32;
    (0..size)
        .flat_map(|y| {
            let src_y = (y - dy).clamp(0, size - 1);
            (0..size).map(move |x| {
                let src_x = (x - dx).clamp(0, size - 1);
                normalized[(src_y * size + src_x) as usize]
            })
        })
        .collect()
}

/// tile grids of the image under every trial shift (includes the zero shift), the tile matcher picks whichever grid aligns best with the DB entry
pub fn shifted_tile_grids(normalized: &[u8]) -> Result<Vec<TileGrid>, Error> {
    trial_shifts()
        .collect::<Vec<_>>()
        .into_par_iter()
        .map(|(dy, dx)| get_hash_grid(&shift_image(normalized, dy, dx)))
        .collect()
}

fn trial_shifts() -> impl Iterator<Item = (i32, i32)> {
    let steps = || (-SHIFT_RANGE..=SHIFT_RANGE).step_by(SHIFT_STEP);
    steps().flat_map(move |dy| steps().map(move |dx| (dy, dx)))
}

/// rotate the normalized image about its center by `degrees`, bilinear
/// sampling with edge clamp so corners replicate border pixels instead of
/// introducing fake black wedges that would skew the DCT hash
pub fn rotate_image(normalized: &[u8], degrees: f32) -> Vec<u8> {
    debug_assert_eq!(normalized.len(), IMAGE_SIZE * IMAGE_SIZE * BYTES_PER_PIXEL);

    let center = (IMAGE_SIZE as f32 - 1.0) / 2.0;
    let (sin, cos) = degrees.to_radians().sin_cos();

    let mut rotated = Vec::with_capacity(IMAGE_SIZE * IMAGE_SIZE);
    for y in 0..IMAGE_SIZE {
        for x in 0..IMAGE_SIZE {
            let dx = x as f32 - center;
            let dy = y as f32 - center;
            // inverse mapping: sample the source at the un-rotated position
            let src_x = center + cos * dx + sin * dy;
            let src_y = center - sin * dx + cos * dy;
            rotated.push(bilinear_sample(normalized, src_x, src_y));
        }
    }

    rotated
}

fn bilinear_sample(pixels: &[u8], x: f32, y: f32) -> u8 {
    let max = (IMAGE_SIZE - 1) as f32;
    let x = x.clamp(0.0, max);
    let y = y.clamp(0.0, max);

    let x0 = x.floor() as usize;
    let y0 = y.floor() as usize;
    let x1 = (x0 + 1).min(IMAGE_SIZE - 1);
    let y1 = (y0 + 1).min(IMAGE_SIZE - 1);
    let fx = x - x0 as f32;
    let fy = y - y0 as f32;

    let sample = |xx: usize, yy: usize| pixels[yy * IMAGE_SIZE + xx] as f32;
    let top = sample(x0, y0) * (1.0 - fx) + sample(x1, y0) * fx;
    let bottom = sample(x0, y1) * (1.0 - fx) + sample(x1, y1) * fx;

    (top * (1.0 - fy) + bottom * fy).round() as u8
}

/// whole-image hashes of the image under every trial rotation (includes 0°);
/// stage 1 takes the minimum distance per entry, so a tilted repost of a scam
/// template still lands within the whole-match threshold
pub fn rotated_whole_hashes(normalized: &[u8]) -> Result<Vec<[u8; HASH_BYTES]>, Error> {
    trial_rotations()
        .collect::<Vec<_>>()
        .into_par_iter()
        .map(|deg| whole_image_hash(&rotate_image(normalized, deg as f32)))
        .collect()
}

/// crop away near-uniform borders (white padding, dark frames,
/// screenshot-of-a-screenshot canvases) and rescale the remaining content back
/// to 256x256; `None` when there is nothing worth trimming
pub fn trimmed_view(normalized: &[u8]) -> Option<Vec<u8>> {
    debug_assert_eq!(normalized.len(), IMAGE_SIZE * IMAGE_SIZE * BYTES_PER_PIXEL);

    let row = |y: usize| &normalized[y * IMAGE_SIZE..(y + 1) * IMAGE_SIZE];
    let column = |x: usize| -> Vec<u8> {
        (0..IMAGE_SIZE).map(|y| normalized[y * IMAGE_SIZE + x]).collect()
    };
    let is_flat_row = |y: &usize| variance_of(row(*y)) < BORDER_VARIANCE_THRESHOLD;
    let is_flat_column = |x: &usize| variance_of(&column(*x)) < BORDER_VARIANCE_THRESHOLD;

    let top = (0..IMAGE_SIZE).take_while(is_flat_row).count();
    let bottom = (0..IMAGE_SIZE).rev().take_while(is_flat_row).count();
    let left = (0..IMAGE_SIZE).take_while(is_flat_column).count();
    let right = (0..IMAGE_SIZE).rev().take_while(is_flat_column).count();

    // a fully flat image trims to nothing, checked_sub bails out on it
    let width = IMAGE_SIZE.checked_sub(left + right)?;
    let height = IMAGE_SIZE.checked_sub(top + bottom)?;
    if width < MIN_TRIMMED_SIZE || height < MIN_TRIMMED_SIZE {
        return None;
    }
    if top + bottom + left + right < MIN_TRIM_PX {
        return None;
    }

    let mut content = Vec::with_capacity(width * height);
    for y in top..IMAGE_SIZE - bottom {
        let start = y * IMAGE_SIZE + left;
        content.extend_from_slice(&normalized[start..start + width]);
    }

    let cropped = GrayImage::from_raw(width as u32, height as u32, content)?;
    let resized = image::DynamicImage::ImageLuma8(cropped)
        .resize_exact(
            IMAGE_SIZE as u32,
            IMAGE_SIZE as u32,
            image::imageops::FilterType::Lanczos3,
        )
        .into_luma8();

    Some(resized.into_raw())
}

/// every whole-image hash view stage 1 tries: the image itself and (when
/// uniform padding was detected) its border-trimmed version, each under all
/// trial rotations; the matcher takes the minimum distance per entry
pub fn stage1_hashes(normalized: &[u8]) -> Result<Vec<[u8; HASH_BYTES]>, Error> {
    let mut hashes = rotated_whole_hashes(normalized)?;
    if let Some(trimmed) = trimmed_view(normalized) {
        hashes.extend(rotated_whole_hashes(&trimmed)?);
    }

    Ok(hashes)
}

fn trial_rotations() -> impl Iterator<Item = i32> {
    (-ROTATION_RANGE_DEG..=ROTATION_RANGE_DEG).step_by(ROTATION_STEP_DEG)
}

pub fn get_hash_grid(bytes: &[u8]) -> Result<TileGrid, Error> {
    let expected_len = IMAGE_SIZE * IMAGE_SIZE * BYTES_PER_PIXEL;
    if bytes.len() != expected_len {
        return Err(format!(
            "expected {expected_len} bytes of normalized image data, got {}",
            bytes.len()
        )
        .into());
    }

    let hasher = get_hasher();

    let stride = IMAGE_SIZE * BYTES_PER_PIXEL;
    let mut hashes = Vec::with_capacity(TILE_COUNT);
    let mut informative = Vec::with_capacity(TILE_COUNT);

    for ty in 0..TILES_PER_SIDE {
        for tx in 0..TILES_PER_SIDE {
            let mut tile: Vec<u8> = Vec::with_capacity(TILE_SIZE * TILE_SIZE * BYTES_PER_PIXEL);

            for row in 0..TILE_SIZE {
                let src_row = ty * TILE_SIZE + row;
                let start = src_row * stride + tx * TILE_SIZE * BYTES_PER_PIXEL;
                let end = start + TILE_SIZE * BYTES_PER_PIXEL;
                tile.extend_from_slice(&bytes[start..end]);
            }

            let image = GrayImage::from_raw(TILE_SIZE as u32, TILE_SIZE as u32, tile)
                .ok_or("failed to create GrayImage from raw tile data")?;

            hashes.push(hash_gray_image(&hasher, &image)?);
            informative.push(is_informative(image.as_raw()));
        }
    }

    let hashes: [[u8; HASH_BYTES]; TILE_COUNT] = hashes
        .try_into()
        .map_err(|_| "unexpected tile hash count")?;
    let informative: [bool; TILE_COUNT] = informative
        .try_into()
        .map_err(|_| "unexpected informative mask length")?;

    Ok(TileGrid { hashes, informative })
}

fn hash_gray_image(hasher: &Hasher, image: &GrayImage) -> Result<[u8; HASH_BYTES], Error> {
    Ok(hasher
        .hash_image(image)
        .as_bytes()
        .try_into()
        .map_err(|_| "unexpected perceptual hash length")?)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn hamming_distance_counts_differing_bits() {
        let zeros = [0u8; HASH_BYTES];
        let ones = [0xFFu8; HASH_BYTES];

        assert_eq!(hamming_distance(&zeros, &zeros), 0);
        assert_eq!(hamming_distance(&zeros, &ones), 64);
        assert_eq!(hamming_distance(&[0x0Fu8; HASH_BYTES], &zeros), 32);
    }

    #[test]
    fn shift_image_translates_content() {
        let marker = 10 * IMAGE_SIZE + 10;
        let img: Vec<u8> = (0..IMAGE_SIZE * IMAGE_SIZE)
            .map(|i| if i == marker { 255 } else { 0 })
            .collect();

        let shifted = shift_image(&img, 2, 4);
        assert_eq!(shifted[12 * IMAGE_SIZE + 14], 255);

        let shifted_left = shift_image(&img, 0, -6);
        assert_eq!(shifted_left[10 * IMAGE_SIZE + 4], 255);
    }

    #[test]
    fn shift_image_replicates_edges_instead_of_wrapping() {
        let img: Vec<u8> = (0..IMAGE_SIZE * IMAGE_SIZE)
            .map(|i| if i % IMAGE_SIZE == IMAGE_SIZE - 1 { 200 } else { 0 })
            .collect();

        let shifted = shift_image(&img, 0, -3);
        assert_eq!(shifted[IMAGE_SIZE - 1], 200);
        assert_eq!(shifted[IMAGE_SIZE - 3], 200);
        assert_eq!(shifted[IMAGE_SIZE - 4], 200);
        assert_eq!(shifted[IMAGE_SIZE - 5], 0);
    }

    #[test]
    fn trial_shifts_cover_symmetric_grid_with_zero() {
        let shifts: Vec<_> = trial_shifts().collect();

        assert_eq!(shifts.len(), 49);
        assert!(shifts.contains(&(0, 0)));
        assert!(shifts.contains(&(-6, 6)));
        assert!(shifts.contains(&(2, 6)));
    }

    #[test]
    fn rotate_image_zero_degrees_is_identity() {
        let img: Vec<u8> = (0..IMAGE_SIZE * IMAGE_SIZE)
            .map(|i| (i % 251) as u8)
            .collect();

        assert_eq!(rotate_image(&img, 0.0), img);
    }

    #[test]
    fn rotate_image_quarter_turn_moves_marker() {
        let (marker_x, marker_y) = (10usize, 20usize);
        let img: Vec<u8> = (0..IMAGE_SIZE * IMAGE_SIZE)
            .map(|i| if i == marker_y * IMAGE_SIZE + marker_x { 255 } else { 0 })
            .collect();

        // inverse mapping for 90 deg: src_x = dest_y, src_y = (size-1) - dest_x
        let rotated = rotate_image(&img, 90.0);
        let dest_x = (IMAGE_SIZE - 1) - marker_y;
        let dest_y = marker_x;
        assert_eq!(rotated[dest_y * IMAGE_SIZE + dest_x], 255);
        assert_eq!(rotated.iter().filter(|&&p| p == 255).count(), 1);
    }

    #[test]
    fn small_rotation_barely_moves_whole_hash() {
        // block gradient pattern: structured enough for a meaningful hash
        let img: Vec<u8> = (0..IMAGE_SIZE * IMAGE_SIZE)
            .map(|i| {
                let (y, x) = (i / IMAGE_SIZE, i % IMAGE_SIZE);
                ((x / 32) * 32 + (y / 32) * 8) as u8
            })
            .collect();

        let base = whole_image_hash(&img).unwrap();
        let rotated = whole_image_hash(&rotate_image(&img, 2.0)).unwrap();
        assert!(hamming_distance(&base, &rotated) <= 10);
    }

    #[test]
    fn trial_rotations_cover_symmetric_range_with_zero() {
        let rotations: Vec<_> = trial_rotations().collect();

        assert_eq!(rotations.len(), 9);
        assert!(rotations.contains(&0));
        assert!(rotations.contains(&-12));
        assert!(rotations.contains(&12));
    }

    /// noisy checkerboard content in the given box, uniform `background` elsewhere
    fn padded_test_image(content_box: (usize, usize, usize, usize), background: u8) -> Vec<u8> {
        let (x0, y0, x1, y1) = content_box;
        (0..IMAGE_SIZE * IMAGE_SIZE)
            .map(|i| {
                let (y, x) = (i / IMAGE_SIZE, i % IMAGE_SIZE);
                if x >= x0 && x < x1 && y >= y0 && y < y1 {
                    if (x + y) % 2 == 0 { 30 } else { 220 }
                } else {
                    background
                }
            })
            .collect()
    }

    #[test]
    fn trimmed_view_strips_uniform_borders() {
        let img = padded_test_image((28, 28, 228, 228), 255);
        let trimmed = trimmed_view(&img).expect("padding should be trimmed");

        // the checkerboard content fills the whole trimmed frame again
        assert_eq!(trimmed.len(), IMAGE_SIZE * IMAGE_SIZE);
        assert!(is_informative(&trimmed[..IMAGE_SIZE * 8]));
    }

    #[test]
    fn trimmed_view_skips_full_frame_content() {
        let img = padded_test_image((0, 0, IMAGE_SIZE, IMAGE_SIZE), 255);
        assert!(trimmed_view(&img).is_none());
    }

    #[test]
    fn trimmed_view_skips_fully_flat_images() {
        assert!(trimmed_view(&vec![128u8; IMAGE_SIZE * IMAGE_SIZE]).is_none());
    }

    #[test]
    fn trimmed_view_rejects_overly_deep_trims() {
        // content smaller than MIN_TRIMMED_SIZE is a different image, not padding
        let img = padded_test_image((100, 100, 180, 180), 0);
        assert!(trimmed_view(&img).is_none());
    }

    #[test]
    fn is_informative_filters_flat_tiles() {
        let flat = vec![128u8; TILE_SIZE * TILE_SIZE];
        assert!(!is_informative(&flat));

        let checkerboard: Vec<u8> = (0..TILE_SIZE * TILE_SIZE)
            .map(|i| if (i / TILE_SIZE + i % TILE_SIZE) % 2 == 0 { 0 } else { 255 })
            .collect();
        assert!(is_informative(&checkerboard));
    }
}
