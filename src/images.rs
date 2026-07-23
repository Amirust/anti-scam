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
    let n = tile.len() as f32;

    let mean = tile.iter().map(|&p| p as f32).sum::<f32>() / n;
    let variance = tile.iter()
        .map(|&p| (p as f32 - mean).powi(2))
        .sum::<f32>() / n;

    variance > INFORMATIVE_VARIANCE_THRESHOLD
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
    fn is_informative_filters_flat_tiles() {
        let flat = vec![128u8; TILE_SIZE * TILE_SIZE];
        assert!(!is_informative(&flat));

        let checkerboard: Vec<u8> = (0..TILE_SIZE * TILE_SIZE)
            .map(|i| if (i / TILE_SIZE + i % TILE_SIZE) % 2 == 0 { 0 } else { 255 })
            .collect();
        assert!(is_informative(&checkerboard));
    }
}
