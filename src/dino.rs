use std::sync::{Arc, Mutex};

use ort::session::{Session, builder::GraphOptimizationLevel};
use ort::value::Tensor;

use crate::Error;
use crate::config::CONFIG;
use crate::dino_dataset::{self, DinoEntry};

/// DINOv2-S hidden size; every stored embedding must have this length
pub const EMBEDDING_DIM: usize = 384;

const INPUT_SIZE: usize = 224;
const CHANNELS: usize = 3;
/// normalization constants the encoder was trained with (ImageNet)
const IMAGENET_MEAN: [f32; CHANNELS] = [0.485, 0.456, 0.406];
const IMAGENET_STD: [f32; CHANNELS] = [0.229, 0.224, 0.225];
/// tensor names of the Xenova/dinov2-small ONNX export
const INPUT_NAME: &str = "pixel_values";
const OUTPUT_NAME: &str = "last_hidden_state";
/// ONNX Runtime intra-op threads; embeddings are a background signal and must
/// not starve the hashing pipeline of cores
const INTRA_THREADS: usize = 2;

/// everything the shadow mode needs at runtime: the ONNX encoder plus the
/// reference embeddings of known scam images
pub struct DinoRuntime {
    pub embedder: Embedder,
    pub refs: Vec<DinoEntry>,
}

/// build the shadow-mode runtime from `CONFIG.dino`; `None` when disabled or
/// when there is no embedding dataset yet, a broken model/dataset is fatal
/// (fail fast at startup, same philosophy as config.toml)
pub fn init_from_config() -> Option<Arc<DinoRuntime>> {
    let dino = &CONFIG.dino;
    if !dino.enabled {
        tracing::info!("dino shadow mode OFF (dino.enabled = false)");
        return None;
    }

    let refs = match dino_dataset::load(&dino.dataset_path) {
        Ok(refs) => refs,
        Err(e) if dino_dataset::is_not_found(&e) => {
            tracing::warn!(
                "dino.enabled is set but {} does not exist, shadow mode stays OFF; \
                 build it with `anti-scam dino-export <images_dir>`",
                dino.dataset_path
            );
            return None;
        }
        Err(e) => panic!("failed to load dino dataset {}: {e}", dino.dataset_path),
    };
    if refs.is_empty() {
        tracing::warn!("dino dataset {} has no entries, shadow mode stays OFF", dino.dataset_path);
        return None;
    }

    let embedder = Embedder::load(&dino.model_path)
        .unwrap_or_else(|e| panic!("failed to load dino model {}: {e}", dino.model_path));

    tracing::info!(
        "dino shadow mode ON: {} reference embedding(s), review threshold {}",
        refs.len(),
        dino.review_threshold
    );
    Some(Arc::new(DinoRuntime { embedder, refs }))
}

/// DINOv2-S image encoder behind ONNX Runtime; `embed` is CPU-bound and must
/// be called from a blocking context
pub struct Embedder {
    // ort sessions require &mut to run, shadow inferences are serialized
    session: Mutex<Session>,
}

impl Embedder {
    pub fn load(path: &str) -> Result<Self, Error> {
        // ort builder errors carry the non-Send builder, flatten them to text
        let session = Session::builder()
            .map_err(|e| e.to_string())?
            .with_optimization_level(GraphOptimizationLevel::Level3)
            .map_err(|e| e.to_string())?
            .with_intra_threads(INTRA_THREADS)
            .map_err(|e| e.to_string())?
            .commit_from_file(path)
            .map_err(|e| e.to_string())?;

        // fail fast on a wrong ONNX file instead of on the first image
        if !session.outputs().iter().any(|output| output.name() == OUTPUT_NAME) {
            let names: Vec<&str> = session.outputs().iter().map(|o| o.name()).collect();
            return Err(format!(
                "model {path} has no \"{OUTPUT_NAME}\" output (found {names:?}); \
                 expected the Xenova/dinov2-small ONNX export, see README"
            )
            .into());
        }

        Ok(Self { session: Mutex::new(session) })
    }

    /// decode raw image bytes into an L2-normalized CLS-token embedding
    pub fn embed(&self, bytes: &[u8]) -> Result<Vec<f32>, Error> {
        let image = image::load_from_memory(bytes)?;
        let pixels = preprocess(&image);
        let tensor = Tensor::from_array(([1, CHANNELS, INPUT_SIZE, INPUT_SIZE], pixels))?;

        let mut session = self.session.lock().unwrap();
        let outputs = session.run(ort::inputs![INPUT_NAME => tensor])?;
        let (shape, data) = outputs[OUTPUT_NAME].try_extract_tensor::<f32>()?;

        // (batch, tokens, dim); the CLS token opens the sequence
        let dim = shape.last().copied().unwrap_or_default() as usize;
        if dim != EMBEDDING_DIM || data.len() < EMBEDDING_DIM {
            return Err(format!(
                "unexpected embedding shape {shape:?}, expected dim {EMBEDDING_DIM}"
            )
            .into());
        }

        Ok(l2_normalized(&data[..EMBEDDING_DIM]))
    }
}

/// resize to the encoder input and normalize into planar (CHW) layout;
/// `resize_exact` mirrors the hashing pipeline: full content is kept, mild
/// aspect distortion is fine for the encoder
fn preprocess(image: &image::DynamicImage) -> Vec<f32> {
    let size = INPUT_SIZE as u32;
    let rgb = image
        .resize_exact(size, size, image::imageops::FilterType::Lanczos3)
        .into_rgb8();
    let pixels: Vec<image::Rgb<u8>> = rgb.pixels().copied().collect();

    (0..CHANNELS)
        .flat_map(|channel| {
            pixels.iter().map(move |pixel| {
                let value = pixel[channel] as f32 / 255.0;
                (value - IMAGENET_MEAN[channel]) / IMAGENET_STD[channel]
            })
        })
        .collect()
}

pub fn l2_normalized(vector: &[f32]) -> Vec<f32> {
    let norm = vector.iter().map(|v| v * v).sum::<f32>().sqrt().max(f32::EPSILON);
    vector.iter().map(|v| v / norm).collect()
}

/// both sides are L2-normalized, so the dot product IS the cosine similarity
pub fn cosine_similarity(a: &[f32], b: &[f32]) -> f32 {
    a.iter().zip(b).map(|(x, y)| x * y).sum()
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn preprocess_produces_planar_chw_tensor() {
        let white = image::DynamicImage::ImageRgb8(image::RgbImage::from_pixel(
            10,
            10,
            image::Rgb([255, 255, 255]),
        ));

        let pixels = preprocess(&white);

        assert_eq!(pixels.len(), CHANNELS * INPUT_SIZE * INPUT_SIZE);
        // every plane is constant: (1.0 - mean) / std of its channel
        for channel in 0..CHANNELS {
            let expected = (1.0 - IMAGENET_MEAN[channel]) / IMAGENET_STD[channel];
            let plane_start = channel * INPUT_SIZE * INPUT_SIZE;
            assert!((pixels[plane_start] - expected).abs() < 1e-5);
            assert!((pixels[plane_start + INPUT_SIZE * INPUT_SIZE - 1] - expected).abs() < 1e-5);
        }
    }

    #[test]
    fn l2_normalized_returns_unit_vector() {
        let normalized = l2_normalized(&[3.0, 4.0]);

        assert!((normalized[0] - 0.6).abs() < 1e-6);
        assert!((normalized[1] - 0.8).abs() < 1e-6);
    }

    #[test]
    fn l2_normalized_survives_zero_vector() {
        let normalized = l2_normalized(&[0.0, 0.0]);

        assert!(normalized.iter().all(|v| v.is_finite()));
    }

    #[test]
    fn cosine_similarity_of_identical_unit_vectors_is_one() {
        let vector = l2_normalized(&[1.0, 2.0, 3.0]);

        assert!((cosine_similarity(&vector, &vector) - 1.0).abs() < 1e-6);
    }

    #[test]
    fn cosine_similarity_of_orthogonal_vectors_is_zero() {
        assert_eq!(cosine_similarity(&[1.0, 0.0], &[0.0, 1.0]), 0.0);
    }
}
