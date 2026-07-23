use std::path::{Path, PathBuf};

use crate::config::CONFIG;
use crate::dino::{Embedder, cosine_similarity};
use crate::dino_dataset::{self, DinoEntry};
use crate::{Error, images, img_config};

const IMAGE_EXTENSIONS: [&str; 4] = ["jpg", "jpeg", "png", "webp"];

/// `anti-scam dino-export <images_dir> [out_file]` — embed every image under a
/// folder (recursively) into the shadow-mode reference dataset
pub fn run_export(args: &[String]) {
    let (dir, out) = match args {
        [dir] => (dir.as_str(), "dino.json"),
        [dir, out] => (dir.as_str(), out.as_str()),
        _ => {
            eprintln!("usage: anti-scam dino-export <images_dir> [out_file]");
            std::process::exit(2);
        }
    };

    if let Err(e) = export(dir, out) {
        eprintln!("dino-export failed: {e}");
        std::process::exit(1);
    }
}

/// `anti-scam dino-classify <images_dir> [dataset_file]` — score every image
/// under a folder against the reference dataset; TSV to stdout for
/// calibration, summary to stderr
pub fn run_classify(args: &[String]) {
    let (dir, dataset_path) = match args {
        [dir] => (dir.as_str(), CONFIG.dino.dataset_path.as_str()),
        [dir, dataset] => (dir.as_str(), dataset.as_str()),
        _ => {
            eprintln!("usage: anti-scam dino-classify <images_dir> [dataset_file]");
            std::process::exit(2);
        }
    };

    if let Err(e) = classify(dir, dataset_path) {
        eprintln!("dino-classify failed: {e}");
        std::process::exit(1);
    }
}

fn export(dir: &str, out: &str) -> Result<(), Error> {
    let embedder = load_embedder()?;
    let images = collect_images(dir)?;

    let entries: Vec<DinoEntry> = images
        .iter()
        .map(|image| {
            eprintln!("embedding {}...", image.path.display());
            let bytes = std::fs::read(&image.path)?;
            let embedding = embedder
                .embed(&bytes)
                .map_err(|e| format!("{}: {e}", image.path.display()))?;
            Ok(DinoEntry { name: image.name.clone(), embedding })
        })
        .collect::<Result<_, Error>>()?;

    let json = dino_dataset::to_json(&entries)?;
    std::fs::write(out, &json)?;

    println!(
        "wrote {out}: {} entr(ies), embedding pipeline v{}",
        entries.len(),
        dino_dataset::PIPELINE_VERSION
    );
    println!("sha256: {}", img_config::hex_encode(&images::sha256_hash(json.as_bytes())));

    Ok(())
}

fn classify(dir: &str, dataset_path: &str) -> Result<(), Error> {
    let refs = dino_dataset::load(dataset_path)
        .map_err(|e| format!("cannot load dino dataset {dataset_path}: {e}"))?;
    if refs.is_empty() {
        return Err(format!("dino dataset {dataset_path} has no entries").into());
    }

    let embedder = load_embedder()?;
    let images = collect_images(dir)?;

    println!("file\tbest\tbest_sim\tsecond\tsecond_sim");

    let best_similarities: Vec<f32> = images
        .iter()
        .map(|image| {
            let bytes = std::fs::read(&image.path)?;
            let embedding = embedder
                .embed(&bytes)
                .map_err(|e| format!("{}: {e}", image.path.display()))?;

            let ranked = ranked_matches(&embedding, &refs);
            let (best_name, best_sim) = &ranked[0];
            let (second_name, second_sim) = ranked
                .get(1)
                .map(|(name, sim)| (name.as_str(), *sim))
                .unwrap_or(("-", f32::NAN));

            println!(
                "{}\t{best_name}\t{best_sim:.4}\t{second_name}\t{second_sim:.4}",
                image.path.display()
            );
            Ok(*best_sim)
        })
        .collect::<Result<_, Error>>()?;

    print_summary(&best_similarities);
    Ok(())
}

/// refs sorted by similarity, best first; refs are validated non-empty
fn ranked_matches(embedding: &[f32], refs: &[DinoEntry]) -> Vec<(String, f32)> {
    let mut ranked: Vec<(String, f32)> = refs
        .iter()
        .map(|entry| (entry.name.clone(), cosine_similarity(embedding, &entry.embedding)))
        .collect();
    ranked.sort_by(|(_, a), (_, b)| b.total_cmp(a));
    ranked
}

fn print_summary(similarities: &[f32]) {
    let count = similarities.len();
    if count == 0 {
        eprintln!("no images found");
        return;
    }

    let min = similarities.iter().copied().fold(f32::INFINITY, f32::min);
    let max = similarities.iter().copied().fold(f32::NEG_INFINITY, f32::max);
    let mean = similarities.iter().sum::<f32>() / count as f32;
    eprintln!("{count} image(s): best-sim min {min:.4} / mean {mean:.4} / max {max:.4}");
}

fn load_embedder() -> Result<Embedder, Error> {
    let path = &CONFIG.dino.model_path;
    Embedder::load(path).map_err(|e| {
        format!("cannot load dino model {path} (set dino.model_path in config.toml): {e}").into()
    })
}

struct SourceImage {
    path: PathBuf,
    name: String,
}

/// recursive scan: entry names come from the path relative to the root, so
/// `mr_beast/1.jpg` becomes `mr_beast_1`; deterministic order, duplicate
/// names are an error
fn collect_images(dir: &str) -> Result<Vec<SourceImage>, Error> {
    let root = Path::new(dir);
    let mut paths = collect_image_paths(root)?;
    paths.sort();

    if paths.is_empty() {
        return Err(format!("no images found in {dir} (looked for {IMAGE_EXTENSIONS:?})").into());
    }

    let images: Vec<SourceImage> = paths
        .into_iter()
        .map(|path| {
            let name = entry_name(root, &path)?;
            Ok(SourceImage { path, name })
        })
        .collect::<Result<_, Error>>()?;

    if let Some(duplicate) = first_duplicate_name(&images) {
        return Err(format!("duplicate entry name \"{duplicate}\" in {dir}").into());
    }
    Ok(images)
}

fn collect_image_paths(dir: &Path) -> Result<Vec<PathBuf>, Error> {
    let mut paths = Vec::new();
    for entry in std::fs::read_dir(dir)? {
        let path = entry?.path();
        if path.is_dir() {
            paths.extend(collect_image_paths(&path)?);
        } else if has_image_extension(&path) {
            paths.push(path);
        }
    }
    Ok(paths)
}

fn entry_name(root: &Path, path: &Path) -> Result<String, Error> {
    let relative = path
        .strip_prefix(root)
        .unwrap_or(path)
        .with_extension("");
    let name: String = relative
        .to_str()
        .ok_or_else(|| format!("non-UTF8 file name: {}", path.display()))?
        .replace(['/', '\\'], "_");
    Ok(name)
}

fn first_duplicate_name(images: &[SourceImage]) -> Option<&str> {
    let mut seen = std::collections::HashSet::new();
    images
        .iter()
        .find(|image| !seen.insert(image.name.as_str()))
        .map(|image| image.name.as_str())
}

fn has_image_extension(path: &Path) -> bool {
    path.extension()
        .and_then(|e| e.to_str())
        .is_some_and(|e| IMAGE_EXTENSIONS.contains(&e.to_lowercase().as_str()))
}
