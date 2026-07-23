use std::path::Path;

use crate::{img_config, images, Error};

const IMAGE_EXTENSIONS: [&str; 4] = ["jpg", "jpeg", "png", "webp"];

/// `anti-scam export <images_dir> [out_file]` — hash every image in a folder
/// into a distributable banned-config JSON and print its sha256 for the
/// checksum file
pub fn run(args: &[String]) {
    let (dir, out) = match args {
        [dir] => (dir.as_str(), "banned.json"),
        [dir, out] => (dir.as_str(), out.as_str()),
        _ => {
            eprintln!("usage: anti-scam export <images_dir> [out_file]");
            std::process::exit(2);
        }
    };

    if let Err(e) = export(dir, out) {
        eprintln!("export failed: {e}");
        std::process::exit(1);
    }
}

fn export(dir: &str, out: &str) -> Result<(), Error> {
    let entries = build_entries(dir)?;
    if entries.is_empty() {
        return Err(format!("no images found in {dir} (looked for {IMAGE_EXTENSIONS:?})").into());
    }

    let json = img_config::to_json(&entries)?;
    std::fs::write(out, &json)?;

    println!(
        "wrote {out}: {} entr(ies), pipeline v{}",
        entries.len(),
        img_config::PIPELINE_VERSION
    );
    println!("sha256: {}", img_config::hex_encode(&images::sha256_hash(json.as_bytes())));

    Ok(())
}

fn build_entries(dir: &str) -> Result<Vec<img_config::ImageData>, Error> {
    let mut paths: Vec<_> = std::fs::read_dir(dir)?
        .collect::<Result<Vec<_>, _>>()?
        .into_iter()
        .map(|entry| entry.path())
        .filter(|path| has_image_extension(path))
        .collect();
    // deterministic output: same folder -> same JSON -> same sha256
    paths.sort();

    paths
        .iter()
        .map(|path| {
            let name = path
                .file_stem()
                .and_then(|s| s.to_str())
                .ok_or_else(|| format!("non-UTF8 file name: {}", path.display()))?;
            let bytes = std::fs::read(path)?;

            println!("hashing {}...", path.display());
            img_config::image_data_from_bytes(name, &bytes)
                .map_err(|e| format!("{}: {e}", path.display()).into())
        })
        .collect()
}

fn has_image_extension(path: &Path) -> bool {
    path.extension()
        .and_then(|e| e.to_str())
        .is_some_and(|e| IMAGE_EXTENSIONS.contains(&e.to_lowercase().as_str()))
}
