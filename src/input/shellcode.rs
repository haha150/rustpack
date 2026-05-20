use std::path::Path;

pub fn read_shellcode(path: &Path) -> anyhow::Result<Vec<u8>> {
    let data = std::fs::read(path)
        .map_err(|e| anyhow::anyhow!("Failed to read shellcode file '{}': {}", path.display(), e))?;
    if data.is_empty() {
        anyhow::bail!("Shellcode file is empty: {}", path.display());
    }
    Ok(data)
}
