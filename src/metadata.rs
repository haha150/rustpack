use std::collections::HashMap;
use std::path::Path;

pub fn clone_metadata(source_exe: &Path) -> anyhow::Result<HashMap<String, String>> {
    let pe_bytes = std::fs::read(source_exe)
        .map_err(|e| anyhow::anyhow!("Failed to read source PE '{}': {}", source_exe.display(), e))?;

    let mut metadata = HashMap::new();

    // Parse PE to find VS_VERSION_INFO resource
    // This is a simplified parser - in production, use a full PE resource parser
    if let Some(version_info) = find_version_info(&pe_bytes) {
        metadata.extend(version_info);
    } else {
        // Default metadata if parsing fails
        metadata.insert("FileDescription".to_string(), "Windows System Service".to_string());
        metadata.insert("CompanyName".to_string(), "Microsoft Corporation".to_string());
        metadata.insert("ProductName".to_string(), "Microsoft Windows Operating System".to_string());
        metadata.insert("ProductVersion".to_string(), "10.0.19041.1".to_string());
        metadata.insert("FileVersion".to_string(), "10.0.19041.1".to_string());
        metadata.insert("LegalCopyright".to_string(), "© Microsoft Corporation. All rights reserved.".to_string());
    }

    Ok(metadata)
}

pub fn generate_rc_file(metadata: &HashMap<String, String>, icon_path: Option<&Path>) -> String {
    let file_desc = metadata.get("FileDescription").cloned().unwrap_or_default();
    let company = metadata.get("CompanyName").cloned().unwrap_or_default();
    let product = metadata.get("ProductName").cloned().unwrap_or_default();
    let product_ver = metadata.get("ProductVersion").cloned().unwrap_or_default();
    let file_ver = metadata.get("FileVersion").cloned().unwrap_or_default();
    let copyright = metadata.get("LegalCopyright").cloned().unwrap_or_default();

    let icon_section = if let Some(icon) = icon_path {
        format!("1 ICON \"{}\"\n\n", icon.display())
    } else {
        String::new()
    };

    format!(
        r#"{icon_section}1 VERSIONINFO
FILEVERSION 1,0,0,0
PRODUCTVERSION 1,0,0,0
FILEFLAGSMASK 0x3fL
FILEFLAGS 0x0L
FILEOS 0x40004L
FILETYPE 0x1L
FILESUBTYPE 0x0L
BEGIN
    BLOCK "StringFileInfo"
    BEGIN
        BLOCK "040904b0"
        BEGIN
            VALUE "CompanyName", "{company}\0"
            VALUE "FileDescription", "{file_desc}\0"
            VALUE "FileVersion", "{file_ver}\0"
            VALUE "LegalCopyright", "{copyright}\0"
            VALUE "ProductName", "{product}\0"
            VALUE "ProductVersion", "{product_ver}\0"
        END
    END
    BLOCK "VarFileInfo"
    BEGIN
        VALUE "Translation", 0x0409, 1200
    END
END
"#,
        icon_section = icon_section,
        company = company,
        file_desc = file_desc,
        file_ver = file_ver,
        copyright = copyright,
        product = product,
        product_ver = product_ver
    )
}

fn find_version_info(pe_bytes: &[u8]) -> Option<HashMap<String, String>> {
    // Search for VS_VERSION_INFO signature in the PE
    // The string "VS_VERSION_INFO" in UTF-16LE is a marker
    let marker: Vec<u8> = "VS_VERSION_INFO"
        .encode_utf16()
        .flat_map(|c| c.to_le_bytes())
        .collect();

    let pos = pe_bytes
        .windows(marker.len())
        .position(|w| w == marker.as_slice())?;

    // Try to extract StringFileInfo values
    let mut metadata = HashMap::new();
    let search_area = &pe_bytes[pos..pe_bytes.len().min(pos + 4096)];

    // Look for known keys in UTF-16LE
    for key in &[
        "FileDescription",
        "CompanyName",
        "ProductName",
        "ProductVersion",
        "FileVersion",
        "LegalCopyright",
    ] {
        let key_bytes: Vec<u8> = key.encode_utf16().flat_map(|c| c.to_le_bytes()).collect();
        if let Some(key_pos) = search_area
            .windows(key_bytes.len())
            .position(|w| w == key_bytes.as_slice())
        {
            // Value follows the key + null + padding
            let value_start = key_pos + key_bytes.len() + 2; // skip null terminator
            // Align to 4-byte boundary
            let aligned_start = (value_start + 3) & !3;
            if aligned_start < search_area.len() {
                let value_area = &search_area[aligned_start..];
                let value = read_utf16_string(value_area);
                if !value.is_empty() {
                    metadata.insert(key.to_string(), value);
                }
            }
        }
    }

    if metadata.is_empty() {
        None
    } else {
        Some(metadata)
    }
}

fn read_utf16_string(data: &[u8]) -> String {
    let mut chars: Vec<u16> = Vec::new();
    for chunk in data.chunks_exact(2) {
        let c = u16::from_le_bytes([chunk[0], chunk[1]]);
        if c == 0 {
            break;
        }
        chars.push(c);
    }
    String::from_utf16_lossy(&chars)
}
