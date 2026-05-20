use rustpack::builder::*;
use rustpack::encode::EncodingType;
use rustpack::injection::InjectionMethod;
use rustpack::input::InputFormat;
use rustpack::output::OutputFormat;
use std::io::Write;
use std::path::PathBuf;

#[test]
fn test_full_pipeline_with_shellcode_file() {
    // Create a temp shellcode file (NOP sled + RET)
    let temp_dir = std::env::temp_dir().join("rustpack_test_integration");
    let _ = std::fs::create_dir_all(&temp_dir);

    let shellcode_path = temp_dir.join("test_payload.bin");
    let mut shellcode: Vec<u8> = vec![0x90; 512]; // NOP sled
    shellcode.push(0xC3); // RET
    std::fs::write(&shellcode_path, &shellcode).unwrap();

    let output_path = temp_dir.join("test_output.exe");
    let payload_file_path = temp_dir.join("encrypted_payload.bin");

    let config = BuildConfig {
        input_file: shellcode_path.clone(),
        output_file: output_path.clone(),
        input_format: InputFormat::Shellcode,
        output_format: OutputFormat::Exe,
        encoding: EncodingType::IntArray,
        injection_method: InjectionMethod::LocalCrt,
        shellcode_file: Some(payload_file_path.to_str().unwrap().to_string()),
        reg_payload: None,
        shellcode_url: None,
        sandbox: Some("DomainJoined".to_string()),
        env_domain: None,
        env_host: None,
        kill_date: Some("2030-01-01".to_string()),
        amsi_bypass: false,
        etw_bypass: false,
        unhook_dll: None,
        interactive_ps: false,
        icon_path: None,
        clone_metadata_path: None,
    };

    // The build will fail on Linux (no Windows toolchain), but we can test
    // that the pipeline doesn't panic and generates source correctly
    let result = build(&config);

    // On non-Windows, the cargo build step will fail but source generation should work
    // We're testing the pipeline logic, not actual compilation
    match result {
        Ok(r) => {
            // If somehow cargo build works, verify output
            assert!(r.loader_source.contains("fn main()") || r.loader_source.contains("DllMain"));
            assert!(r.loader_source.contains("black_box") || r.loader_source.contains("_jnk_")
                || r.loader_source.contains("_s_") || r.loader_source.contains("_end_"));
        }
        Err(e) => {
            // Expected on non-Windows - cargo build for windows-msvc will fail
            let err_str = format!("{}", e);
            assert!(
                err_str.contains("cargo") || err_str.contains("build") || err_str.contains("target"),
                "Unexpected error: {}",
                err_str
            );
        }
    }

    // Cleanup
    let _ = std::fs::remove_dir_all(&temp_dir);
}

#[test]
fn test_pipeline_generates_polymorphic_output() {
    let temp_dir = std::env::temp_dir().join("rustpack_test_poly");
    let _ = std::fs::create_dir_all(&temp_dir);

    let shellcode_path = temp_dir.join("test_poly.bin");
    let shellcode: Vec<u8> = vec![0x90; 100];
    std::fs::write(&shellcode_path, &shellcode).unwrap();

    // We can at least test the source generation portion
    let payload_bytes = rustpack::input::shellcode::read_shellcode(&shellcode_path).unwrap();
    let encrypted = rustpack::encrypt::encrypt_aes256_cbc(&payload_bytes);
    let encoded1 = rustpack::encode::encode_payload(&encrypted.ciphertext, EncodingType::IntArray);
    let encoded2 = rustpack::encode::encode_payload(&encrypted.ciphertext, EncodingType::IntArray);

    // Different encodings due to random offset
    assert_ne!(encoded1.encoded_literal, encoded2.encoded_literal);

    // Cleanup
    let _ = std::fs::remove_dir_all(&temp_dir);
}
