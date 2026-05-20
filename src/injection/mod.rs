pub mod local_crt;
pub mod remote_crt;
pub mod apc;
pub mod fiber;
pub mod threadless;
pub mod pool_party;

pub enum InjectionMethod {
    LocalCrt,
    RemoteCrt { target: String, spawn: bool },
    Apc { target: String, spawn: bool },
    Fiber,
    Threadless { target: String },
    PoolParty { target: String },
    SyscallLocal,
    SyscallRemote { target: String },
    SyscallSpawn { target: String },
}

pub fn get_injection_snippet(method: &InjectionMethod) -> String {
    match method {
        InjectionMethod::LocalCrt => local_crt::local_crt_snippet(),
        InjectionMethod::RemoteCrt { target, spawn } => {
            remote_crt::remote_crt_snippet(target, *spawn)
        }
        InjectionMethod::Apc { target, spawn } => apc::apc_snippet(target, *spawn),
        InjectionMethod::Fiber => fiber::fiber_snippet(),
        InjectionMethod::Threadless { target } => threadless::threadless_snippet(target),
        InjectionMethod::PoolParty { target } => pool_party::pool_party_snippet(target),
        InjectionMethod::SyscallLocal => crate::syscalls::syscall_local_snippet(),
        InjectionMethod::SyscallRemote { target } => crate::syscalls::syscall_remote_snippet(target),
        InjectionMethod::SyscallSpawn { target } => crate::syscalls::syscall_spawn_snippet(target),
    }
}

/// Returns true if the injection method uses indirect syscalls
pub fn uses_syscalls(method: &InjectionMethod) -> bool {
    matches!(method, InjectionMethod::SyscallLocal | InjectionMethod::SyscallRemote { .. } | InjectionMethod::SyscallSpawn { .. })
}
