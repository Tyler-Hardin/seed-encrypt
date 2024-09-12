use anyhow::{Context, Result};

#[cfg(feature="pledge")]
pub fn pledge() -> Result<()> {
    use libseccomp::*;

    // Initialize seccomp filter
    let mut ctx = ScmpFilterContext::new_filter(ScmpAction::KillProcess)
        .context("failed to create seccomp context")?;

    // Allow basic syscalls needed for process control
    let allowed_syscalls = [
        "brk", "read", "write", "exit", "exit_group",

        // Needed by dialoguer
        "ioctl", "poll", "munmap", "sigaltstack", "clock_nanosleep",
    ];
    for syscall in allowed_syscalls.iter() {
        let syscall = ScmpSyscall::from_name(syscall)
            .context("failed to get syscall number")?;
        ctx.add_rule(ScmpAction::Allow, syscall)
            .context("failed to add seccomp rule")?;
    }

    // Load the seccomp filter
    ctx.load().context("failed to load seccomp context")?;

    Ok(())
}
