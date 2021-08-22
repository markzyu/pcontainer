// Provide a business-level event-handler for tracee events like on_clone_complete
//
// All mods are stateless. States are stored by TraceeHandlerStates, so
// that tracee threads don't need to loop over all mods for every syscall.
// (Their internal state already knows what to do)
//
// Later, we could even allow dynamically loading mods, and exposing mod
// configuraitons through procfs.
mod chroot;
mod perms;
mod rootfs;
mod simple_root;
mod strace;

pub use crate::chroot::ChrootMod;
pub use crate::perms::PermsMod;
pub use crate::rootfs::RootfsMod;
pub use crate::simple_root::SimpleRootMod;
pub use crate::strace::StraceMod;
