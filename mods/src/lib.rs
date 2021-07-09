// Provide a business-level getter/setter for Augment* structs.
//
// Mods are used from tracee-thread to initialize/configure Augment*
//
// All mods are stateless. States are stored by Augment* structs, so
// that tracee threads don't need to loop over all mods for every syscall.
// (Their internal state already knows what to do)
//
// Later, we could even allow dynamically loading mods, and exposing mod
// configuraitons through procfs.
mod chroot;
mod strace;
mod trace_child;

pub use crate::chroot::ChrootMod;
pub use crate::strace::StraceMod;
pub use crate::trace_child::TraceChildMod;

#[cfg(test)]
mod tests {
    #[test]
    fn it_works() {
        assert_eq!(2 + 2, 4);
    }
}
