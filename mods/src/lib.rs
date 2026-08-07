// Copyright 2026 Zhongzhi Yu <7296488+markzyu@users.noreply.github.com>
//
// This program is free software: you can redistribute it and/or modify
// it under the terms of the GNU Lesser General Public License as published by
// the Free Software Foundation, either version 3 of the License, or
// (at your option) any later version.
//
// This program is distributed in the hope that it will be useful,
// but WITHOUT ANY WARRANTY; without even the implied warranty of
// MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
// GNU Lesser General Public License for more details.

// Provide a business-level event-handler for tracee events like on_clone_complete
//
// All mods are stateless. States are stored by TraceeHandlerStates, so
// that tracee threads don't need to loop over all mods for every syscall.
// (Their internal state already knows what to do)
//
// Later, we could even allow dynamically loading mods, and exposing mod
// configuraitons through procfs.
mod perms;
mod strace;

pub use crate::perms::PermsMod;
pub use crate::strace::StraceMod;
