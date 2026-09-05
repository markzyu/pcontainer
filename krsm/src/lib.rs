// SPDX-License-Identifier: MIT OR GPL-3.0-or-later
#![no_std]
#![doc = include_str!("../README.md")]

mod futures;

pub use crate::futures::{AsyncRuntime, AsyncRuntimeError, AsyncYielder};
