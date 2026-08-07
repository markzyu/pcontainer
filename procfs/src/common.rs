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

use thiserror::Error;

#[derive(Debug, Error)]
pub enum ProcfsError {
    #[error("/proc/config.gz is not a valid gzip: {0}")]
    InvalidGzip(std::io::Error),

    #[error("/proc/config.gz doesn't exist: {0}")]
    NoGzip(std::io::Error),

    #[error("I/O Error: {0}")]
    IO(std::io::Error),
}
