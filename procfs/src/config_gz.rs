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

use crate::common::ProcfsError;
use flate2::bufread::GzDecoder;
use std::io;
use std::io::BufRead;

#[derive(Debug)]
pub struct ConfigGzLine {
    content: Vec<u8>,
}

#[derive(Debug, Default)]
pub struct ConfigGz {
    pub lines: Vec<ConfigGzLine>,
    #[allow(dead_code)]
    override_lines: Vec<ConfigGzLine>,
}

const WHITESPACES: &[u8] = b" \t\n\r";

fn _strip_slice(input: &[u8]) -> &[u8] {
    if let Some(left) = input.iter().position(|x| !WHITESPACES.contains(x)) {
        let right = input
            .iter()
            .rposition(|x| !WHITESPACES.contains(x))
            .unwrap();
        return &input[left..right + 1];
    }
    &input[0..0]
}

impl ConfigGzLine {
    fn preproc(&self) -> Option<(&[u8], usize)> {
        let mut content = self.content.as_slice();
        if let Some(ignore_idx) = content.iter().position(|x| x == &b'#') {
            content = &(content[..ignore_idx]);
        }
        let eq_idx = content.iter().position(|x| x == &b'=')?;
        Some((content, eq_idx))
    }

    pub fn maybe_value(&self) -> Option<(&[u8], usize)> {
        let (content, idx) = self.preproc()?;
        Some((_strip_slice(content.get(idx + 1..).unwrap_or(b"")), idx))
    }

    pub fn maybe_name(&self) -> Option<(&[u8], usize)> {
        let (content, idx) = self.preproc()?;
        Some((_strip_slice(content.get(..idx).unwrap_or(b"")), idx))
    }
}

impl ConfigGz {
    pub fn init_from_host_os(&mut self) -> Result<(), ProcfsError> {
        let f = io::BufReader::new(
            std::fs::File::open("/proc/config.gz").map_err(ProcfsError::NoGzip)?,
        );
        let mut gunzip = io::BufReader::new(GzDecoder::new(f));

        let mut line_buf = vec![];
        self.lines.clear();
        loop {
            line_buf.clear();
            let nbytes_read = gunzip
                .read_until(b'\n', &mut line_buf)
                .map_err(ProcfsError::InvalidGzip)?;
            if nbytes_read == 0 {
                break;
            }

            self.lines.push(ConfigGzLine {
                content: line_buf.clone(),
            });
        }
        Ok(())
    }

    pub fn lines(&self) -> &[ConfigGzLine] {
        self.lines.as_slice()
    }
}

#[cfg(test)]
mod tests {
    use crate::config_gz;

    #[test]
    fn config_gz_line_maybe_value() {
        let test_cases: Vec<(config_gz::ConfigGzLine, Option<(&[u8], usize)>)> = vec![
            (
                config_gz::ConfigGzLine {
                    content: b"".to_vec(),
                },
                None,
            ),
            (
                config_gz::ConfigGzLine {
                    content: b"#comment a=123".to_vec(),
                },
                None,
            ),
            (
                config_gz::ConfigGzLine {
                    content: b"INVALID_VAR".to_vec(),
                },
                None,
            ),
            (
                config_gz::ConfigGzLine {
                    content: b"CONFIG_ABC_DEF=ab".to_vec(),
                },
                Some((b"ab", 14)),
            ),
            (
                config_gz::ConfigGzLine {
                    content: b"CONFIG_ABC_DEFG=cd \t ".to_vec(),
                },
                Some((b"cd", 15)),
            ),
            (
                config_gz::ConfigGzLine {
                    content: b"CONFIG_ABC_DEF=xy \t # def".to_vec(),
                },
                Some((b"xy", 14)),
            ),
            (
                config_gz::ConfigGzLine {
                    content: b"CONFIG_ABC_DEF= xy \t # def".to_vec(),
                },
                Some((b"xy", 14)),
            ),
        ];
        for (line, expect) in test_cases {
            assert_eq!(line.maybe_value(), expect);
        }
    }

    #[test]
    fn config_gz_line_maybe_name() {
        let test_cases: Vec<(config_gz::ConfigGzLine, Option<(&[u8], usize)>)> = vec![
            (
                config_gz::ConfigGzLine {
                    content: b"".to_vec(),
                },
                None,
            ),
            (
                config_gz::ConfigGzLine {
                    content: b"#comment a=123".to_vec(),
                },
                None,
            ),
            (
                config_gz::ConfigGzLine {
                    content: b"INVALID_VAR".to_vec(),
                },
                None,
            ),
            (
                config_gz::ConfigGzLine {
                    content: b"CONFIG_ABC_DEF=ab".to_vec(),
                },
                Some((b"CONFIG_ABC_DEF", 14)),
            ),
            (
                config_gz::ConfigGzLine {
                    content: b"CONFIG_ABC_DEFG=cd \t ".to_vec(),
                },
                Some((b"CONFIG_ABC_DEFG", 15)),
            ),
            (
                config_gz::ConfigGzLine {
                    content: b" CONFIG_ABC_DEF=xy \t # def".to_vec(),
                },
                Some((b"CONFIG_ABC_DEF", 15)),
            ),
            (
                config_gz::ConfigGzLine {
                    content: b"CONFIG_ABC_DEF = xy \t # def".to_vec(),
                },
                Some((b"CONFIG_ABC_DEF", 15)),
            ),
        ];
        for (line, expect) in test_cases {
            assert_eq!(line.maybe_name(), expect);
        }
    }
}
