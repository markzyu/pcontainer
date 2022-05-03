use std::error;
use std::io;
use std::io::BufRead;
use flate2::bufread::GzDecoder;

#[derive(Debug)]
pub struct ConfigGzLine {
  content: Vec<u8>
}

#[derive(Debug)]
pub struct ConfigGz {
  pub lines: Vec<ConfigGzLine>
}

impl ConfigGzLine {
  fn preproc(&self) -> Option<(&[u8], usize)> {
    let mut content = self.content.as_slice();
    if let Some(ignore_idx) = content.iter().position(|x| x == &b'#') {
      content = &(content[..ignore_idx]);
    }
    let eq_idx = content.iter().position(|x| x == &b'=')?;
    return Some((content, eq_idx));
  }

  pub fn maybeValue(&self) -> Option<(&[u8], usize)> {
    let (content, idx) = self.preproc()?;
    return Some((
      content.get(idx+1..).unwrap_or(b""),
      idx
    ));
  }

  pub fn maybeName(&self) -> Option<(&[u8], usize)> {
    let (content, idx) = self.preproc()?;
    return Some((
      content.get(..idx).unwrap_or(b""),
      idx
    ));
  }
}

impl ConfigGz {
  pub fn init_from_host_os(&mut self) -> Result<(), Box<dyn error::Error>> {
    let f = io::BufReader::new(std::fs::File::open("/proc/config.gz")?);
    let mut gunzip = io::BufReader::new(GzDecoder::new(f));

    let mut line_buf = vec![];
    self.lines.clear();
    loop {
      line_buf.clear();
      let nbytes_read = gunzip.read_until(b'\n', &mut line_buf)?;
      if nbytes_read == 0 {
        break;
      }

      self.lines.push(ConfigGzLine {content: line_buf.clone()});
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
        let testCases: Vec<(config_gz::ConfigGzLine, Option<(&[u8], usize)>)> = vec![
          (config_gz::ConfigGzLine{content: b"".to_vec()}, None),
          (config_gz::ConfigGzLine{content: b"#comment a=123".to_vec()}, None),
          (config_gz::ConfigGzLine{content: b"INVALID_VAR".to_vec()}, None),
          (config_gz::ConfigGzLine{content: b"CONFIG_ABC_DEF=ab".to_vec()}, Some((b"ab", 14))),
          (config_gz::ConfigGzLine{content: b"CONFIG_ABC_DEFG=cd \t ".to_vec()}, Some((b"cd", 15))),
          (config_gz::ConfigGzLine{content: b"CONFIG_ABC_DEF=xy \t # def".to_vec()}, Some((b"xy", 14))),
          (config_gz::ConfigGzLine{content: b"CONFIG_ABC_DEF= xy \t # def".to_vec()}, Some((b"xy", 14))),
        ];
        for (line, expect) in testCases {
          assert_eq!(line.maybeValue(), expect);
        }
    }

    #[test]
    fn config_gz_line_maybe_name() {
        let testCases: Vec<(config_gz::ConfigGzLine, Option<(&[u8], usize)>)> = vec![
          (config_gz::ConfigGzLine{content: b"".to_vec()}, None),
          (config_gz::ConfigGzLine{content: b"#comment a=123".to_vec()}, None),
          (config_gz::ConfigGzLine{content: b"INVALID_VAR".to_vec()}, None),
          (config_gz::ConfigGzLine{content: b"CONFIG_ABC_DEF=ab".to_vec()}, Some((b"CONFIG_ABC_DEF", 14))),
          (config_gz::ConfigGzLine{content: b"CONFIG_ABC_DEFG=cd \t ".to_vec()}, Some((b"CONFIG_ABC_DEFG", 15))),
          (config_gz::ConfigGzLine{content: b" CONFIG_ABC_DEF=xy \t # def".to_vec()}, Some((b"CONFIG_ABC_DEF", 15))),
          (config_gz::ConfigGzLine{content: b"CONFIG_ABC_DEF = xy \t # def".to_vec()}, Some((b"CONFIG_ABC_DEF", 15))),
        ];
        for (line, expect) in testCases {
          assert_eq!(line.maybeName(), expect);
        }
    }
}
