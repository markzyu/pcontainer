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
