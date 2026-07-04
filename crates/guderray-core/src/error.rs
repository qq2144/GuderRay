use thiserror::Error;

#[derive(Error, Debug)]
pub enum CoreError {
    #[error("io error: {0}")]
    Io(#[from] std::io::Error),

    #[error("json error: {0}")]
    Json(#[from] serde_json::Error),

    #[error("invalid share link: {0}")]
    InvalidLink(String),

    #[error("unsupported protocol: {0}")]
    UnsupportedProtocol(String),

    #[error("profile not found: {0}")]
    ProfileNotFound(u32),

    #[error("config error: {0}")]
    Config(String),

    #[error("{0}")]
    Other(String),
}

pub type Result<T> = std::result::Result<T, CoreError>;
