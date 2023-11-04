#[derive(thiserror::Error, Debug)]
pub enum Error {
    #[error("{0}")]
    Unknown(String),

    #[error("Config error: {0}")]
    ConfigError(String),

    #[error("Unsupported key pem label: {0}")]
    UnsupportedKeyError(String),

    #[error("Unsupported EcPrivateKey curve parameter")]
    UnknownKeyCurveError,

    #[error("No certificate found for given private key")]
    IdentityCertificateNotFoundError,

    #[error("Unsupported certificate error; other reason: {0}")]
    UnsupportedCertificateError(String),

    #[error("Unauthorized ({0})")]
    Unauthorized(&'static str),

    #[error("Bad Request ({0})")]
    BadRequest(String),

    #[error(transparent)]
    StdIoError(#[from] std::io::Error),

    #[error(transparent)]
    PemError(#[from] pem_rfc7468::Error),

    #[error(transparent)]
    DerError(#[from] x509_cert::der::Error),

    #[error(transparent)]
    RsaError(#[from] rsa::errors::Error),

    #[error(transparent)]
    RsaPkcs8Error(#[from] rsa::pkcs8::Error),

    #[error(transparent)]
    SpkiError(#[from] pkcs8::spki::Error),

    #[error(transparent)]
    Pkcs1Error(#[from] pkcs1::Error),

    #[error(transparent)]
    EcError(#[from] elliptic_curve::Error),

    #[error(transparent)]
    Sec1Error(#[from] sec1::Error),

    #[error(transparent)]
    EcdsaError(#[from] ecdsa::Error),

    #[error(transparent)]
    InvaildHeaderError(#[from] reqwest::header::InvalidHeaderName),

    #[error(transparent)]
    JsonError(#[from] serde_json::Error),

    #[error(transparent)]
    ReqwestError(#[from] reqwest::Error),

    #[error("API Error ({0}): {1}")]
    ApiError(reqwest::StatusCode, String),
}

impl Error {
    pub fn error_status(&self) -> axum::http::StatusCode {
        use axum::http::StatusCode;
        match *self {
            Self::Unauthorized(_) => StatusCode::UNAUTHORIZED,
            Self::BadRequest(_) => StatusCode::BAD_REQUEST,
            _ => StatusCode::INTERNAL_SERVER_ERROR,
        }
    }

    pub fn error_string_for_user(&self) -> &str {
        match *self {
            Self::Unauthorized(_) => "unauthorized",
            Self::BadRequest(_) => "bad-request",
            _ => "internal-error",
        }
    }
}

impl axum::response::IntoResponse for Error {
    fn into_response(self) -> axum::response::Response {
        if self.error_status().is_client_error() {
            tracing::warn!(message = "returning error to client", error = ?&self);
        } else {
            tracing::error!(message = "returning error to client", error = ?&self);
        }
        (
            self.error_status(),
            self.error_string_for_user().to_string(),
        )
            .into_response()
    }
}
