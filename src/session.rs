//! rolesanywhere:CreateSession API client with sigv4 x509 signer (AWS4-X509-{RSA,ECDSA}-SHA256)

/// https://docs.aws.amazon.com/rolesanywhere/latest/userguide/authentication-create-session.html
#[derive(Debug, serde::Serialize)]
#[serde(rename_all = "camelCase")]
pub struct CreateSessionRequest {
    pub duration_seconds: Option<u32>,
    pub profile_arn: String,
    pub role_arn: String,
    pub session_name: Option<String>,
    pub trust_anchor_arn: String,
}
