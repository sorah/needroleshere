//! rolesanywhere:CreateSession API client

/// https://docs.aws.amazon.com/rolesanywhere/latest/userguide/authentication-create-session.html
#[derive(Debug, serde::Serialize)]
#[serde(rename_all = "camelCase")]
pub struct CreateSessionRequest {
    pub duration_seconds: Option<i64>,
    pub profile_arn: String,
    pub role_arn: String,
    pub session_name: Option<String>,
    pub trust_anchor_arn: String,
}

#[derive(Debug, serde::Serialize, serde::Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct CreateSessionResponse {
    pub credential_set: Vec<AssumeRoleResponse>,
    pub subject_arn: String,
}

#[derive(Debug, serde::Serialize, serde::Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct AssumeRoleResponse {
    pub assumed_role_user: AssumedRoleUser,
    pub credentials: Credentials,
    pub packed_policy_size: i64,
    pub source_identity: String,
}

#[derive(Debug, serde::Serialize, serde::Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct AssumedRoleUser {
    pub arn: String,
    pub assumed_role_id: String,
}

#[derive(Debug, serde::Serialize, serde::Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct Credentials {
    pub access_key_id: String,
    pub expiration: chrono::DateTime<chrono::Utc>,
    pub secret_access_key: String, // TODO: mark as sensitive value
    pub session_token: String,
}

pub struct Client {
    http_client: reqwest::Client,
    region: String,
}

const SERVICE_NAME: &str = "rolesanywhere";

fn default_region() -> Result<String, crate::error::Error> {
    if let Ok(r) = std::env::var("AWS_REGION") {
        return Ok(r);
    }
    if let Ok(r) = std::env::var("AWS_DEFAULT_REGION") {
        return Ok(r);
    }
    Err(crate::error::Error::ConfigError(
        "AWS region not specified; use --region or $AWS_REGION or $AWS_DEFAULT_REGION".to_string(),
    ))
}

impl Client {
    pub fn new(region: Option<&str>) -> Result<Self, crate::error::Error> {
        // because sigv4 requires to switch to `:authority` header when using http2
        let http_client = reqwest::ClientBuilder::new().http1_only().build().unwrap();

        Ok(Self {
            http_client,
            region: match region {
                Some(s) => s.to_owned(),
                None => default_region()?,
            },
        })
    }

    pub async fn create(
        &self,
        identity: &crate::identity::Identity,
        request: &CreateSessionRequest,
    ) -> Result<CreateSessionResponse, crate::error::Error> {
        let body = serde_json::to_vec(request)?;

        // Use http::Request for signer
        let mut req = http::Request::builder()
            .uri(format!(
                "https://rolesanywhere.{}.amazonaws.com/sessions",
                self.region
            ))
            .method(http::Method::POST)
            .header(http::header::CONTENT_TYPE, "application/json")
            .body(bytes::Bytes::from(body))
            .unwrap();

        let auth_headers = crate::sign::calculate_signing_headers(
            &crate::sign::SignableRequest::from(&req),
            &crate::sign::SigningParams {
                region: &self.region,
                service_name: SERVICE_NAME,
                time: chrono::Utc::now(),
                identity,
            },
        )?;

        for (k, v) in auth_headers.iter() {
            req.headers_mut().append(k, v.to_owned());
        }

        let resp = self
            .http_client
            .execute(reqwest::Request::try_from(req)?)
            .await?;

        let status = resp.status();
        if status.is_success() {
            Ok(resp.json::<CreateSessionResponse>().await?)
        } else {
            let body = resp.text().await?;
            Err(crate::error::Error::ApiError(status, body))
        }
    }
}
