#[derive(clap::Args)]
pub struct ServeArgs {
    /// AWS region to use
    #[clap(long)]
    region: Option<String>,
}

#[tokio::main]
pub async fn run(config: &crate::config::Config, args: &ServeArgs) -> Result<(), anyhow::Error> {
    serve(config.clone(), args).await?;
    Ok(())
}

pub async fn serve(config: crate::config::Config, args: &ServeArgs) -> Result<(), anyhow::Error> {
    let client = crate::client::Client::new(args.region.as_ref().map(|v| v.as_ref()))?;

    let app = axum::Router::new()
        .route("/healthz", axum::routing::get(healthz))
        .route("/ecs/credentials", axum::routing::get(get_ecs_credentials))
        .layer(axum::extract::Extension(std::sync::Arc::new(config)))
        .layer(axum::extract::Extension(std::sync::Arc::new(client)));

    if let Some(l) = listenfd::ListenFd::from_env().take_tcp_listener(0)? {
        tracing::info!(message="Starting a server", listener=?l);
        axum::Server::from_tcp(l)?
    } else {
        tracing::warn!("Using 127.0.0.1:3000 to listen because sd_listen_fds parameters are missing (use systemd.socket to control listen configuration)");
        axum::Server::bind(&std::net::SocketAddr::from(([127, 0, 0, 1], 3000)))
    }
    .serve(app.into_make_service())
    .await?;
    Ok(())
}

async fn healthz() -> axum::response::Result<(axum::http::StatusCode, &'static str)> {
    Ok((axum::http::StatusCode::OK, "ok"))
}

#[derive(Debug, serde::Serialize)]
#[serde(rename_all = "PascalCase")]
pub struct GetEcsCredentialsResponse {
    access_key_id: String,
    secret_access_key: crate::client::AwsSecretAccessKey,
    token: Option<String>,
    expiration: Option<chrono::DateTime<chrono::Utc>>,
}

/// ECS Credentials Provider implementation
async fn get_ecs_credentials(
    ExtractBearer(bearer_source, bearer): ExtractBearer,
    axum::extract::Extension(config): axum::extract::Extension<
        std::sync::Arc<crate::config::Config>,
    >,
    axum::extract::Extension(client): axum::extract::Extension<
        std::sync::Arc<crate::client::Client>,
    >,
) -> Result<axum::Json<GetEcsCredentialsResponse>, crate::error::Error> {
    use tracing::Instrument;
    let span = tracing::info_span!("get_ecs_credentials");
    async move {
        let at = {
            use secrecy::ExposeSecret;
            match crate::auth::AccessToken::parse(bearer.expose_secret().as_ref()) {
                Ok(v) => v,
                Err(e) => {
                    tracing::warn!(message = "ECS Credentials Provider endpoint received a invalid token", rejected = true, error = ?e);
                    return Err(e);
                }
            }
        };

        let binding = match crate::binding::RoleBinding::load(&config, at.binding_name).await {
            Ok(v) => v,
            Err(crate::error::Error::ConfigError(e)) => {
                tracing::warn!(message = "ECS Credentials Provider endpoint received a invalid token (invalid binding)", rejected = true, binding_name=?at.binding_name, config_dir=?config.config_dir(), config_error = ?e);
                return Err(crate::error::Error::Unauthorized(UNAUTHORIZED_TOKEN_BINDING_NOT_FOUND));
            }

            Err(crate::error::Error::StdIoError(e))  if e.kind() == std::io::ErrorKind::NotFound => {
                tracing::warn!(message = "ECS Credentials Provider endpoint received a invalid token (binding not found)", rejected = true, binding_name=?at.binding_name, config_dir=?config.config_dir(), error = ?e);
                return Err(crate::error::Error::Unauthorized(UNAUTHORIZED_TOKEN_BINDING_NOT_FOUND));

            }
            Err(e) => {
                tracing::error!(message = "ECS Credentials Provider endpoint received a token and encountered error while trying to load a corresponding role binding data", binding_name=?at.binding_name, config_dir=?config.config_dir(), error = ?e);
                return Err(e);
            }
        };
        tracing::trace!(binding = ?binding);

        let expected_bearer_source = match binding.mode {
            crate::binding::EnvironmentMode::EcsFull(_) => BearerSource::Header,
            crate::binding::EnvironmentMode::EcsRelative(_) => BearerSource::Header,
            crate::binding::EnvironmentMode::EcsFullQuery(_) => BearerSource::Query,
            crate::binding::EnvironmentMode::EcsRelativeQuery(_) => BearerSource::Query,
            _ => BearerSource::Never,
        };

        tracing::trace!(bearer_source = ?bearer_source, expected_bearer_source = ?expected_bearer_source);
        if bearer_source != expected_bearer_source {
            tracing::warn!(message = "ECS Credentials Provider endpoint received a request with correct secret, but rejecting a request due to mismatch in --mode.", rejected = true, given_bearer_source = ?bearer_source, expected_bearer_source = ?expected_bearer_source, mode = ?binding.mode);
            return Err(crate::error::Error::Unauthorized(UNAUTHORIZED_TOKEN_AUD));
        }

        match at.verify(&binding.secret_hash) {
            Ok(_) => {}
            Err(e) => {
                tracing::warn!(message = "ECS Credentials Provider endpoint received a invalid secret (while binding name is correct)", binding_name = ?binding.name, mode = ?binding.mode);
                return Err(e);
            }
        }

        tracing::debug!(message = "Requesting credentials", binding_name = %binding.name, mode = ?binding.mode);

        let session = match binding.create_session(&client).await {
            Ok(v) => v,
            Err(e) => {
                tracing::error!(message = "Failed to request credentials", binding_name = ?binding.name, mode = ?binding.mode, request = ?binding.request, error = ?e);
                return Err(e);
            }
        };

        let assumed_role = session.credential_set.get(0).ok_or_else(|| {
            crate::error::Error::Unknown("returned CredentialSet is missing item".to_string())
        })?;

        let res = GetEcsCredentialsResponse {
            access_key_id: assumed_role.credentials.access_key_id.clone(),
            secret_access_key: assumed_role.credentials.secret_access_key.clone(),
            token: Some(assumed_role.credentials.session_token.clone()),
            expiration: Some(assumed_role.credentials.expiration),
        };
        tracing::info!(message = "Vending credentials to consumer", ok = true, binding_name = %binding.name, mode = ?binding.mode, access_key_id = ?assumed_role.credentials.access_key_id, expiration = ?assumed_role.credentials.expiration, assumed_role_user_arn= ?assumed_role.assumed_role_user.arn);

        Ok(axum::Json(res))
    }.instrument(span).await
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
enum BearerSource {
    Header,
    Query,
    #[allow(dead_code)]
    Never,
}
struct ExtractBearer(BearerSource, secrecy::SecretString);

const BEARER_PREFIX: &str = "bearer";
const ACCESS_TOKEN: &str = "access_token";

const UNAUTHORIZED_TOKEN_AUD: &str = "unexpected usage (correct token given but mode mismatch)";
const UNAUTHORIZED_TOKEN_NOT_GIVEN: &str = "bearer token not given";
const UNAUTHORIZED_TOKEN_BINDING_NOT_FOUND: &str = "corresponding role binding data not found";

#[async_trait::async_trait]
impl<B> axum::extract::FromRequest<B> for ExtractBearer
where
    B: Send,
{
    type Rejection = crate::error::Error;

    async fn from_request(
        req: &mut axum::extract::RequestParts<B>,
    ) -> Result<Self, Self::Rejection> {
        let _span = tracing::trace_span!("extract_bearer").entered();

        let header = if let Some(hvs) = req
            .headers()
            .get(http::header::AUTHORIZATION)
            .and_then(|hv| hv.to_str().ok())
        {
            tracing::trace!("Authorization header found");
            let prefix = hvs.split(' ').next().map(|s| s.to_ascii_lowercase());
            match prefix {
                Some(prefix) if prefix == BEARER_PREFIX => hvs.get(BEARER_PREFIX.len() + 1..),
                Some(_) => None,
                None => None,
            }
        } else {
            None
        };
        let query = if let Some(mut q) = req
            .uri()
            .query()
            .map(|v| url::form_urlencoded::parse(v.as_bytes()))
        {
            tracing::trace!("query string found");
            q.find(|(k, _)| k == ACCESS_TOKEN).map(|(_, v)| v)
        } else {
            None
        };
        match (header, query) {
            // https://www.rfc-editor.org/rfc/rfc6750#section-2
            (Some(_), Some(_)) => Err(crate::error::Error::BadRequest(
                "token given in both header and query".to_string(),
            )),
            (None, None) => Err(crate::error::Error::Unauthorized(
                UNAUTHORIZED_TOKEN_NOT_GIVEN,
            )),
            (Some(v), None) => {
                tracing::trace!("Extracted bearer token from Authorization header");
                Ok(Self(
                    BearerSource::Header,
                    secrecy::Secret::new(v.to_string()),
                ))
            }
            (None, Some(v)) => {
                tracing::trace!("Extracted bearer token from query string");
                Ok(Self(
                    BearerSource::Query,
                    secrecy::Secret::new(v.to_string()),
                ))
            }
        }
    }
}
