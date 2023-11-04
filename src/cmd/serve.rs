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

pub fn make_router(
    arc_config: std::sync::Arc<crate::config::Config>,
    arc_client: std::sync::Arc<crate::client::Client>,
) -> axum::Router {
    axum::Router::new()
        .route("/healthz", axum::routing::get(healthz))
        .route("/ecs/credentials", axum::routing::get(get_ecs_credentials))
        .layer(axum::extract::Extension(arc_config))
        .layer(axum::extract::Extension(arc_client))
}

pub async fn serve(config: crate::config::Config, args: &ServeArgs) -> Result<(), anyhow::Error> {
    let client = crate::client::Client::new(args.region.as_ref().map(|v| v.as_ref()))?;

    let arc_config = std::sync::Arc::new(config);
    let arc_client = std::sync::Arc::new(client);

    let mut fds = listenfd::ListenFd::from_env();

    let servers = if fds.len() == 0 {
        tracing::warn!("Using 127.0.0.1:3000 to listen because sd_listen_fds parameters are missing (use systemd.socket to control listen configuration)");
        vec![axum::Server::bind(&std::net::SocketAddr::from((
            [127, 0, 0, 1],
            3000,
        )))]
    } else {
        let mut ls = Vec::new();
        for idx in 0..fds.len() {
            let l = fds.take_tcp_listener(idx)?.unwrap();
            tracing::info!(message="Starting a server", idx=?idx, listener=?l);
            ls.push(axum::Server::from_tcp(l)?);
        }
        ls
    };

    let services: Vec<_> = servers
        .into_iter()
        .map(|v| {
            tokio::spawn(
                v.serve(make_router(arc_config.clone(), arc_client.clone()).into_make_service()),
            )
        })
        .collect();

    for service in services {
        service.await.unwrap().unwrap();
    }

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
    ExtractBearer {
        source: bearer_source,
        value: bearer,
    }: ExtractBearer,
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
            crate::binding::EnvironmentMode::Empty(_) => unreachable!(),
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

const UNAUTHORIZED_TOKEN_AUD: &str = "unexpected usage (correct token given but mode mismatch)";
const UNAUTHORIZED_TOKEN_BINDING_NOT_FOUND: &str = "corresponding role binding data not found";

/// Axum extractor for Bearer token per [RFC 6750][]
///
/// A given authentication scheme in Authorization header must exactly be `Bearer` (case sensitive).
/// This is due to https://github.com/hyperium/headers/issues/112 and is a deviation from [RFC 9110 Section 11.1.][rfc9110].
///
/// [RFC 6750]: https://datatracker.ietf.org/doc/html/rfc6750
/// [rfc9110]: https://datatracker.ietf.org/doc/html/rfc9110#section-11.1
#[derive(Debug)]
pub(crate) struct ExtractBearer {
    #[allow(dead_code)]
    pub(crate) source: BearerSource,

    pub(crate) value: secrecy::SecretString,
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub(crate) enum BearerSource {
    Header,
    Query,
}

const ACCESS_TOKEN: &str = "access_token";

#[async_trait::async_trait]
impl<S> axum::extract::FromRequestParts<S> for ExtractBearer
where
    S: Send + Sync,
{
    type Rejection = ExtractBearerRejection;

    #[tracing::instrument(skip_all)]
    async fn from_request_parts(
        parts: &mut axum::http::request::Parts,
        _state: &S,
    ) -> Result<Self, Self::Rejection> {
        use headers::Header;

        let query_values_maybe = parts
            .uri
            .query()
            .map(|v| url::form_urlencoded::parse(v.as_bytes()))
            .ok_or(ExtractBearerRejection::Missing)
            .and_then(|q| {
                let ts: Vec<_> = q.filter(|(k, _)| k == ACCESS_TOKEN).collect();

                match ts.len().cmp(&1) {
                    std::cmp::Ordering::Equal => Ok(ts[0].1.clone()),
                    std::cmp::Ordering::Less => Err(ExtractBearerRejection::Missing),
                    std::cmp::Ordering::Greater => Err(ExtractBearerRejection::Ambiguous),
                }
            });
        let query_value = match query_values_maybe {
            Ok(vs) => Some(vs),
            Err(ExtractBearerRejection::Ambiguous) => {
                return Err(ExtractBearerRejection::Ambiguous)
            }
            Err(ExtractBearerRejection::Error(_)) => {
                unreachable!("ExtractBearerRejection::Error shouldn't appear at this point")
            }
            Err(ExtractBearerRejection::Missing) => None,
        };

        let mut header_values = parts
            .headers
            .get_all(headers::Authorization::<headers::authorization::Bearer>::name())
            .iter();
        let header_value = match header_values.size_hint() {
            (1, Some(1)) => {
                match headers::Authorization::<headers::authorization::Bearer>::decode(
                    &mut header_values,
                ) {
                    Ok(c) => Some(c),
                    Err(e) => return Err(ExtractBearerRejection::Error(e)),
                }
            }
            (0, Some(0)) => None,
            (1, None) => {
                return Err(ExtractBearerRejection::Ambiguous);
            }
            (_, _) => {
                return Err(ExtractBearerRejection::Ambiguous);
            }
        };

        match (query_value, header_value) {
            (None, None) => Err(ExtractBearerRejection::Missing),
            (Some(_), Some(_)) => Err(ExtractBearerRejection::Ambiguous),
            (Some(q), None) => Ok(ExtractBearer {
                source: BearerSource::Query,

                value: secrecy::SecretString::new(q.as_ref().to_owned()),
            }),
            (None, Some(h)) => Ok(ExtractBearer {
                source: BearerSource::Header,
                value: secrecy::SecretString::new(h.token().to_owned()),
            }),
        }
    }
}

#[derive(Debug, thiserror::Error)]
pub(crate) enum ExtractBearerRejection {
    /// no bearer token was given
    #[error("bearer token was missing, must be given through Authorization header or access_token query parameter")]
    Missing,
    /// multiple tokens were given, had to decline per [RFC 6750 Section 2.](https://datatracker.ietf.org/doc/html/rfc6750#section-2)
    #[error("multiple bearer tokens were given")]
    Ambiguous,
    /// other possible header parse error
    #[error(transparent)]
    Error(headers::Error),
}

impl axum::response::IntoResponse for ExtractBearerRejection {
    fn into_response(self) -> axum::response::Response {
        (axum::http::StatusCode::BAD_REQUEST, self.to_string()).into_response()
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    use tower::Service; // for `call`
    use tower::ServiceExt; // for `oneshot` and `ready`

    mod extract_bearer {
        use super::*;

        async fn handler(bearer: ExtractBearer) -> impl axum::response::IntoResponse {
            use secrecy::ExposeSecret;
            format!(
                "source={:?},value={}",
                bearer.source,
                bearer.value.expose_secret()
            )
        }

        fn app() -> axum::Router {
            axum::Router::new().route("/", axum::routing::get(handler))
        }

        async fn do_request_and_body(req: axum::http::Request<axum::body::Body>) -> String {
            let resp = app().ready().await.unwrap().call(req).await.unwrap();
            String::from_utf8(
                hyper::body::to_bytes(resp.into_body())
                    .await
                    .unwrap()
                    .to_vec(),
            )
            .unwrap()
        }

        #[tokio::test]
        async fn test_header() {
            let req = axum::http::Request::builder()
                .uri("/")
                .header("Authorization", "Bearer himitsu")
                .body(axum::body::Body::empty())
                .unwrap();
            let body = do_request_and_body(req).await;
            assert_eq!(body, "source=Header,value=himitsu");
        }

        #[tokio::test]
        async fn test_header_invalid() {
            let req = axum::http::Request::builder()
                .uri("/")
                .header("Authorization", "Basic Zm9vOmJhcg==") // foo:bar
                .body(axum::body::Body::empty())
                .unwrap();
            let resp = app().ready().await.unwrap().call(req).await.unwrap();
            assert_eq!(resp.status(), 400);
        }

        #[tokio::test]
        async fn test_query() {
            let req = axum::http::Request::builder()
                .uri("/?access_token=kueri")
                .body(axum::body::Body::empty())
                .unwrap();
            let body = do_request_and_body(req).await;
            assert_eq!(body, "source=Query,value=kueri");
        }

        #[tokio::test]
        async fn test_query_invalid() {
            let req = axum::http::Request::builder()
                .uri("/?a==")
                .body(axum::body::Body::empty())
                .unwrap();
            let resp = app().ready().await.unwrap().call(req).await.unwrap();
            assert_eq!(resp.status(), 400);
        }

        #[tokio::test]
        async fn test_missing() {
            let req = axum::http::Request::builder()
                .uri("/")
                .body(axum::body::Body::empty())
                .unwrap();
            let resp = app().ready().await.unwrap().call(req).await.unwrap();
            assert_eq!(resp.status(), 400);
        }

        #[tokio::test]
        async fn test_header_unambiguous() {
            let req = axum::http::Request::builder()
                .header("Authorization", "Bearer hedda1")
                .header("Authorization", "Bearer hedda2")
                .body(axum::body::Body::empty())
                .unwrap();
            let resp = app().ready().await.unwrap().call(req).await.unwrap();
            assert_eq!(resp.status(), 400);
        }
        #[tokio::test]
        async fn test_query_unambiguous() {
            let req = axum::http::Request::builder()
                .uri("/?access_token=kueri&access_token=kueri2")
                .body(axum::body::Body::empty())
                .unwrap();
            let resp = app().ready().await.unwrap().call(req).await.unwrap();
            assert_eq!(resp.status(), 400);
        }
        #[tokio::test]
        async fn test_both_unambiguous() {
            let req = axum::http::Request::builder()
                .uri("/?access_token=kueri")
                .header("Authorization", "Bearer hedda")
                .body(axum::body::Body::empty())
                .unwrap();
            let resp = app().ready().await.unwrap().call(req).await.unwrap();
            assert_eq!(resp.status(), 400);
        }
    }
}
