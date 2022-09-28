#![allow(dead_code)]

//! Manage role bindings and environment files.

#[derive(Debug, Clone, serde::Serialize, serde::Deserialize)]
pub struct RoleBinding {
    pub name: String,
    pub secret_hash: String,
    pub certificate_files: Vec<String>,
    pub private_key_file: String,
    pub request: crate::client::CreateSessionRequest,

    #[serde(skip)]
    pub secret: Option<String>,
}

fn validate_name(name: &str) -> Result<(), crate::error::Error> {
    if name.contains('.') {
        return Err(crate::error::Error::ConfigError(
            "binding name cannot include '.' (dot)".to_string(),
        ));
    }

    if name.find(std::path::MAIN_SEPARATOR).is_some() {
        return Err(crate::error::Error::ConfigError(
            "binding name cannot include path separator".to_string(),
        ));
    }
    // TODO: reject non-ascii

    Ok(())
}

impl RoleBinding {
    pub fn new(
        name: String,
        certificate_files: Vec<String>,
        private_key_file: String,
        request: crate::client::CreateSessionRequest,
    ) -> Result<Self, crate::error::Error> {
        use base64ct::Encoding;
        use rand::Rng;
        use sha2::Digest;

        validate_name(&name)?;
        if certificate_files.is_empty() {
            return Err(crate::error::Error::ConfigError(
                "certificate_files cannot be empty".to_string(),
            ));
        }

        let mut secret_raw = [0u8; 64];
        rand::thread_rng().fill(&mut secret_raw[..]);
        let secret_dgst = sha2::Sha384::digest(secret_raw);
        let secret_hash = base64ct::Base64UrlUnpadded::encode_string(&secret_dgst);
        let secret = base64ct::Base64UrlUnpadded::encode_string(&secret_raw);

        Ok(Self {
            name,
            secret_hash,
            secret: Some(secret),
            certificate_files,
            private_key_file,
            request,
        })
    }

    pub async fn load(
        config: &crate::config::Config,
        name: &str,
    ) -> Result<Self, crate::error::Error> {
        let binding_json = tokio::fs::read(config.path_for_binding(name)).await?;
        Ok(serde_json::from_str(
            std::str::from_utf8(&binding_json).map_err(|_| {
                crate::error::Error::ConfigError(
                    "binding json is malformed (invalid utf8)".to_string(),
                )
            })?,
        )?)
    }

    pub async fn identity(&self) -> Result<crate::identity::Identity, crate::error::Error> {
        crate::identity::Identity::from_file(
            &self.private_key_file,
            self.certificate_files
                .iter()
                .map(|v| v.as_str())
                .collect::<Vec<&str>>()
                .as_ref(),
        )
        .await
    }

    fn path(&self, config: &crate::config::Config) -> std::path::PathBuf {
        config.path_for_binding(&self.name)
    }

    fn env_path(&self, config: &crate::config::Config) -> std::path::PathBuf {
        config.path_for_env(&self.name)
    }

    pub async fn save(
        &self,
        config: &crate::config::Config,
        env_mode: EnvironmentMode,
    ) -> Result<(), crate::error::Error> {
        use tokio::io::AsyncWriteExt;

        let binding_json = serde_json::to_vec_pretty(&self)?;
        let env = env_mode.render(self, config)?.to_string();

        config.ensure_config_dir().await?;

        let binding_path = self.path(config);
        let binding_path_wip = {
            let path = binding_path
                .parent()
                .unwrap()
                .join(format!(".wip.{}", self.name));
            let mut binding_file = tokio::fs::OpenOptions::new()
                .write(true)
                .create_new(true)
                .mode(0o600)
                .open(&path)
                .await?;
            binding_file.write_all(&binding_json).await?;
            binding_file.write_all("\n".as_bytes()).await?;
            path
        };

        let env_path = self.env_path(config);
        {
            let mut env_file = tokio::fs::OpenOptions::new()
                .write(true)
                .create(true)
                .truncate(true)
                .mode(0o600)
                .open(&env_path)
                .await?;
            env_file.write_all(env.as_bytes()).await?;
        }
        tokio::fs::rename(&binding_path_wip, &binding_path).await?;
        Ok(())
    }

    pub async fn remove(&self, config: &crate::config::Config) -> Result<(), crate::error::Error> {
        remove_file_ignoring_enoent(self.env_path(config)).await?;
        remove_file_ignoring_enoent(self.path(config)).await?;
        Ok(())
    }

    pub(crate) fn authorization_header(&self) -> crate::auth::AuthorizationHeader<'_> {
        crate::auth::AuthorizationHeader::new(
            &self.name,
            self.secret
                .as_ref()
                .expect("role_binding secret (raw) must be provided but none (BUG)"),
        )
    }
}

async fn remove_file_ignoring_enoent(path: std::path::PathBuf) -> std::io::Result<()> {
    match tokio::fs::remove_file(path).await {
        Ok(v) => Ok(v),
        Err(e) if e.kind() == std::io::ErrorKind::NotFound => Ok(()),
        Err(e) => Err(e),
    }
}

const AWS_CONTAINER_CREDENTIALS_FULL_URI: &str = "AWS_CONTAINER_CREDENTIALS_FULL_URI";
const AWS_CONTAINER_CREDENTIALS_RELATIVE_URI: &str = "AWS_CONTAINER_CREDENTIALS_RELATIVE_URI";
const AWS_CONTAINER_AUTHORIZATION_TOKEN: &str = "AWS_CONTAINER_AUTHORIZATION_TOKEN";

type EnvironmentListInner = Vec<(&'static str, String)>;

pub struct EnvironmentList {
    inner: EnvironmentListInner,
}

impl EnvironmentList {
    pub fn into_inner(self) -> EnvironmentListInner {
        self.inner
    }
}

impl std::fmt::Display for EnvironmentList {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> Result<(), std::fmt::Error> {
        for (k, v) in self.inner.iter() {
            writeln!(f, "{k}={v}")?;
        }
        Ok(())
    }
}

impl std::ops::Deref for EnvironmentList {
    type Target = EnvironmentListInner;

    fn deref(&self) -> &Self::Target {
        &self.inner
    }
}

impl From<EnvironmentListInner> for EnvironmentList {
    fn from(mut inner: Vec<(&'static str, String)>) -> Self {
        inner.sort_by_key(|k| k.0);
        Self { inner }
    }
}

#[derive(Clone, Debug, clap::ValueEnum)]
pub enum EnvironmentMode {
    EcsFull,
    EcsRelative,
    Empty,
}

impl EnvironmentMode {
    pub fn render(
        &self,
        binding: &RoleBinding,
        config: &crate::config::Config,
    ) -> Result<EnvironmentList, crate::error::Error> {
        match *self {
            Self::EcsFull => self.render_as_ecs_full(binding, config),
            Self::EcsRelative => self.render_as_ecs_relative(binding, config),
            Self::Empty => Ok(Vec::new().into()),
        }
    }

    fn render_as_ecs_full(
        &self,
        binding: &RoleBinding,
        config: &crate::config::Config,
    ) -> Result<EnvironmentList, crate::error::Error> {
        let mut url = config.base_url()?;
        url.set_path("/ecs/credentials");
        Ok(vec![
            (AWS_CONTAINER_CREDENTIALS_FULL_URI, url.into()),
            self.render_container_auth_token(binding),
        ]
        .into())
    }

    fn render_as_ecs_relative(
        &self,
        binding: &RoleBinding,
        _config: &crate::config::Config,
    ) -> Result<EnvironmentList, crate::error::Error> {
        Ok(vec![
            (
                AWS_CONTAINER_CREDENTIALS_RELATIVE_URI,
                "/ecs/credentials".to_string(),
            ),
            self.render_container_auth_token(binding),
        ]
        .into())
    }

    fn render_container_auth_token(&self, binding: &RoleBinding) -> (&'static str, String) {
        (
            AWS_CONTAINER_AUTHORIZATION_TOKEN,
            binding.authorization_header().to_string(),
        )
    }
}

#[cfg(test)]
mod test {
    use super::*;

    use base64ct::Encoding;
    use std::os::unix::prelude::PermissionsExt;

    fn make_test_role_binding() -> RoleBinding {
        RoleBinding::new(
            "testrole".to_string(),
            vec!["".to_string()],
            "".to_string(),
            crate::client::CreateSessionRequest {
                role_arn: "".to_string(),
                session_name: None,
                duration_seconds: None,
                trust_anchor_arn: "".to_string(),
                profile_arn: "".to_string(),
            },
        )
        .unwrap()
    }

    #[test]
    fn test_role_binding_new() {
        let b = make_test_role_binding();
        assert!(b.secret.is_some());
        base64ct::Base64UrlUnpadded::decode_vec(b.secret.as_ref().unwrap()).unwrap();
        base64ct::Base64UrlUnpadded::decode_vec(&b.secret_hash).unwrap();
    }

    #[test]
    fn test_role_binding_auth_roundtrip() {
        let b = make_test_role_binding();
        let ah = b.authorization_header();
        ah.verify(&b.secret_hash).unwrap();
    }

    #[tokio::test]
    async fn test_role_binding_save() {
        let config = crate::dev::TestConfig::new();
        let binding = make_test_role_binding();
        binding.save(&config, EnvironmentMode::Empty).await.unwrap();

        {
            let binding_path = config.tmpdir.path().join("bindings").join("testrole.json");
            let meta = std::fs::metadata(binding_path).unwrap();
            assert_eq!(meta.permissions().mode(), 0o100600);
        }

        {
            let env_path = config.tmpdir.path().join("env").join("testrole");
            let meta = std::fs::metadata(env_path).unwrap();
            assert_eq!(meta.permissions().mode(), 0o100600);
        }

        binding.save(&config, EnvironmentMode::Empty).await.unwrap();
        binding.remove(&config).await.unwrap();
    }

    #[test]
    fn test_rendering_ecs_full_environment() {
        let config = crate::dev::TestConfig::new();
        let binding = make_test_role_binding();
        let ah = binding.authorization_header();
        let envlist = EnvironmentMode::EcsFull
            .render(&binding, &config)
            .unwrap()
            .into_inner();

        assert_eq!(
            envlist,
            vec![
                (AWS_CONTAINER_AUTHORIZATION_TOKEN, ah.to_string()),
                (
                    AWS_CONTAINER_CREDENTIALS_FULL_URI,
                    "http://nrh.test.invalid:7224/ecs/credentials".to_string()
                ),
            ]
        )
    }

    #[test]
    fn test_rendering_envlist() {
        let envlist = EnvironmentList::from(vec![
            ("TEST_ENV_A", "aaa".to_string()),
            ("TEST_ENV_B", "bbb".to_string()),
            ("TEST_ENV_C", "ccc".to_string()),
        ]);
        assert_eq!(
            envlist.to_string(),
            indoc::indoc! {"
                TEST_ENV_A=aaa
                TEST_ENV_B=bbb
                TEST_ENV_C=ccc
            "}
        );
    }
}
