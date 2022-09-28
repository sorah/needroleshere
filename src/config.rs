#[derive(Debug, Clone, Default)]
pub struct Config {
    config_dir: std::path::PathBuf,
    inner: ConfigData,
}

impl Config {
    pub fn new(
        config_dir: Option<std::path::PathBuf>,
        inner: ConfigData,
    ) -> Result<Self, crate::error::Error> {
        let config_dir_ = match config_dir {
            Some(v) => v,
            None => std::env::var("RUNTIME_DIRECTORY")
                .map_err(|_| {
                    crate::error::Error::ConfigError(
                        "--configuration-directory is required or provide $RUNTIME_DIRECTORY"
                            .to_string(),
                    )
                })?
                .into(),
        };

        Ok(Self {
            config_dir: config_dir_,
            inner,
        })
    }

    pub fn into_inner(self) -> ConfigData {
        self.inner
    }

    pub fn config_dir(&self) -> std::path::PathBuf {
        self.config_dir.clone()
    }

    pub(crate) fn path_for_binding(&self, name: &str) -> std::path::PathBuf {
        self.config_dir()
            .join(SUBDIR_BINDINGS)
            .join(&format!("{name}.json"))
    }

    pub(crate) fn path_for_env(&self, name: &str) -> std::path::PathBuf {
        self.config_dir().join(SUBDIR_ENV).join(name)
    }

    /// Ensure subdirectories
    pub(crate) async fn ensure_config_dir(&self) -> Result<(), crate::error::Error> {
        use std::os::unix::fs::PermissionsExt;

        {
            let bindings_path = self.config_dir().join(SUBDIR_BINDINGS);
            tokio::fs::create_dir_all(&bindings_path).await?;
        }
        {
            let env_path = self.config_dir().join(SUBDIR_ENV);
            tokio::fs::create_dir_all(&env_path).await?;
            let mut perm = tokio::fs::metadata(&env_path).await?.permissions();
            perm.set_mode(0o755);
            tokio::fs::set_permissions(&env_path, perm).await?;
        }

        Ok(())
    }
}

impl std::ops::Deref for Config {
    type Target = ConfigData;

    fn deref(&self) -> &Self::Target {
        &self.inner
    }
}

#[derive(Debug, Clone, Default, serde::Serialize, serde::Deserialize)]
pub struct ConfigData {
    pub url: Option<String>,
}

const SUBDIR_BINDINGS: &str = "bindings";
const SUBDIR_ENV: &str = "env";

impl Config {
    pub fn base_url(&self) -> Result<url::Url, crate::error::Error> {
        let u = self.url.as_ref().ok_or_else(|| {
            crate::error::Error::ConfigError(
                "base url (--url) is missing to construct full URI".to_string(),
            )
        })?;
        let url = reqwest::Url::parse(u).map_err(|_| {
            crate::error::Error::ConfigError("base url (--url) is malformed".to_string())
        })?;

        match url.origin() {
            url::Origin::Opaque(_) => Err(crate::error::Error::ConfigError(
                "base url (--url) is malformed".to_string(),
            )),
            url::Origin::Tuple(scheme, host, port) => {
                let mut base_url = reqwest::Url::parse(&format!("{scheme}://{host}")).unwrap();
                match base_url.port_or_known_default() {
                    Some(known) if known == port => {}
                    _ => {
                        base_url.set_port(Some(port)).unwrap();
                    }
                };
                Ok(base_url)
            }
        }
    }
}
