pub struct TestConfig {
    inner: crate::config::Config,
    pub tmpdir: temp_dir::TempDir,
}

impl std::ops::Deref for TestConfig {
    type Target = crate::config::Config;

    fn deref(&self) -> &Self::Target {
        &self.inner
    }
}

impl TestConfig {
    pub fn new() -> Self {
        let tmpdir = temp_dir::TempDir::with_prefix("needroleshere-dev").unwrap();
        let inner = crate::config::Config::new(
            Some(tmpdir.path().into()),
            crate::config::ConfigData {
                url: Some("http://nrh.test.invalid:7224/foo/bar?baz".to_string()),
            },
        )
        .unwrap();
        Self { inner, tmpdir }
    }
}
