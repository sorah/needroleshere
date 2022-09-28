//! Authentication for clients of credential provider implementation

pub(crate) struct AccessToken<'a> {
    pub(crate) binding_name: &'a str,
    /// base64url encoded secret
    secret: &'a str,
}

impl<'a> std::fmt::Display for AccessToken<'a> {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> Result<(), std::fmt::Error> {
        write!(f, "needroleshere.{}.{}", self.binding_name, self.secret)?;
        Ok(())
    }
}

impl<'a> AccessToken<'a> {
    /// secret must be base64url encoded
    pub(crate) fn new(binding_name: &'a str, secret: &'a str) -> Self {
        Self {
            binding_name,
            secret,
        }
    }

    pub(crate) fn parse(value: &'a str) -> Result<Self, crate::error::Error> {
        if !value.starts_with("needroleshere.") {
            return Err(crate::error::Error::Unauthorized);
        }
        let start = value.find('.').unwrap();
        let mut contents = value
            .get(start + 1..)
            .ok_or(crate::error::Error::Unauthorized)?
            .splitn(2, '.');

        let binding_name = contents.next().ok_or(crate::error::Error::Unauthorized)?;
        let secret = contents.next().ok_or(crate::error::Error::Unauthorized)?;

        Ok(Self {
            binding_name,
            secret,
        })
    }

    pub(crate) fn verify(&self, expected_secret_hash: &str) -> Result<(), crate::error::Error> {
        use base64ct::Encoding;
        use sha2::Digest;

        let mut expected_secret_dgst0 = digest::Output::<sha2::Sha384>::default();
        base64ct::Base64UrlUnpadded::decode(expected_secret_hash, &mut expected_secret_dgst0)
            .map_err(|_| {
                crate::error::Error::Unknown("expected_secret_hash is invalid".to_string())
            })?;
        let expected_secret_dgst = digest::CtOutput::<sha2::Sha384>::new(expected_secret_dgst0);

        let secret_raw = base64ct::Base64UrlUnpadded::decode_vec(self.secret)
            .map_err(|_| crate::error::Error::Unauthorized)?;
        let given_secret_dgst =
            digest::CtOutput::new(sha2::Sha384::new_with_prefix(&secret_raw).finalize());

        if given_secret_dgst == expected_secret_dgst {
            Ok(())
        } else {
            Err(crate::error::Error::Unauthorized)
        }
    }
}

#[cfg(test)]
mod test {
    use super::*;

    //const TEST_SECRET: &str = "thisisatest.";
    const TEST_SECRET_B64: &str = "dGhpc2lzYXRlc3Qu";
    const TEST_SECRET_HASH: &str =
        "HMH2ZT39k34kFlafxZaIu2h8P5gfnx4k5jX6mkTib7-QWAwXBaKd7uC9B6Y59mcf";

    #[test]
    fn test_new() {
        let ah = AccessToken::new("testrole", TEST_SECRET_B64);
        assert_eq!(ah.binding_name, "testrole");
        assert_eq!(ah.secret, TEST_SECRET_B64);
        assert_eq!(
            ah.to_string(),
            format!("needroleshere.testrole.{}", TEST_SECRET_B64)
        );
    }

    #[test]
    fn test_parse() {
        let hv = format!("needroleshere.testrole.{}", TEST_SECRET_B64);
        let ah = AccessToken::parse(&hv).unwrap();
        assert_eq!(ah.binding_name, "testrole");
        assert_eq!(ah.secret, TEST_SECRET_B64);
    }
    #[test]
    fn test_parse_invalid1() {
        let hv = "Bearer something".to_string();
        assert!(AccessToken::parse(&hv).is_err());
    }
    #[test]
    fn test_parse_invalid2() {
        let hv = "needroleshere.".to_string();
        assert!(AccessToken::parse(&hv).is_err());
    }
    #[test]
    fn test_parse_invalid3() {
        let hv = "needroleshere.abc".to_string();
        assert!(AccessToken::parse(&hv).is_err());
    }

    #[test]
    fn test_verify() {
        let hv = format!("needroleshere.testrole.{}", TEST_SECRET_B64);
        let ah = AccessToken::parse(&hv).unwrap();
        ah.verify(TEST_SECRET_HASH).unwrap();
    }
    #[test]
    fn test_verify_invalid() {
        let hv = "needroleshere.testrole.dGhpc2lzYXRlc3Q_".to_string();
        let ah = AccessToken::parse(&hv).unwrap();
        assert!(ah.verify(TEST_SECRET_HASH).is_err());
    }
    #[test]
    fn test_verify_invalid_b64() {
        let hv = "needroleshere.testrole.~".to_string();
        let ah = AccessToken::parse(&hv).unwrap();
        assert!(ah.verify(TEST_SECRET_HASH).is_err());
    }
    #[test]
    fn test_verify_invalid_b64_2() {
        let hv = "needroleshere.testrole.".to_string();
        let ah = AccessToken::parse(&hv).unwrap();
        assert!(ah.verify(TEST_SECRET_HASH).is_err());
    }
}
