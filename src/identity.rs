#![allow(dead_code)]

const OID_SECP_256_R_1: pkcs8::ObjectIdentifier =
    pkcs8::ObjectIdentifier::new_unwrap("1.2.840.10045.3.1.7"); // secp256r1, prime256v1
const OID_SECP_384_R_1: pkcs8::ObjectIdentifier =
    pkcs8::ObjectIdentifier::new_unwrap("1.3.132.0.34"); // secp384r1

#[derive(Clone, Debug, PartialEq, Eq)]
#[allow(clippy::large_enum_variant)]
pub enum PrivateKey {
    Rsa(rsa::RsaPrivateKey),
    Ec(PrivateKeyEc),
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub enum PrivateKeyEc {
    P256(elliptic_curve::SecretKey<p256::NistP256>),
    P384(elliptic_curve::SecretKey<p384::NistP384>),
    // TODO: P521 support once ecdsa crate supports
}

impl PrivateKey {
    pub fn from_private_key_pem(input: &str) -> Result<Self, crate::error::Error> {
        use rsa::pkcs1::DecodeRsaPrivateKey as _;
        use sec1::der::Decode as _;

        let (label, der) = pem_rfc7468::decode_vec(input.as_bytes())?;
        let key = match label {
            "RSA PRIVATE KEY" => PrivateKey::Rsa(rsa::RsaPrivateKey::from_pkcs1_der(&der)?),
            "EC PRIVATE KEY" => {
                let sec1_pkey = sec1::EcPrivateKey::from_der(&der)?;
                let named_curve = sec1_pkey
                    .parameters
                    .ok_or(crate::error::Error::UnknownKeyCurveError)?
                    .named_curve()
                    .ok_or(crate::error::Error::UnknownKeyCurveError)?;

                match named_curve {
                    OID_SECP_256_R_1 => PrivateKey::Ec(PrivateKeyEc::P256(
                        elliptic_curve::SecretKey::from_sec1_der(&der)?,
                    )), // secp256r1, prime256v1
                    OID_SECP_384_R_1 => PrivateKey::Ec(PrivateKeyEc::P384(
                        elliptic_curve::SecretKey::from_sec1_der(&der)?,
                    )),
                    _ => return Err(crate::error::Error::UnknownKeyCurveError),
                }
            }
            // TODO: missing pkcs8 "PRIVATE KEY" support
            _ => return Err(crate::error::Error::UnsupportedKeyError(label.to_owned())),
        };

        Ok(key)
    }

    pub fn spki_der(&self) -> Result<pkcs8::der::Document, crate::error::Error> {
        use pkcs8::EncodePublicKey as _;

        match *self {
            Self::Rsa(ref pkey) => {
                // NOTE: spki::PublicKeyDocument is replaced with der::Document but rsa crate is still
                // depending on older spki crate
                let rsa_doc = pkey.to_public_key().to_public_key_der()?;
                Ok(pkcs8::der::Document::try_from(rsa_doc.as_ref())?)
            }
            Self::Ec(PrivateKeyEc::P256(ref pkey)) => Ok(pkey.public_key().to_public_key_der()?),
            Self::Ec(PrivateKeyEc::P384(ref pkey)) => Ok(pkey.public_key().to_public_key_der()?),
        }
    }
}

#[derive(Clone, Debug)]
pub struct Identity {
    pub certificate_der: pkcs8::der::Document,
    pub private_key: PrivateKey,

    pub intermediates: Option<Vec<crate::certificate::ChainItem>>,
}

impl Identity {
    pub fn from_chain_and_key(
        chain: &[crate::certificate::ChainItem],
        private_key: PrivateKey,
    ) -> Result<Self, crate::error::Error> {
        use pkcs8::der::Decode as _;
        let key_spki_der = private_key.spki_der()?;
        let key_spki = pkcs8::spki::SubjectPublicKeyInfo::from_der(key_spki_der.as_bytes())?;

        let (matches, unmatches): (Vec<_>, Vec<_>) = chain.iter().partition(|i| {
            let cert = i.certificate();
            let cert_spki = cert.tbs_certificate.subject_public_key_info;
            tracing::debug!(message = "loaded certificate", cert_sub = %cert.tbs_certificate.subject, cert_iss = %cert.tbs_certificate.issuer);
            tracing::trace!(message = "loaded certificate (detail)", key_spki = ?key_spki, cert_spki = ?cert_spki, cert_sub = %cert.tbs_certificate.subject, cert_iss = %cert.tbs_certificate.issuer);
            key_spki == cert_spki
        });

        let certificate_der_maybe = matches
            .first()
            .ok_or(crate::error::Error::IdentityCertificateNotFoundError);

        let certificate_der = match certificate_der_maybe {
            Ok(v) => {
                let cert = v.certificate();
                tracing::debug!(message = "end entity certificate found", cert_sub = %cert.tbs_certificate.subject, cert_iss = %cert.tbs_certificate.issuer);
                v.der.to_owned()
            }
            Err(e) => {
                tracing::error!(message = "Couldn't find a certificate from given chain for the given private key", key_spki = ?key_spki);
                return Err(e);
            }
        };
        let intermediates: Vec<_> = unmatches.iter().map(|v| (*v).clone()).collect();

        let identity = Self {
            certificate_der,
            private_key,

            intermediates: if intermediates.is_empty() {
                None
            } else {
                Some(intermediates)
            },
        };
        identity.validate()?;
        Ok(identity)
    }

    pub async fn from_file(
        private_key_path: &str,
        certificate_file_paths: &[&str],
    ) -> Result<Self, crate::error::Error> {
        use secrecy::ExposeSecret;

        tracing::trace!(message = "from_file", private_key_path = ?private_key_path, certificate_file_paths = ?certificate_file_paths);

        let key_file = secrecy::Secret::new(
            match tokio::fs::read_to_string(private_key_path).await {
                Ok(v) => v,
                Err(e) => {
                    tracing::error!(message = "failed to load private key", path = %private_key_path, error = ?e);
                    return Err(e.into());
                }
            },
        );
        let pkey = match PrivateKey::from_private_key_pem(key_file.expose_secret()) {
            Ok(v) => v,
            Err(e) => {
                tracing::error!(message = "failed to parse private key", path = %private_key_path, error = ?e);
                return Err(e);
            }
        };

        let mut chain = Vec::new();
        for file in certificate_file_paths.iter() {
            chain.append(&mut crate::certificate::load_pem_chain_file(file).await?);
        }

        Self::from_chain_and_key(&chain, pkey)
    }

    #[inline]
    pub fn validate(&self) -> Result<(), crate::error::Error> {
        // Formerly SerialNumber length was validated here, but it is now validated within
        // x509_cert crate, so this function resulting empty
        Ok(())
    }

    pub fn certificate(&self) -> x509_cert::Certificate {
        use x509_cert::der::Decode as _;
        x509_cert::Certificate::from_der(self.certificate_der.as_ref())
            .expect("der is a certificate")
    }

    pub fn serial_number_string(&self) -> String {
        // XXX: crypto-bigint doesn't have decimal representation formatter?
        let cert = self.certificate();
        let sn = cert.tbs_certificate.serial_number.as_bytes();
        num_bigint::BigUint::from_bytes_be(sn).to_str_radix(10)
        // let mut slice = [0u8; 24];
        // slice[(24 - bytes.len())..].copy_from_slice(bytes);

        // let n = crypto_bigint::U192::from_be_slice(&slice);
    }
}

#[cfg(test)]
mod test {
    use rsa::pkcs1::EncodeRsaPrivateKey;
    use std::ops::Deref;

    use super::*;

    const KEY_RSA: &str = include_str!("../tests/examples/cert-key.pem");
    const CERT_RSA_SINGLE: &str = include_str!("../tests/examples/cert.pem");
    const CERT_RSA_CHAIN: &str = include_str!("../tests/examples/cert.chained.pem");

    const KEY_EC: &str = include_str!("../tests/examples/cert-ec-key.pem");
    const CERT_EC_SINGLE: &str = include_str!("../tests/examples/cert-ec.pem");
    const CERT_EC_CHAIN: &str = include_str!("../tests/examples/cert-ec.chained.pem");

    #[test]
    fn test_pkey_rsa() {
        let key = PrivateKey::from_private_key_pem(KEY_RSA).unwrap();
        let rsa_pkey = match key {
            PrivateKey::Rsa(pkey) => pkey,
            _ => panic!("key is not PrivateKey::Rsa"),
        };

        let pem = rsa_pkey.to_pkcs1_pem(rsa::pkcs1::LineEnding::LF).unwrap();
        assert_eq!(pem.deref(), KEY_RSA);
    }

    #[test]
    fn test_pkey_ec_p256_roundtrip() {
        let key = PrivateKey::from_private_key_pem(KEY_EC).unwrap();
        let pkey = match key {
            PrivateKey::Ec(PrivateKeyEc::P256(pkey)) => pkey,
            _ => panic!("key is not PrivateKeyEc::P256"),
        };

        // elliptic_curve::SecretKey::to_sec1_pem (to_sec1_der) lacks sec1::EcPrivateKey#parameters (resulting None)
        // while sec1::EncodeEcPrivateKey writes a named curve
        // https://github.com/RustCrypto/traits/blob/128d4e6df73f9ec528e0b0a6dd88a9e6917aa221/elliptic-curve/src/secret_key.rs#L200
        // https://github.com/RustCrypto/formats/blob/ce9d249e5ca11a7b4af0d2425fefe0e9355ec4f4/sec1/src/traits.rs#L113
        let pem =
            <elliptic_curve::SecretKey<p256::NistP256> as sec1::EncodeEcPrivateKey>::to_sec1_pem(
                &pkey,
                sec1::LineEnding::LF,
            )
            .unwrap();
        //let pem = pkey.to_sec1_pem(sec1::LineEnding::LF).unwrap();
        assert_eq!(pem.deref(), KEY_EC);
    }

    #[test]
    fn test_pkey_broken() {
        assert!(PrivateKey::from_private_key_pem(&KEY_EC[..50]).is_err());
    }

    #[test]
    fn test_identity_rsa_single() {
        let chain = crate::certificate::decode_pem_chain(CERT_RSA_SINGLE).unwrap();
        let source_key = PrivateKey::from_private_key_pem(KEY_RSA).unwrap();
        let identity = Identity::from_chain_and_key(&chain, source_key.clone()).unwrap();

        assert_eq!(identity.private_key, source_key);
        assert_eq!(identity.certificate(), chain[0].certificate());
        assert!(identity.intermediates.is_none());
    }

    #[test]
    fn test_identity_rsa_chain() {
        let chain = crate::certificate::decode_pem_chain(CERT_RSA_CHAIN).unwrap();
        let source_key = PrivateKey::from_private_key_pem(KEY_RSA).unwrap();
        let identity = Identity::from_chain_and_key(&chain, source_key.clone()).unwrap();

        assert_eq!(identity.private_key, source_key);
        assert_eq!(identity.certificate(), chain[0].certificate());

        let intermediates = identity.intermediates.unwrap();
        assert_eq!(intermediates.len(), 1);
        assert_eq!(intermediates[0].certificate(), chain[1].certificate());
    }

    #[test]
    fn test_identity_ec_single() {
        let chain = crate::certificate::decode_pem_chain(CERT_EC_SINGLE).unwrap();
        let source_key = PrivateKey::from_private_key_pem(KEY_EC).unwrap();
        let identity = Identity::from_chain_and_key(&chain, source_key.clone()).unwrap();

        assert_eq!(identity.private_key, source_key);
        assert_eq!(identity.certificate(), chain[0].certificate());
        assert!(identity.intermediates.is_none());
    }

    #[test]
    fn test_identity_ec_chain() {
        let chain = crate::certificate::decode_pem_chain(CERT_EC_CHAIN).unwrap();
        let source_key = PrivateKey::from_private_key_pem(KEY_EC).unwrap();
        let identity = Identity::from_chain_and_key(&chain, source_key.clone()).unwrap();

        assert_eq!(identity.private_key, source_key);
        assert_eq!(identity.certificate(), chain[0].certificate());

        let intermediates = identity.intermediates.unwrap();
        assert_eq!(intermediates.len(), 1);
        assert_eq!(intermediates[0].certificate(), chain[1].certificate());
    }

    #[test]
    fn test_identity_chain_reversed() {
        let source_chain = crate::certificate::decode_pem_chain(CERT_RSA_CHAIN).unwrap();
        let source_key = PrivateKey::from_private_key_pem(KEY_RSA).unwrap();

        let chain = vec![source_chain[1].clone(), source_chain[0].clone()];
        let identity = Identity::from_chain_and_key(&chain, source_key.clone()).unwrap();

        assert_eq!(identity.private_key, source_key);
        assert_eq!(identity.certificate(), source_chain[0].certificate());

        let intermediates = identity.intermediates.unwrap();
        assert_eq!(intermediates.len(), 1);
        assert_eq!(
            intermediates[0].certificate(),
            source_chain[1].certificate()
        );
    }

    #[test]
    fn test_identity_chain_unmatch() {
        let chain = crate::certificate::decode_pem_chain(CERT_EC_CHAIN).unwrap();
        let source_key = PrivateKey::from_private_key_pem(KEY_RSA).unwrap();

        let identity = Identity::from_chain_and_key(&chain, source_key);

        assert!(matches!(
            identity,
            Err(crate::error::Error::IdentityCertificateNotFoundError)
        ));
    }

    #[test]
    fn test_identity_serial_number() {
        let chain = crate::certificate::decode_pem_chain(CERT_RSA_CHAIN).unwrap();
        let source_key = PrivateKey::from_private_key_pem(KEY_RSA).unwrap();
        let identity = Identity::from_chain_and_key(&chain, source_key).unwrap();

        assert_eq!(
            identity.serial_number_string(),
            "337562787801933536189724934726614584366112857655"
        );
    }
}
