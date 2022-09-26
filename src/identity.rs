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
        use rsa::pkcs8::EncodePublicKey as _;

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
            let cert_spki = i.certificate().tbs_certificate.subject_public_key_info;
            key_spki == cert_spki
        });

        let certificate_der = matches
            .first()
            .ok_or(crate::error::Error::IdentityCertificateNotFoundError)?
            .der
            .clone();
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

    pub fn validate(&self) -> Result<(), crate::error::Error> {
        if self.certificate().tbs_certificate.serial_number.len() > x509_cert::der::Length::new(20)
        {
            return Err(crate::error::Error::UnsupportedCertificateError(
                "Serial number is too long (supported up to 20 octets)".to_string(),
            ));
        }
        Ok(())
    }

    pub fn certificate(&self) -> x509_cert::Certificate {
        use x509_cert::der::Decode as _;
        x509_cert::Certificate::from_der(self.certificate_der.as_ref())
            .expect("der is a certificate")
    }

    pub fn serial_number_string(&self) -> String {
        // XXX: crypto-bigint doesn't have decimal representation formatter?
        let bytes = self.certificate().tbs_certificate.serial_number.as_bytes();
        num_bigint::BigUint::from_bytes_be(bytes).to_str_radix(10)
        // let mut slice = [0u8; 24];
        // slice[(24 - bytes.len())..].copy_from_slice(bytes);

        // let n = crypto_bigint::U192::from_be_slice(&slice);
    }
}

// TODO: zeroize

#[cfg(test)]
mod test {
    use rsa::pkcs1::EncodeRsaPrivateKey;
    use sec1::EncodeEcPrivateKey;
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
    fn test_pkey_ec_p256() {
        let key = PrivateKey::from_private_key_pem(KEY_EC).unwrap();
        let pkey = match key {
            PrivateKey::Ec(PrivateKeyEc::P256(pkey)) => pkey,
            _ => panic!("key is not PrivateKeyEc::P256"),
        };

        let pem = pkey.to_sec1_pem(sec1::LineEnding::LF).unwrap();
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

        let identity = Identity::from_chain_and_key(&chain, source_key.clone());

        assert!(matches!(
            identity,
            Err(crate::error::Error::IdentityCertificateNotFoundError)
        ));
    }

    #[test]
    fn test_identity_serial_number() {
        let chain = crate::certificate::decode_pem_chain(CERT_RSA_CHAIN).unwrap();
        let source_key = PrivateKey::from_private_key_pem(KEY_RSA).unwrap();
        let identity = Identity::from_chain_and_key(&chain, source_key.clone()).unwrap();

        assert_eq!(
            identity.serial_number_string(),
            "337562787801933536189724934726614584366112857655"
        );
    }
}
