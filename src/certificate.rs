#![allow(dead_code)]

#[derive(Debug, Clone)]
pub struct ChainItem {
    pub der: pkcs8::der::Document,
}

impl ChainItem {
    pub fn certificate(&self) -> x509_cert::Certificate {
        use x509_cert::der::Decode as _;
        x509_cert::Certificate::from_der(self.der.as_ref()).expect("der is a certificate")
    }
}

pub(crate) async fn load_pem_chain_file(path: &str) -> Result<Vec<ChainItem>, crate::error::Error> {
    tracing::trace!(message = "load_pem_chain_file", path = %path);
    let content = match tokio::fs::read_to_string(path).await {
        Ok(v) => v,
        Err(e) => {
            tracing::error!(message = "failed to load_pem_chain_file", path = %path, error = ?e);
            return Err(e.into());
        }
    };
    match crate::certificate::decode_pem_chain(&content) {
        Ok(v) => Ok(v),
        Err(e) => {
            tracing::error!(message = "failed to decode_pem_chain", path = %path, error = ?e);
            Err(e)
        }
    }
}

// Returns Vec<ChainItem>. The der (Vec<u8>) is guaranteed to be parseable as x509 certificate.
pub(crate) fn decode_pem_chain(input: &str) -> Result<Vec<ChainItem>, crate::error::Error> {
    use x509_cert::der::Decode as _;

    let mut result = Vec::new();

    let pems = split_pems(input);
    for pem in pems.into_iter() {
        let (_label, der) = pem_rfc7468::decode_vec(pem.as_bytes())?;
        x509_cert::Certificate::from_der(&der)?;
        let der = pkcs8::der::Document::try_from(der)?;
        result.push(ChainItem { der });
    }

    Ok(result)
}

const PEM_CERT_PREEB: &str = "-----BEGIN CERTIFICATE-----";
const PEM_CERT_POSTEB: &str = "-----END CERTIFICATE-----";

// This fn is not implemented accurately.
pub(crate) fn split_pems(input: &str) -> Vec<String> {
    let mut result = Vec::new();
    let mut head = None;

    for line in input.lines() {
        if line.starts_with(PEM_CERT_PREEB) {
            head = Some(Vec::new());
        }
        if let Some(h) = head.as_mut() {
            h.push(line);
        }
        if line.starts_with(PEM_CERT_POSTEB) {
            if let Some(h) = head {
                result.push(h);
                head = Some(Vec::new());
            }
        }
    }
    if let Some(h) = head {
        if !h.is_empty() {
            result.push(h);
        }
    }

    result.into_iter().map(|i| i.join("\n")).collect()
}

#[cfg(test)]
mod test {
    use super::*;

    const CERT_SINGLE: &str = include_str!("../tests/examples/cert.pem");
    const CERT_CHAIN: &str = include_str!("../tests/examples/cert.chained.pem");

    #[test]
    fn test_parse_single() {
        let chain = decode_pem_chain(CERT_SINGLE).unwrap();
        assert_eq!(chain.len(), 1);
        let cert = chain[0].certificate();
        assert_eq!(
            extract_cn(&cert.tbs_certificate.subject.0).unwrap(),
            "leaf.test.invalid"
        );
    }

    #[test]
    fn test_parse_chain() {
        let chain = decode_pem_chain(CERT_CHAIN).unwrap();
        assert_eq!(chain.len(), 2);
        let cert0 = chain[0].certificate();
        assert_eq!(
            extract_cn(&cert0.tbs_certificate.subject.0).unwrap(),
            "leaf.test.invalid"
        );
        let cert1 = chain[1].certificate();
        assert_eq!(
            extract_cn(&cert1.tbs_certificate.subject.0).unwrap(),
            "rolesanywhere test CA - Intermediate"
        );
    }

    fn extract_cn<'a>(
        subject: &'a Vec<x509_cert::name::RelativeDistinguishedName>,
    ) -> Option<&'a str> {
        use x509_cert::der::Tagged as _;

        for name in subject {
            let frag = name.0.get(0).unwrap();
            // id-at-commonName
            if frag.oid == "2.5.4.3".parse().unwrap() {
                let value = match frag.value.tag() {
                    x509_cert::der::Tag::Utf8String => frag
                        .value
                        .decode_as::<x509_cert::der::asn1::Utf8StringRef>()
                        .unwrap()
                        .as_str(),
                    x509_cert::der::Tag::PrintableString => frag
                        .value
                        .decode_as::<x509_cert::der::asn1::PrintableStringRef>()
                        .unwrap()
                        .as_str(),
                    _ => panic!("unknown tag"),
                };
                return Some(value);
            }
        }
        None
    }
}
