/*
 * This source code is a modified version of aws-sigv4 crate to support
 * AWS4-X509-{RSA,ECDSA}-SHA256 method. Some features are omitted where unnecessary for use with
 * rolesanywhere service and most enums are replaced with a single value for the same reason.
 *
 * https://github.com/awslabs/aws-sdk-rust/blob/main/sdk/aws-sigv4
 *
 * Copyright Amazon.com, Inc. or its affiliates. All Rights Reserved.
 * SPDX-License-Identifier: Apache-2.0
 */

//! AWS4-X509-RSA-SHA256 and AWS4-X509-ECDSA-SHA256 signer

pub const AWS4_X509_RSA_SHA256: &str = "AWS4-X509-RSA-SHA256";
pub const AWS4_X509_ECDSA_SHA256: &str = "AWS4-X509-ECDSA-SHA256";

pub mod header {
    pub const X_AMZ_DATE: &str = "x-amz-date";
    pub const X_AMZ_X509: &str = "x-amz-x509";
    pub const X_AMZ_X509_CHAIN: &str = "x-amz-x509-chain";
}

#[derive(Debug)]
pub struct SigningParams<'a> {
    pub region: &'a str,
    pub service_name: &'a str,
    pub time: chrono::DateTime<chrono::Utc>,

    pub identity: &'a crate::identity::Identity,
}

#[derive(Debug)]
pub struct SignableRequest<'a> {
    pub method: &'a reqwest::Method,
    pub uri: &'a http::Uri,
    pub headers: &'a reqwest::header::HeaderMap,
    pub body: &'a [u8],
}

impl<'a, B> From<&'a http::Request<B>> for SignableRequest<'a>
where
    B: 'a,
    B: AsRef<[u8]>,
{
    fn from(request: &'a http::Request<B>) -> SignableRequest<'a> {
        SignableRequest {
            method: request.method(),
            uri: request.uri(),
            headers: request.headers(),
            body: request.body().as_ref(),
        }
    }
}

#[derive(Debug, PartialEq, Eq, Clone)]
struct CanonicalHeaderName(reqwest::header::HeaderName);

impl PartialOrd for CanonicalHeaderName {
    fn partial_cmp(&self, other: &Self) -> Option<std::cmp::Ordering> {
        Some(self.cmp(other))
    }
}

impl Ord for CanonicalHeaderName {
    fn cmp(&self, other: &Self) -> std::cmp::Ordering {
        self.0.as_str().cmp(other.0.as_str())
    }
}

#[derive(PartialEq, Eq, Debug, Clone)]
pub struct SigningScope<'a> {
    pub time: chrono::DateTime<chrono::Utc>,
    pub region: &'a str,
    pub service: &'a str,
}

impl<'a> std::fmt::Display for SigningScope<'a> {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(
            f,
            "{}/{}/{}/aws4_request",
            self.time.format("%Y%m%d"),
            self.region,
            self.service
        )
    }
}

#[derive(Debug, PartialEq, Eq)]
pub struct StringToSign<'a> {
    pub scope: SigningScope<'a>,
    pub time: chrono::DateTime<chrono::Utc>,
    pub region: &'a str,
    pub service: &'a str,
    pub hashed_creq: &'a str,

    pub algorithm: &'static str,
}

impl<'a> StringToSign<'a> {
    pub(crate) fn new(
        algorithm: &'static str,
        time: chrono::DateTime<chrono::Utc>,
        region: &'a str,
        service: &'a str,
        hashed_creq: &'a str,
    ) -> Self {
        let scope = SigningScope {
            time,
            region,
            service,
        };
        Self {
            scope,
            time,
            region,
            service,
            hashed_creq,

            algorithm,
        }
    }
}

impl<'a> std::fmt::Display for StringToSign<'a> {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(
            f,
            "{}\n{}\n{}\n{}",
            self.algorithm,
            self.time.format("%Y%m%dT%H%M%SZ"),
            self.scope,
            self.hashed_creq
        )
    }
}

#[derive(Debug, PartialEq, Eq, Default)]
pub struct SignedHeaders {
    headers: Vec<CanonicalHeaderName>,
    formatted: String,
}

impl SignedHeaders {
    fn new(mut headers: Vec<CanonicalHeaderName>) -> Self {
        headers.sort();
        let formatted = Self::fmt(&headers);

        SignedHeaders { headers, formatted }
    }

    fn fmt(headers: &[CanonicalHeaderName]) -> String {
        let mut value = String::new();
        let mut iter = headers.iter().peekable();
        while let Some(next) = iter.next() {
            value += next.0.as_str();
            if iter.peek().is_some() {
                value.push(';');
            }
        }
        value
    }

    pub(super) fn as_str(&self) -> &str {
        &self.formatted
    }
}

impl std::fmt::Display for SignedHeaders {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(f, "{}", self.formatted)
    }
}

#[derive(Debug, PartialEq, Eq)]
pub struct SignatureValues {
    pub content_sha256: String,
    pub date_time: String,
    pub signed_headers: SignedHeaders,

    pub x509: reqwest::header::HeaderValue,
    pub x509_chain: Option<reqwest::header::HeaderValue>,
}

#[derive(Debug, PartialEq, Eq)]
pub struct CanonicalRequest<'a> {
    pub method: &'a reqwest::Method,
    pub path: &'a str,
    pub headers: reqwest::header::HeaderMap,
    pub values: SignatureValues,
    // params (query params) is omitted
}

impl<'a> CanonicalRequest<'a> {
    pub fn from<'b>(
        req: &'b SignableRequest<'b>,
        params: &'b SigningParams<'b>,
    ) -> Result<CanonicalRequest<'b>, crate::error::Error> {
        let path = req.uri.path();
        let payload_hash = Self::payload_hash(req.body);

        if matches!(req.uri.query().map(|v| v.is_empty()), Some(false)) {
            panic!("CanonicalRequest currently lacks implementation for signing query string");
        }

        let date_time = params.time.format("%Y%m%dT%H%M%SZ").to_string();

        let x509 = encode_x509_certificate(&params.identity.certificate_der);
        let x509_chain = params
            .identity
            .intermediates
            .as_ref()
            .map(|v| encode_x509_certificate_chain(v));

        let (signed_headers, canonical_headers) = Self::headers(
            req,
            params,
            &payload_hash,
            &date_time,
            &x509,
            x509_chain.as_ref(),
        )?;
        let signed_headers = SignedHeaders::new(signed_headers);
        let values = SignatureValues {
            content_sha256: payload_hash,
            date_time,
            signed_headers,
            x509,
            x509_chain,
        };
        let creq = CanonicalRequest {
            method: req.method,
            path,
            headers: canonical_headers,
            values,
        };
        Ok(creq)
    }

    fn headers(
        req: &SignableRequest<'_>,
        _params: &SigningParams<'_>,
        _payload_hash: &str,
        date_time: &str,
        x509: &reqwest::header::HeaderValue,
        x509_chain: Option<&reqwest::header::HeaderValue>,
    ) -> Result<(Vec<CanonicalHeaderName>, reqwest::header::HeaderMap), crate::error::Error> {
        use std::str::FromStr as _;

        let mut canonical_headers = reqwest::header::HeaderMap::with_capacity(req.headers.len());
        for (name, value) in req.headers.iter() {
            canonical_headers.append(
                reqwest::header::HeaderName::from_str(&name.as_str().to_lowercase())?,
                normalize_header_value(value),
            );
        }

        Self::insert_host_header(&mut canonical_headers, req.uri);
        Self::insert_date_header(&mut canonical_headers, date_time);
        Self::insert_x509_headers(&mut canonical_headers, x509, x509_chain);

        let mut signed_headers = Vec::with_capacity(canonical_headers.len());
        for (name, _) in &canonical_headers {
            signed_headers.push(CanonicalHeaderName(name.clone()));
        }

        Ok((signed_headers, canonical_headers))
    }

    fn payload_hash(body: &[u8]) -> String {
        sha256_hex_string(body)
    }

    fn insert_host_header(
        canonical_headers: &mut reqwest::header::HeaderMap,
        uri: &http::Uri,
    ) -> reqwest::header::HeaderValue {
        match canonical_headers.get(&reqwest::header::HOST) {
            Some(header) => header.clone(),

            None => {
                let authority = uri
                    .authority()
                    .expect("request uri authority must be set for signing");
                let header = reqwest::header::HeaderValue::try_from(authority.as_str())
                    .expect("endpoint must contain valid header characters");
                canonical_headers.insert(reqwest::header::HOST, header.clone());
                header
            }
        }
    }

    fn insert_date_header(
        canonical_headers: &mut reqwest::header::HeaderMap,
        date_time: &str,
    ) -> reqwest::header::HeaderValue {
        let x_amz_date = reqwest::header::HeaderName::from_static(header::X_AMZ_DATE);
        let date_header =
            reqwest::header::HeaderValue::try_from(date_time).expect("date is valid header value");
        canonical_headers.insert(x_amz_date, date_header.clone());

        date_header
    }

    fn insert_x509_headers(
        canonical_headers: &mut reqwest::header::HeaderMap,
        certificate: &reqwest::header::HeaderValue,
        chain: Option<&reqwest::header::HeaderValue>,
    ) {
        let x_amz_x509 = reqwest::header::HeaderName::from_static(header::X_AMZ_X509);
        canonical_headers.insert(x_amz_x509, certificate.clone());

        if let Some(chain) = chain {
            let x_amz_x509_chain =
                reqwest::header::HeaderName::from_static(header::X_AMZ_X509_CHAIN);
            canonical_headers.insert(x_amz_x509_chain, chain.clone());
        }
    }
}

impl<'a> std::fmt::Display for CanonicalRequest<'a> {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        writeln!(f, "{}", self.method)?;
        writeln!(f, "{}", self.path)?;

        // query params is omitted
        writeln!(f)?;

        // write out _all_ the headers
        for header in &self.values.signed_headers.headers {
            // a missing header is a bug, so we should panic.
            let value = &self.headers[&header.0];
            write!(f, "{}:", header.0.as_str())?;
            writeln!(
                f,
                "{}",
                std::str::from_utf8(value.as_bytes())
                    .expect("SDK request header values are valid UTF-8")
            )?;
        }
        writeln!(f)?;
        // write out the signed headers
        write!(f, "{}", self.values.signed_headers.as_str())?;
        writeln!(f)?;
        write!(f, "{}", self.values.content_sha256)?;
        Ok(())
    }
}

static MULTIPLE_SPACES: once_cell::sync::Lazy<regex::bytes::Regex> =
    once_cell::sync::Lazy::new(|| regex::bytes::Regex::new(r" {2,}").unwrap());

fn trim_all(text: &[u8]) -> std::borrow::Cow<'_, [u8]> {
    let text = trim_spaces_from_byte_string(text);
    MULTIPLE_SPACES.replace_all(text, " ".as_bytes())
}

fn trim_spaces_from_byte_string(bytes: &[u8]) -> &[u8] {
    let starting_index = bytes.iter().position(|b| *b != b' ').unwrap_or(0);
    let ending_offset = bytes.iter().rev().position(|b| *b != b' ').unwrap_or(0);
    let ending_index = bytes.len() - ending_offset;
    &bytes[starting_index..ending_index]
}

fn normalize_header_value(
    header_value: &reqwest::header::HeaderValue,
) -> reqwest::header::HeaderValue {
    let trimmed_value = trim_all(header_value.as_bytes());
    reqwest::header::HeaderValue::from_bytes(&trimmed_value).unwrap()
}

fn add_header(map: &mut reqwest::header::HeaderMap, key: &'static str, value: &str) {
    map.insert(
        key,
        reqwest::header::HeaderValue::try_from(value).expect(key),
    );
}

fn sha256_hex_string(body: &[u8]) -> String {
    use sha2::Digest as _;
    let hash = sha2::Sha256::digest(body);
    base16ct::lower::encode_string(&hash)
}

fn encode_x509_certificate(certificate: &pkcs8::der::Document) -> reqwest::header::HeaderValue {
    use base64ct::Encoding as _;
    reqwest::header::HeaderValue::try_from(base64ct::Base64::encode_string(certificate.as_ref()))
        .unwrap()
}

fn encode_x509_certificate_chain(
    chain: &[crate::certificate::ChainItem],
) -> reqwest::header::HeaderValue {
    use base64ct::Encoding as _;
    let value = chain
        .iter()
        .map(|item| base64ct::Base64::encode_string(item.der.as_ref()))
        .collect::<Vec<String>>()
        .join(",");
    reqwest::header::HeaderValue::try_from(value).unwrap()
}

/// Sign string_to_sign with a given key
pub fn x509_sign_string(
    private_key: &crate::identity::PrivateKey,
    string_to_sign: &[u8],
) -> Result<String, crate::error::Error> {
    use ecdsa::signature::RandomizedSigner as _;
    use sha2::Digest as _;

    let signature = match private_key {
        // RSA: go crypto/rsa.SignPKCS1v15
        //      RSASSA-PKCS1-V1_5-SIGN from RSA PKCS #1 v1.5
        //      https://datatracker.ietf.org/doc/html/rfc3447#section-8.2.1
        // Sign digest of sha256
        crate::identity::PrivateKey::Rsa(pkey) => {
            let digest_in = sha2::Sha256::digest(string_to_sign);
            let padding = rsa::PaddingScheme::new_pkcs1v15_sign(Some(rsa::hash::Hash::SHA2_256));
            pkey.sign_blinded(&mut rand::thread_rng(), padding, &digest_in)?
        }
        // ECDSA: Golang crypto/ecdsa.SignASN1. Always use SHA256 for hash function.
        // - While Golang uses randomness, we don't give rng here to align on the RustCrypto defaults
        crate::identity::PrivateKey::Ec(crate::identity::PrivateKeyEc::P256(pkey)) => {
            // SigningKey<P256> uses SHA256 so it can be performed straightforward.
            let signing_key = ecdsa::SigningKey::from(pkey);
            signing_key
                .try_sign_with_rng(&mut rand::thread_rng(), string_to_sign)?
                .to_der()
                .to_bytes()
                .to_vec()
        }
        crate::identity::PrivateKey::Ec(crate::identity::PrivateKeyEc::P384(pkey)) => {
            // both ecdsa and ring crate strictly bind SHA hash function having the same length to
            // EC curve... but AWS4_X509_ECDSA_SHA256 requires always sign a SHA256 digest
            let signing_key = ecdsa::SigningKey::from(pkey);
            let signature = crate::ecdsa_sha256::sign(signing_key, string_to_sign)?;
            signature.to_der().to_bytes().to_vec()
        }
    };

    Ok(base16ct::lower::encode_string(&signature))
}

fn build_authorization_header(
    algorithm: &'static str,
    serial_number: &str,
    creq: &CanonicalRequest<'_>,
    sts: StringToSign<'_>,
    signature: &str,
) -> reqwest::header::HeaderValue {
    let mut value = reqwest::header::HeaderValue::try_from(format!(
        "{} Credential={}/{}, SignedHeaders={}, Signature={}",
        algorithm,
        serial_number,
        sts.scope,
        creq.values.signed_headers.as_str(),
        signature
    ))
    .unwrap();
    value.set_sensitive(true);
    value
}

pub fn calculate_signing_headers<'a>(
    request: &'a SignableRequest<'a>,
    params: &'a SigningParams<'a>,
) -> Result<reqwest::header::HeaderMap, crate::error::Error> {
    let algorithm = match params.identity.private_key {
        crate::identity::PrivateKey::Rsa(_) => AWS4_X509_RSA_SHA256,
        crate::identity::PrivateKey::Ec(_) => AWS4_X509_ECDSA_SHA256,
    };

    let creq = CanonicalRequest::from(request, params)?;
    tracing::trace!(canonical_request = %creq);

    let encoded_creq = &sha256_hex_string(creq.to_string().as_bytes());
    let sts = StringToSign::new(
        algorithm,
        params.time,
        params.region,
        params.service_name,
        encoded_creq,
    );

    let signature = x509_sign_string(&params.identity.private_key, sts.to_string().as_bytes())?;

    let values = &creq.values;

    let mut headers = reqwest::header::HeaderMap::new();

    add_header(&mut headers, header::X_AMZ_DATE, &values.date_time);
    headers.insert(header::X_AMZ_X509, values.x509.clone());
    if let Some(x509_chain) = values.x509_chain.as_ref() {
        headers.insert(header::X_AMZ_X509_CHAIN, x509_chain.clone());
    }

    headers.insert(
        "authorization",
        build_authorization_header(
            algorithm,
            &params.identity.serial_number_string(),
            &creq,
            sts,
            &signature,
        ),
    );

    Ok(headers)
}

#[cfg(test)]
mod test {
    use super::*;
    use sha2::Digest as _;

    const KEY_RSA: &str = include_str!("../tests/examples/cert-key.pem");
    const SERIAL_RSA: &str = "337562787801933536189724934726614584366112857655";
    const CERT_RSA_SINGLE: &str = include_str!("../tests/examples/cert.pem");
    const CERT_RSA_CHAIN: &str = include_str!("../tests/examples/cert.chained.pem");

    const KEY_EC: &str = include_str!("../tests/examples/cert-ec-key.pem");
    const SERIAL_EC: &str = "35778190043212280460863094391048911229757758754";
    const CERT_EC_SINGLE: &str = include_str!("../tests/examples/cert-ec.pem");
    const CERT_EC_CHAIN: &str = include_str!("../tests/examples/cert-ec.chained.pem");

    const KEY_P384: &str = include_str!("../tests/examples/cert-p384-key.pem");
    const SERIAL_P384: &str = "272092831574453500899119014015178080991592167251";
    const CERT_P384_SINGLE: &str = include_str!("../tests/examples/cert-p384.pem");
    const CERT_P384_CHAIN: &str = include_str!("../tests/examples/cert-p384.chained.pem");

    const CERT_RSA_B64: &str = include_str!("../tests/examples/cert.der.b64");
    const CERT_EC_B64: &str = include_str!("../tests/examples/cert-ec.der.b64");
    const CERT_P384_B64: &str = include_str!("../tests/examples/cert-p384.der.b64");
    const CERT_SUBCA_B64: &str = include_str!("../tests/examples/subca.der.b64");

    const TEST_BODY: &str = "{\"foo\": 123}";
    const TEST_BODY_SHA256_HEX: &str =
        "8ae301e76251dfa937e27312e3f89be4941c49e2094f3dafe614ed3c8235fbf9";

    const TEST_REGION: &str = "us-east-1";
    const TEST_SERVICE: &str = "service";

    fn testing_timestamp() -> chrono::DateTime<chrono::Utc> {
        use chrono::TimeZone as _;
        chrono::Utc.ymd(2022, 8, 27).and_hms(1, 2, 3)
    }

    fn make_test_request() -> http::Request<bytes::Bytes> {
        http::Request::builder()
            .uri("https://service.test.invalid/api")
            .method(http::Method::POST)
            .header(http::header::CONTENT_TYPE, "application/json")
            .body(bytes::Bytes::from(TEST_BODY))
            .unwrap()
    }

    fn make_test_request_sign_data(
        alg: &str,
        cert_b64: &str,
    ) -> (String, sha2::digest::Output<sha2::Sha256VarCore>) {
        let creq = vec![
            "POST",
            "/api",
            "",
            "content-type:application/json",
            "host:service.test.invalid",
            "x-amz-date:20220827T010203Z",
            &format!("x-amz-x509:{}", cert_b64.trim_end()),
            &format!("x-amz-x509-chain:{}", CERT_SUBCA_B64.trim_end()),
            "",
            "content-type;host;x-amz-date;x-amz-x509;x-amz-x509-chain",
            TEST_BODY_SHA256_HEX,
        ]
        .join("\n");
        let hashed_creq = base16ct::lower::encode_string(&sha2::Sha256::digest(creq));

        let scope = format!("20220827/{}/{}/aws4_request", TEST_REGION, TEST_SERVICE);

        let sts = vec![alg, "20220827T010203Z", &scope, &hashed_creq].join("\n");
        let digest = sha2::Sha256::digest(sts);

        (scope, digest)
    }

    fn make_test_identity_rsa() -> crate::identity::Identity {
        let chain = crate::certificate::decode_pem_chain(CERT_RSA_SINGLE).unwrap();
        let source_key = crate::identity::PrivateKey::from_private_key_pem(KEY_RSA).unwrap();
        crate::identity::Identity::from_chain_and_key(&chain, source_key).unwrap()
    }

    fn make_test_identity_rsa_chain() -> crate::identity::Identity {
        let chain = crate::certificate::decode_pem_chain(CERT_RSA_CHAIN).unwrap();
        let source_key = crate::identity::PrivateKey::from_private_key_pem(KEY_RSA).unwrap();
        crate::identity::Identity::from_chain_and_key(&chain, source_key).unwrap()
    }

    fn make_test_identity_ec() -> crate::identity::Identity {
        let chain = crate::certificate::decode_pem_chain(CERT_EC_SINGLE).unwrap();
        let source_key = crate::identity::PrivateKey::from_private_key_pem(KEY_EC).unwrap();
        crate::identity::Identity::from_chain_and_key(&chain, source_key).unwrap()
    }

    fn make_test_identity_ec_chain() -> crate::identity::Identity {
        let chain = crate::certificate::decode_pem_chain(CERT_EC_CHAIN).unwrap();
        let source_key = crate::identity::PrivateKey::from_private_key_pem(KEY_EC).unwrap();
        crate::identity::Identity::from_chain_and_key(&chain, source_key).unwrap()
    }

    fn make_test_identity_p384_chain() -> crate::identity::Identity {
        let chain = crate::certificate::decode_pem_chain(CERT_P384_CHAIN).unwrap();
        let source_key = crate::identity::PrivateKey::from_private_key_pem(KEY_P384).unwrap();
        crate::identity::Identity::from_chain_and_key(&chain, source_key).unwrap()
    }

    fn make_test_signing_params(identity: &crate::identity::Identity) -> SigningParams {
        SigningParams {
            region: TEST_REGION,
            service_name: TEST_SERVICE,
            time: testing_timestamp(),
            identity,
        }
    }

    #[test]
    fn test_headers_rsa_single() {
        let identity = make_test_identity_rsa();
        let params = make_test_signing_params(&identity);
        let headers =
            calculate_signing_headers(&SignableRequest::from(&make_test_request()), &params)
                .unwrap();

        assert_eq!(
            headers
                .get("x-amz-x509")
                .map(|v| v.to_str().unwrap())
                .unwrap(),
            CERT_RSA_B64.trim_end()
        );
    }

    #[test]
    fn test_headers_rsa_chain() {
        let identity = make_test_identity_rsa_chain();
        let params = make_test_signing_params(&identity);
        let headers =
            calculate_signing_headers(&SignableRequest::from(&make_test_request()), &params)
                .unwrap();

        assert_eq!(
            headers
                .get("x-amz-x509")
                .map(|v| v.to_str().unwrap())
                .unwrap(),
            CERT_RSA_B64.trim_end()
        );
        assert_eq!(
            headers
                .get("x-amz-x509-chain")
                .map(|v| v.to_str().unwrap())
                .unwrap(),
            CERT_SUBCA_B64.trim_end(),
        );
    }

    #[test]
    fn test_headers_ec_single() {
        let identity = make_test_identity_ec();
        let params = make_test_signing_params(&identity);
        let headers =
            calculate_signing_headers(&SignableRequest::from(&make_test_request()), &params)
                .unwrap();

        assert_eq!(
            headers
                .get("x-amz-x509")
                .map(|v| v.to_str().unwrap())
                .unwrap(),
            CERT_EC_B64.trim_end()
        );
    }

    #[test]
    fn test_headers_ec_chain() {
        let identity = make_test_identity_ec_chain();
        let params = make_test_signing_params(&identity);
        let headers =
            calculate_signing_headers(&SignableRequest::from(&make_test_request()), &params)
                .unwrap();

        assert_eq!(
            headers
                .get("x-amz-x509")
                .map(|v| v.to_str().unwrap())
                .unwrap(),
            CERT_EC_B64.trim_end()
        );
        assert_eq!(
            headers
                .get("x-amz-x509-chain")
                .map(|v| v.to_str().unwrap())
                .unwrap(),
            CERT_SUBCA_B64.trim_end(),
        );
    }

    #[test]
    fn test_headers_chain_multi() {
        let source_chain1 = crate::certificate::decode_pem_chain(CERT_RSA_CHAIN).unwrap();
        let source_chain2 = crate::certificate::decode_pem_chain(CERT_EC_SINGLE).unwrap();
        let chain = vec![
            source_chain1[0].clone(),
            source_chain2[0].clone(),
            source_chain1[1].clone(),
        ];
        let source_key = crate::identity::PrivateKey::from_private_key_pem(KEY_RSA).unwrap();
        let identity = crate::identity::Identity::from_chain_and_key(&chain, source_key).unwrap();

        let params = make_test_signing_params(&identity);
        let headers =
            calculate_signing_headers(&SignableRequest::from(&make_test_request()), &params)
                .unwrap();

        assert_eq!(
            headers
                .get("x-amz-x509")
                .map(|v| v.to_str().unwrap())
                .unwrap(),
            CERT_RSA_B64.trim_end(),
        );
        assert_eq!(
            headers
                .get("x-amz-x509-chain")
                .map(|v| v.to_str().unwrap())
                .unwrap(),
            format!("{},{}", CERT_EC_B64.trim_end(), CERT_SUBCA_B64.trim_end())
        );
    }

    #[test]
    fn test_headers_date() {
        let identity = make_test_identity_rsa();
        let params = make_test_signing_params(&identity);
        let headers =
            calculate_signing_headers(&SignableRequest::from(&make_test_request()), &params)
                .unwrap();

        assert_eq!(
            headers
                .get("x-amz-date")
                .map(|v| v.to_str().unwrap())
                .unwrap(),
            "20220827T010203Z",
        );
    }

    #[test]
    fn test_signature_rsa() {
        let identity = make_test_identity_rsa_chain();
        let params = make_test_signing_params(&identity);
        let headers =
            calculate_signing_headers(&SignableRequest::from(&make_test_request()), &params)
                .unwrap();

        //let creq = vec![
        //    "POST",
        //    "/api",
        //    "",
        //    "content-type:application/json",
        //    "host:service.test.invalid",
        //    "x-amz-date:20220827T010203Z",
        //    &format!("x-amz-x509:{}", CERT_RSA_B64.trim_end()),
        //    &format!("x-amz-x509-chain:{}", CERT_SUBCA_B64.trim_end()),
        //    "",
        //    "content-type;host;x-amz-date;x-amz-x509;x-amz-x509-chain",
        //    TEST_BODY_SHA256_HEX,
        //]
        //.join("\n");
        //let hashed_creq = base16ct::lower::encode_string(&sha2::Sha256::digest(creq));

        let scope = format!("20220827/{}/{}/aws4_request", TEST_REGION, TEST_SERVICE);

        //let sts = vec![
        //    "AWS4-X509-RSA-SHA256",
        //    "20220827T010203Z",
        //    &scope,
        //    &hashed_creq,
        //]
        //.join("\n");
        //let digest = sha2::Sha256::digest(sts);

        let authorization = headers
            .get(reqwest::header::AUTHORIZATION)
            .map(|v| v.to_str().unwrap())
            .unwrap();
        assert!(
            authorization.starts_with(&format!("AWS4-X509-RSA-SHA256 Credential={}/{}, SignedHeaders=content-type;host;x-amz-date;x-amz-x509;x-amz-x509-chain, Signature=", SERIAL_RSA, scope))
        );
        let given_signature = authorization.rsplit("Signature=").next().unwrap();

        // RSA signature is deterministic
        // ``` ruby
        // require 'digest/sha2'
        // require 'openssl'
        // dgst = Digest::SHA256.digest(sts)
        // pk = OpenSSL::PKey::RSA.new(File.read('tests/examples/cert-key.pem'),'')
        // puts pk.sign_raw("SHA256", dgst, { rsa_padding_mode: 'pkcs1' }).unpack1('H*')
        // ```

        assert_eq!(
            given_signature,
            "7f18cf01a29af198006ce4294771b6c8204d5a8d811f1e707131d46e3465665a1f902c2060b28d07f4f7205fd81648585dc3e48ced6b1dc920e698142129985b569fdae3a55d8394a084960bf5362867161de68d43460ac027b7f614b7373597bf93545905051aa2ad062b8fdf452c736ee289e280dd375840b865fc1fc08b0ea6893385663c6171e61252b39777d190acb805cb6c05a790c495167d4d7360245c18858e2e541b6079e7d79c18d0618d283e6a26c1b870d74f3607c85086bb9aa39cecc0b1a1ad5e1bfeeaacbf052b7af8b23ced9142cc1c743b0b7f6fcee0ebfee41bd3ddb17f2985fbc028c0b19ebca79a1fb4e033e40ba410b1115fe7ebd1",
        );
    }

    #[test]
    fn test_signature_ec() {
        let identity = make_test_identity_ec_chain();
        let params = make_test_signing_params(&identity);
        let headers =
            calculate_signing_headers(&SignableRequest::from(&make_test_request()), &params)
                .unwrap();

        let (scope, digest) = make_test_request_sign_data("AWS4-X509-ECDSA-SHA256", CERT_EC_B64);

        let authorization = headers
            .get(reqwest::header::AUTHORIZATION)
            .map(|v| v.to_str().unwrap())
            .unwrap();
        assert!(
            authorization.starts_with(&format!("AWS4-X509-ECDSA-SHA256 Credential={}/{}, SignedHeaders=content-type;host;x-amz-date;x-amz-x509;x-amz-x509-chain, Signature=", SERIAL_EC, scope))
        );
        let given_signature_hex = authorization.rsplit("Signature=").next().unwrap();
        let given_signature_der = base16ct::lower::decode_vec(given_signature_hex).unwrap();
        println!("{}", given_signature_hex);

        // verify
        let cert_public_key = openssl::x509::X509::from_pem(CERT_EC_SINGLE.as_bytes())
            .unwrap()
            .public_key()
            .unwrap()
            .ec_key()
            .unwrap();
        let given_signature = openssl::ecdsa::EcdsaSig::from_der(&given_signature_der).unwrap();
        println!("{:}", given_signature.r().to_hex_str().unwrap());
        println!("{:}", given_signature.s().to_hex_str().unwrap());
        assert!(given_signature.verify(&digest, &cert_public_key).unwrap());
    }

    #[test]
    fn test_signature_p384() {
        let identity = make_test_identity_p384_chain();
        let params = make_test_signing_params(&identity);
        let headers =
            calculate_signing_headers(&SignableRequest::from(&make_test_request()), &params)
                .unwrap();

        let (scope, digest) = make_test_request_sign_data("AWS4-X509-ECDSA-SHA256", CERT_P384_B64);

        let authorization = headers
            .get(reqwest::header::AUTHORIZATION)
            .map(|v| v.to_str().unwrap())
            .unwrap();
        assert!(
            authorization.starts_with(&format!("AWS4-X509-ECDSA-SHA256 Credential={}/{}, SignedHeaders=content-type;host;x-amz-date;x-amz-x509;x-amz-x509-chain, Signature=", SERIAL_P384, scope))
        );
        let given_signature_hex = authorization.rsplit("Signature=").next().unwrap();
        let given_signature_der = base16ct::lower::decode_vec(given_signature_hex).unwrap();
        println!("{}", given_signature_hex);

        // verify
        let cert_public_key = openssl::x509::X509::from_pem(CERT_P384_SINGLE.as_bytes())
            .unwrap()
            .public_key()
            .unwrap()
            .ec_key()
            .unwrap();
        let given_signature = openssl::ecdsa::EcdsaSig::from_der(&given_signature_der).unwrap();
        println!("{:}", given_signature.r().to_hex_str().unwrap());
        println!("{:}", given_signature.s().to_hex_str().unwrap());
        assert!(given_signature.verify(&digest, &cert_public_key).unwrap());
    }
}
