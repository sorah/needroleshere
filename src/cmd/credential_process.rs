#[derive(clap::Args)]
pub struct CredentialProcessArgs {
    /// Path to a certificate file in PEM
    ///
    /// Certificates with RSA, P-256, or P-384 key are supported.
    /// A certificate file may include intermediate CA certificate(s); informally known as fullchain.pem.
    #[clap(long)]
    certificate: String, // TODO: make this Vec
    /// Path to a private key in PEM corresponding to a certificate
    #[clap(long)]
    private_key: String,
    /// Profile ARN of AWS Roles Anywhere
    #[clap(long)]
    profile_arn: String,
    /// Trust Anchor ARN of AWS Roles Anywhere
    #[clap(long)]
    trust_anchor_arn: String,
    /// IAM Role ARN to assume
    #[clap(long)]
    role_arn: String,
    /// AWS Region to use for IAM Roles Anywhere
    #[clap(long)]
    region: Option<String>,
    /// Session duration in seconds
    ///
    /// Default and maximum 3600 seconds (1 hour) and 900 seconds minimum.
    #[clap(long)]
    session_duration: Option<u32>,
    /// Path to a certificate file to include in x-amz-x509-chain (optional)
    ///
    /// can specify multiple times and a file may contain multiple certificates.
    #[clap(long)]
    intermediates: Vec<String>,
}

/// https://docs.aws.amazon.com/sdkref/latest/guide/feature-process-credentials.html
#[derive(Debug, serde::Serialize)]
#[serde(rename_all = "PascalCase")]
pub struct CredentialProcessResponse {
    pub version: i64,
    pub access_key_id: String,
    pub secret_access_key: crate::client::AwsSecretAccessKey,
    pub session_token: String,
    pub expiration: chrono::DateTime<chrono::Utc>,
}

#[tokio::main]
pub async fn run(args: &CredentialProcessArgs) -> Result<(), anyhow::Error> {
    let identity = crate::identity::Identity::from_key_and_cert_and_chain_files(
        &args.private_key,
        &args.certificate,
        &args
            .intermediates
            .iter()
            .map(|v| v.as_ref())
            .collect::<Vec<&str>>(),
    )
    .await?;

    let client = crate::client::Client::new(args.region.as_ref().map(|v| v.as_ref()))?;

    let session = client
        .create(
            &identity,
            &crate::client::CreateSessionRequest {
                duration_seconds: args.session_duration.map(|v| v.into()),
                profile_arn: args.profile_arn.clone(),
                role_arn: args.role_arn.clone(),
                session_name: None,
                trust_anchor_arn: args.trust_anchor_arn.clone(),
            },
        )
        .await?;

    let assumed_role = session
        .credential_set
        .get(0)
        .ok_or_else(|| anyhow::anyhow!("returned CredentialSet is missing item"))?;

    let result = CredentialProcessResponse {
        version: 1,
        access_key_id: assumed_role.credentials.access_key_id.clone(),
        secret_access_key: assumed_role.credentials.secret_access_key.clone(),
        session_token: assumed_role.credentials.session_token.clone(),
        expiration: assumed_role.credentials.expiration,
    };

    {
        serde_json::to_writer(std::io::stdout(), &result).unwrap();
    }
    Ok(())
}
