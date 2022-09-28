#[derive(clap::Args)]
pub struct BindArgs {
    #[clap(value_parser)]
    /// Name of a role binding to create
    ///
    /// Cannot contain `.` and `/`.
    name: String,
    /// Path to a certificate file in PEM
    ///
    /// Certificates with RSA, P-256, or P-384 key are supported.
    ///
    /// A certificate file may include intermediate CA certificate(s); informally known as fullchain.pem.
    /// Or you may give this option multiple times to specify CA certificate(s).
    #[clap(long, min_values = 1)]
    certificate: Vec<String>,
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
    /// Session duration in seconds
    ///
    /// Default and maximum 3600 seconds (1 hour) and 900 seconds minimum.
    #[clap(long)]
    session_duration: Option<u32>,
    /// Session name for AssumeRole; optional
    #[clap(long)]
    session_name: Option<String>,

    /// Skip validation before save; Default to false
    #[clap(long, action = clap::ArgAction::SetTrue)]
    no_validate: bool,

    /// Mode to use; default to ecs-full
    #[clap(arg_enum, long)]
    mode: Option<EnvironmentModeArg>,

    /// AWS region to use during validation; optional
    #[clap(long)]
    region: Option<String>,
}

#[derive(Clone, Debug, clap::ValueEnum)]
pub enum EnvironmentModeArg {
    EcsFull,
    EcsRelative,
}

impl EnvironmentModeArg {
    fn with_opts(&self, opts: crate::binding::EnvironmentOpts) -> crate::binding::EnvironmentMode {
        match self {
            EnvironmentModeArg::EcsFull => crate::binding::EnvironmentMode::EcsFull(opts),
            EnvironmentModeArg::EcsRelative => crate::binding::EnvironmentMode::EcsRelative(opts),
        }
    }
}

#[tokio::main]
pub async fn run(config: &crate::config::Config, args: &BindArgs) -> Result<(), anyhow::Error> {
    let req = crate::client::CreateSessionRequest {
        role_arn: args.role_arn.clone(),
        profile_arn: args.profile_arn.clone(),
        trust_anchor_arn: args.trust_anchor_arn.clone(),
        duration_seconds: args.session_duration.map(|v| v.into()),
        session_name: args.session_name.clone(),
    };

    let env_opts = crate::binding::EnvironmentOpts::default();
    let env_mode = match args.mode {
        Some(ref ma) => ma.with_opts(env_opts),
        None => crate::binding::EnvironmentMode::EcsFull(env_opts),
    };

    let binding = crate::binding::RoleBinding::new(
        args.name.clone(),
        args.certificate.clone(),
        args.private_key.clone(),
        env_mode,
        req,
    )?;

    tracing::debug!(role_binding = ?binding);

    let validate = !args.no_validate;
    if validate {
        tracing::info!("Validation");
        let identity = binding.identity().await?;
        let client = crate::client::Client::new(args.region.as_ref().map(|v| v.as_ref()))?;
        client.create(&identity, &binding.request).await?;
    } else {
        tracing::info!("Skipping validation");
    }

    binding.save(config).await?;

    Ok(())
}
