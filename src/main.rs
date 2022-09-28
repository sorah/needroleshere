#[derive(clap::Parser)]
#[clap(author, version, long_about = None)]
#[clap(about = "Yet Another rolesanywhere-credential-helper")]
#[clap(propagate_version = true)]
struct Cli {
    /// Base URL where a Needroleshere server is listening to
    #[clap(long, global = true)]
    url: Option<String>,

    /// Configuration directory. Default to $RUNTIME_DIRECTORY
    #[clap(long, global = true)]
    configuration_directory: Option<String>,

    #[clap(subcommand)]
    command: Commands,
}

#[derive(clap::Subcommand)]
enum Commands {
    /// Run as a credential_process program; Compatible with original helper
    CredentialProcess(needroleshere::cmd::credential_process::CredentialProcessArgs),
    /// Create or update a role binding
    Bind(needroleshere::cmd::bind::BindArgs),
    /// Delete a role binding
    Unbind(needroleshere::cmd::unbind::UnbindArgs),
}

impl TryInto<needroleshere::config::Config> for &Cli {
    type Error = needroleshere::error::Error;

    fn try_into(self) -> Result<needroleshere::config::Config, Self::Error> {
        needroleshere::config::Config::new(
            self.configuration_directory.clone().map(|v| v.into()),
            needroleshere::config::ConfigData {
                url: self.url.clone(),
            },
        )
    }
}

fn main() -> Result<(), anyhow::Error> {
    use clap::Parser;
    let cli = Cli::parse();

    match &cli.command {
        Commands::CredentialProcess(params) => {
            enable_tracing(true);
            needroleshere::cmd::credential_process::run(params)?;
        }
        Commands::Bind(params) => {
            enable_tracing(false);
            needroleshere::cmd::bind::run(&(&cli).try_into()?, params)?;
        }
        Commands::Unbind(params) => {
            enable_tracing(false);
            needroleshere::cmd::unbind::run(&(&cli).try_into()?, params)?;
        }
    };
    Ok(())
}

fn enable_tracing(stderr: bool) {
    if stderr {
        tracing_subscriber::fmt()
            .with_writer(std::io::stderr)
            .with_env_filter(tracing_subscriber::EnvFilter::from_default_env())
            .init();
    } else {
        tracing_subscriber::fmt::init();
    }
}
