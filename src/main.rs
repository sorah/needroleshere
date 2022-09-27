#[derive(clap::Parser)]
#[clap(author, version, long_about = None)]
#[clap(about = "Yet Another rolesanywhere-credential-helper")]
#[clap(propagate_version = true)]
struct Cli {
    #[clap(subcommand)]
    command: Commands,
}

#[derive(clap::Subcommand)]
enum Commands {
    /// Run as a credential_process program; Compatible with original helper
    CredentialProcess(needroleshere::cmd::credential_process::CredentialProcessArgs),
}

fn main() -> Result<(), anyhow::Error> {
    use clap::Parser;
    let cli = Cli::parse();

    match &cli.command {
        Commands::CredentialProcess(params) => {
            enable_tracing(true);
            needroleshere::cmd::credential_process::run(params)?
        }
    }
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
