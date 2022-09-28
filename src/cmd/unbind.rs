#[derive(clap::Args)]
pub struct UnbindArgs {
    #[clap(value_parser)]
    /// Name of a role binding to remove
    ///
    /// Cannot contain `.` and `/`.
    name: String,
}

#[tokio::main]
pub async fn run(config: &crate::config::Config, args: &UnbindArgs) -> Result<(), anyhow::Error> {
    let binding = crate::binding::RoleBinding::load(config, &args.name).await?;
    tracing::debug!(role_binding = ?binding);
    binding.remove(config).await?;
    Ok(())
}
