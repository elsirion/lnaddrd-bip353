use anyhow::Result;
use clap::Parser;
use lnaddrd::config::Config;
use lnaddrd::dns::DnsServer;
use tracing_subscriber;

#[tokio::main]
async fn main() -> Result<()> {
    tracing_subscriber::fmt::init();
    let config = Config::parse();

    let server = DnsServer::new(config)?;
    server.run().await?;

    Ok(())
}
