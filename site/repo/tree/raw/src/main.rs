use anyhow::Result;

#[tokio::main]
async fn main() -> Result<()> {
    gossip_protocol::cli::run().await
}
