use clap::Parser;

/// Anthropic <-> Kiro API 客户端
#[derive(Parser, Debug)]
#[command(version, about, long_about = None)]
pub struct Args {
    /// 配置文件路径
    #[arg(short, long)]
    pub config: Option<String>,

    /// 凭证文件路径
    #[arg(long)]
    pub credentials: Option<String>,

    /// Import credentials from the local Kiro CLI login database, then exit.
    #[arg(long)]
    pub import_kiro_cli_credentials: bool,

    /// Override the Kiro CLI SQLite database path.
    #[arg(long)]
    pub kiro_cli_db: Option<String>,
}
