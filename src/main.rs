mod admin;
mod admin_ui;
mod anthropic;
mod common;
mod http_client;
mod kiro;
mod model;
pub mod token;

use std::collections::HashMap;
use std::path::{Path, PathBuf};
use std::sync::Arc;

use anyhow::Context;
use clap::Parser;
use kiro::cli_credentials;
use kiro::endpoint::{IdeEndpoint, KiroEndpoint};
use kiro::model::credentials::{CredentialsConfig, KiroCredentials};
use kiro::provider::KiroProvider;
use kiro::token_manager::MultiTokenManager;
use model::arg::Args;
use model::config::Config;

#[tokio::main]
async fn main() {
    // 解析命令行参数
    let args = Args::parse();

    // 初始化日志
    tracing_subscriber::fmt()
        .with_env_filter(
            tracing_subscriber::EnvFilter::try_from_default_env()
                .unwrap_or_else(|_| tracing_subscriber::EnvFilter::new("info")),
        )
        .init();

    let credentials_path = args
        .credentials
        .clone()
        .unwrap_or_else(|| KiroCredentials::default_credentials_path().to_string());
    let kiro_cli_db = args.kiro_cli_db.as_deref().map(PathBuf::from);

    if args.import_kiro_cli_credentials {
        if let Err(e) = import_kiro_cli_credentials(&credentials_path, kiro_cli_db.clone()) {
            tracing::error!("导入 Kiro CLI 凭据失败: {:#}", e);
            std::process::exit(1);
        }
        return;
    }

    // 加载配置
    let config_path = args
        .config
        .unwrap_or_else(|| Config::default_config_path().to_string());
    let config = Config::load(&config_path).unwrap_or_else(|e| {
        tracing::error!("加载配置失败: {}", e);
        std::process::exit(1);
    });

    // 加载凭证（支持单对象或数组格式）
    let mut credentials_config = CredentialsConfig::load(&credentials_path).unwrap_or_else(|e| {
        tracing::error!("加载凭证失败: {}", e);
        std::process::exit(1);
    });

    if credentials_config.is_empty() {
        match cli_credentials::detect_local_credentials_from(kiro_cli_db) {
            Ok(Some(detected)) => {
                tracing::info!(
                    "凭据文件为空或不存在，已从本机 Kiro CLI 登录数据库自动生成凭据: {}",
                    detected.db_path.display()
                );
                credentials_config = CredentialsConfig::Multiple(vec![detected.credentials]);
            }
            Ok(None) => {
                tracing::info!(
                    "凭据文件为空或不存在，且未检测到本机 Kiro CLI 登录数据库；如需自动检测可设置 KIRO_CLI_DB"
                );
            }
            Err(e) => {
                tracing::warn!("自动检测本机 Kiro CLI 凭据失败: {}", e);
            }
        }
    }

    // 判断是否为多凭据格式（用于刷新后回写）
    let is_multiple_format = credentials_config.is_multiple();

    // 转换为按优先级排序的凭据列表
    let mut credentials_list = credentials_config.into_sorted_credentials();

    // 检查 KIRO_API_KEY 环境变量，自动创建 API Key 凭据
    if let Ok(kiro_api_key) = std::env::var("KIRO_API_KEY") {
        if kiro_api_key.is_empty() {
            tracing::warn!("KIRO_API_KEY 环境变量已设置但为空，视为未配置");
        } else {
            tracing::info!("检测到 KIRO_API_KEY 环境变量，添加 API Key 凭据（最高优先级）");
            let api_key_cred = KiroCredentials {
                kiro_api_key: Some(kiro_api_key),
                auth_method: Some("api_key".to_string()),
                priority: 0,
                ..Default::default()
            };
            credentials_list.insert(0, api_key_cred);
        }
    }

    tracing::info!("已加载 {} 个凭据配置", credentials_list.len());

    // 获取第一个凭据用于日志显示
    let first_credentials = credentials_list.first().cloned().unwrap_or_default();
    tracing::debug!("主凭证: {:?}", first_credentials);

    // 获取 API Key
    let api_key = config.api_key.clone().unwrap_or_else(|| {
        tracing::error!("配置文件中未设置 apiKey");
        std::process::exit(1);
    });

    // 构建代理配置
    let proxy_config = config.proxy_url.as_ref().map(|url| {
        let mut proxy = http_client::ProxyConfig::new(url);
        if let (Some(username), Some(password)) = (&config.proxy_username, &config.proxy_password) {
            proxy = proxy.with_auth(username, password);
        }
        proxy
    });

    if proxy_config.is_some() {
        tracing::info!("已配置 HTTP 代理: {}", config.proxy_url.as_ref().unwrap());
    }

    // 构建端点注册表
    let mut endpoints: HashMap<String, Arc<dyn KiroEndpoint>> = HashMap::new();
    {
        let ide = IdeEndpoint::new();
        endpoints.insert(ide.name().to_string(), Arc::new(ide));
    }

    // 校验默认端点存在
    if !endpoints.contains_key(&config.default_endpoint) {
        tracing::error!("默认端点 \"{}\" 未注册", config.default_endpoint);
        std::process::exit(1);
    }

    // 校验所有凭据声明的端点都已注册
    for cred in &credentials_list {
        let name = cred
            .endpoint
            .as_deref()
            .unwrap_or(&config.default_endpoint);
        if !endpoints.contains_key(name) {
            tracing::error!(
                "凭据 id={:?} 指定了未知端点 \"{}\"（已注册: {:?}）",
                cred.id,
                name,
                endpoints.keys().collect::<Vec<_>>()
            );
            std::process::exit(1);
        }
    }

    let endpoint_names: Vec<String> = endpoints.keys().cloned().collect();

    // 创建 MultiTokenManager 和 KiroProvider
    let token_manager = MultiTokenManager::new(
        config.clone(),
        credentials_list,
        proxy_config.clone(),
        Some(credentials_path.into()),
        is_multiple_format,
    )
    .unwrap_or_else(|e| {
        tracing::error!("创建 Token 管理器失败: {}", e);
        std::process::exit(1);
    });
    let token_manager = Arc::new(token_manager);
    let kiro_provider = KiroProvider::with_proxy(
        token_manager.clone(),
        proxy_config.clone(),
        endpoints,
        config.default_endpoint.clone(),
    );

    // 初始化 count_tokens 配置
    token::init_config(token::CountTokensConfig {
        api_url: config.count_tokens_api_url.clone(),
        api_key: config.count_tokens_api_key.clone(),
        auth_type: config.count_tokens_auth_type.clone(),
        proxy: proxy_config,
        tls_backend: config.tls_backend,
    });

    // 构建 Anthropic API 路由（profile_arn 由 provider 层根据实际凭据动态注入）
    let anthropic_app = anthropic::create_router_with_provider(
        &api_key,
        Some(kiro_provider),
        config.extract_thinking,
    );

    // 构建 Admin API 路由（如果配置了非空的 admin_api_key）
    // 安全检查：空字符串被视为未配置，防止空 key 绕过认证
    let admin_key_valid = config
        .admin_api_key
        .as_ref()
        .map(|k| !k.trim().is_empty())
        .unwrap_or(false);

    let app = if let Some(admin_key) = &config.admin_api_key {
        if admin_key.trim().is_empty() {
            tracing::warn!("admin_api_key 配置为空，Admin API 未启用");
            anthropic_app
        } else {
            let admin_service =
                admin::AdminService::new(token_manager.clone(), endpoint_names.clone());
            let admin_state = admin::AdminState::new(admin_key, admin_service);
            let admin_app = admin::create_admin_router(admin_state);

            // 创建 Admin UI 路由
            let admin_ui_app = admin_ui::create_admin_ui_router();

            tracing::info!("Admin API 已启用");
            tracing::info!("Admin UI 已启用: /admin");
            anthropic_app
                .nest("/api/admin", admin_app)
                .nest("/admin", admin_ui_app)
        }
    } else {
        anthropic_app
    };

    // 启动服务器
    let addr = format!("{}:{}", config.host, config.port);
    tracing::info!("启动 Anthropic API 端点: {}", addr);
    tracing::info!("API Key: {}***", &api_key[..(api_key.len() / 2)]);
    tracing::info!("可用 API:");
    tracing::info!("  GET  /v1/models");
    tracing::info!("  POST /v1/messages");
    tracing::info!("  POST /v1/messages/count_tokens");
    if admin_key_valid {
        tracing::info!("Admin API:");
        tracing::info!("  GET  /api/admin/credentials");
        tracing::info!("  POST /api/admin/credentials/:index/disabled");
        tracing::info!("  POST /api/admin/credentials/:index/priority");
        tracing::info!("  POST /api/admin/credentials/:index/reset");
        tracing::info!("  GET  /api/admin/credentials/:index/balance");
        tracing::info!("Admin UI:");
        tracing::info!("  GET  /admin");
    }

    let listener = tokio::net::TcpListener::bind(&addr).await.unwrap();
    axum::serve(listener, app).await.unwrap();
}

fn import_kiro_cli_credentials(
    credentials_path: &str,
    kiro_cli_db: Option<PathBuf>,
) -> anyhow::Result<()> {
    let detected = cli_credentials::detect_local_credentials_from(kiro_cli_db)?
        .context("未检测到可导入的 Kiro CLI 登录凭据；可用 --kiro-cli-db 或 KIRO_CLI_DB 指定数据库路径")?;

    let mut credentials = match CredentialsConfig::load(credentials_path)
        .with_context(|| format!("加载凭据文件失败: {}", credentials_path))?
    {
        CredentialsConfig::Single(credential) => vec![credential],
        CredentialsConfig::Multiple(credentials) => credentials,
    };

    if credentials
        .iter()
        .any(|credential| same_credential(credential, &detected.credentials))
    {
        tracing::info!(
            "当前 Kiro CLI 登录凭据已存在于 {}，跳过重复导入",
            credentials_path
        );
        return Ok(());
    }

    credentials.push(detected.credentials);
    save_credentials_list(credentials_path, &credentials)?;

    tracing::info!(
        "已从 {} 导入当前 Kiro CLI 登录凭据到 {}",
        detected.db_path.display(),
        credentials_path
    );
    Ok(())
}

fn same_credential(left: &KiroCredentials, right: &KiroCredentials) -> bool {
    same_non_empty_value(&left.refresh_token, &right.refresh_token)
}

fn same_non_empty_value(left: &Option<String>, right: &Option<String>) -> bool {
    match (left.as_deref(), right.as_deref()) {
        (Some(left), Some(right)) => {
            let left = left.trim();
            let right = right.trim();
            !left.is_empty() && left == right
        }
        _ => false,
    }
}

fn save_credentials_list<P: AsRef<Path>>(
    credentials_path: P,
    credentials: &[KiroCredentials],
) -> anyhow::Result<()> {
    let credentials_path = credentials_path.as_ref();
    if let Some(parent) = credentials_path.parent().filter(|p| !p.as_os_str().is_empty()) {
        std::fs::create_dir_all(parent)
            .with_context(|| format!("创建凭据目录失败: {}", parent.display()))?;
    }

    let json = serde_json::to_string_pretty(credentials).context("序列化凭据失败")?;
    std::fs::write(credentials_path, json)
        .with_context(|| format!("写入凭据文件失败: {}", credentials_path.display()))?;
    Ok(())
}
