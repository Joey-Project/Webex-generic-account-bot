use std::{
    env,
    path::{Path, PathBuf},
    sync::Arc,
};

use anyhow::{Result, anyhow};
use async_trait::async_trait;
use webex_headless_messenger::{AccessTokenProvider, TokenSet, WebexClient};

use crate::config::WebexAuthConfig;

#[derive(Debug, Clone)]
pub enum TokenSource {
    Env(String),
    File(PathBuf),
}

#[derive(Debug, Clone)]
pub struct ReloadingAccessTokenProvider {
    source: TokenSource,
}

impl ReloadingAccessTokenProvider {
    pub fn from_config(config: &WebexAuthConfig) -> Result<Self> {
        if let Some(path) = &config.access_token_file {
            return Ok(Self {
                source: TokenSource::File(path.clone()),
            });
        }
        if let Ok(path) = env::var(&config.access_token_file_env) {
            if !path.trim().is_empty() {
                return Ok(Self {
                    source: TokenSource::File(PathBuf::from(path)),
                });
            }
        }
        if let Ok(token) = env::var(&config.access_token_env) {
            if !token.trim().is_empty() {
                return Ok(Self {
                    source: TokenSource::Env(token),
                });
            }
        }
        Err(anyhow!(
            "set {}, {}, or webex.access_token_file",
            config.access_token_env,
            config.access_token_file_env
        ))
    }
}

#[async_trait]
impl AccessTokenProvider for ReloadingAccessTokenProvider {
    async fn access_token(&self) -> webex_headless_messenger::Result<String> {
        match &self.source {
            TokenSource::Env(token) => Ok(token.trim().to_owned()),
            TokenSource::File(path) => load_access_token_file(path).map_err(|error| {
                webex_headless_messenger::Error::Other(format!(
                    "failed to load access token file {}: {error}",
                    path.display()
                ))
            }),
        }
    }
}

pub fn build_webex_client(config: &WebexAuthConfig) -> Result<WebexClient> {
    let provider = ReloadingAccessTokenProvider::from_config(config)?;
    Ok(WebexClient::builder()?
        .token_provider(Arc::new(provider))
        .build()?)
}

fn load_access_token_file(path: &Path) -> Result<String> {
    let raw = std::fs::read_to_string(path)?;
    let trimmed = raw.trim();
    if trimmed.is_empty() {
        return Err(anyhow!("access token file is empty"));
    }
    if !trimmed.starts_with('{') {
        return Ok(trimmed.to_owned());
    }

    let token_set: TokenSet = serde_json::from_str(trimmed)?;
    let token = token_set.access_token.trim();
    if token.is_empty() {
        return Err(anyhow!("access token file JSON has an empty accessToken"));
    }
    Ok(token.to_owned())
}

#[cfg(test)]
mod tests {
    use std::{fs, time::SystemTime};

    use super::*;

    fn temp_path(name: &str) -> PathBuf {
        std::env::temp_dir().join(format!(
            "webex-generic-account-bot-{name}-{}",
            SystemTime::now()
                .duration_since(SystemTime::UNIX_EPOCH)
                .unwrap()
                .as_nanos()
        ))
    }

    #[test]
    fn loads_raw_access_token_file() {
        let path = temp_path("raw-token");
        fs::write(&path, "raw-token\n").unwrap();

        assert_eq!(load_access_token_file(&path).unwrap(), "raw-token");

        let _ = fs::remove_file(path);
    }

    #[test]
    fn loads_token_set_json_file() {
        let path = temp_path("json-token");
        fs::write(
            &path,
            serde_json::to_string(&TokenSet {
                access_token: " json-token\n".to_owned(),
                refresh_token: None,
                token_type: "Bearer".to_owned(),
                scopes: Vec::new(),
                expires_at: None,
                refresh_token_expires_at: None,
            })
            .unwrap(),
        )
        .unwrap();

        assert_eq!(load_access_token_file(&path).unwrap(), "json-token");

        let _ = fs::remove_file(path);
    }
}
