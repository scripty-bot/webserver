use std::path::Path;

use serde::{Deserialize, Serialize};

#[derive(Serialize, Deserialize)]
pub struct Config {
    pub oauth: OAuth2Config,
    pub host: String,
    pub port: u16,
}

#[derive(Serialize, Deserialize)]
pub struct OAuth2Config {
    /// Your Discord client ID
    pub client_id: u64,
    /// Your Discord client secret
    pub client_secret: String,
    /// Required permissions for inviting the bot
    pub permissions: u64,
    /// A list of scopes that should be requested upon invite
    pub invite_scopes: Vec<String>,
    /// A list of scopes that should be requested when verifying
    pub verify_scopes: Vec<String>,
}

pub fn read_config<P>(path: P) -> Config
where
    P: AsRef<Path>,
{
    let data = std::fs::read_to_string(path).expect("Failed to read config!");
    toml::from_str::<Config>(&data).expect("failed to deserialize sample config")
}

#[cfg(test)]
mod tests {
    use crate::Config;

    #[test]
    fn test_deserialization() {
        toml::from_str::<Config>(include_str!("../../config.example.toml"))
            .expect("failed to deserialize sample config");
    }
}
