#[derive(Serialize, Deserialize)]
pub struct Config {
    pub oauth: OAuth2Config,
    pub host: String,
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

#[cfg(test)]
mod tests {
    #[test]
    fn test_deserialization() {
        toml::from_str(include_str!("../../config.example.toml"))
            .expect("failed to deserialize sample config");
    }
}
