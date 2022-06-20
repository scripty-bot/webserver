//! Discord is shit and returns a different response for OAuth2 than defined in the RFC.
//!
//! This module contains this response type.
use std::time::Duration;

use oauth2::{
    basic::{
        BasicErrorResponse, BasicRevocationErrorResponse, BasicTokenIntrospectionResponse,
        BasicTokenType,
    },
    helpers::{deserialize_space_delimited_vec, serialize_space_delimited_vec},
    AccessToken, Client, EmptyExtraTokenFields, ExtraTokenFields, RefreshToken, Scope,
    StandardRevocableToken, TokenResponse, TokenType,
};

#[derive(Clone, Debug, Deserialize, Serialize)]
pub struct DiscordTokenResponse<EF> {
    access_token: AccessToken,
    token_type: BasicTokenType,
    expires_in: u64,
    refresh_token: RefreshToken,
    #[serde(rename = "scope")]
    #[serde(deserialize_with = "deserialize_space_delimited_vec")]
    #[serde(serialize_with = "serialize_space_delimited_vec")]
    #[serde(skip_serializing_if = "Option::is_none")]
    #[serde(default)]
    scopes: Option<Vec<Scope>>,

    guild: Guild,

    #[serde(bound = "EF: ExtraTokenFields")]
    #[serde(flatten)]
    extra_fields: EF,
}

#[derive(Clone, Debug, Deserialize, Serialize)]
pub struct Guild {
    pub name: String,
    pub owner_id: String,
    pub id: String,
    pub icon: Option<String>,
    pub preferred_locale: String,
}

pub type SpecialTokenResponse = DiscordTokenResponse<EmptyExtraTokenFields>;
pub type SpecialClient = Client<
    BasicErrorResponse,
    SpecialTokenResponse,
    BasicTokenType,
    BasicTokenIntrospectionResponse,
    StandardRevocableToken,
    BasicRevocationErrorResponse,
>;

impl<EF> TokenResponse<BasicTokenType> for DiscordTokenResponse<EF>
where
    EF: ExtraTokenFields,
    BasicTokenType: TokenType,
{
    fn access_token(&self) -> &AccessToken {
        &self.access_token
    }

    fn token_type(&self) -> &BasicTokenType {
        &self.token_type
    }

    fn expires_in(&self) -> Option<Duration> {
        Some(Duration::from_secs(self.expires_in))
    }

    fn refresh_token(&self) -> Option<&RefreshToken> {
        Some(&self.refresh_token)
    }

    fn scopes(&self) -> Option<&Vec<Scope>> {
        self.scopes.as_ref()
    }
}

impl<EF> DiscordTokenResponse<EF> {
    /// Return the guild associated with this response.
    pub fn guild(&self) -> &Guild {
        &self.guild
    }
}
