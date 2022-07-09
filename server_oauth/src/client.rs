use std::sync::Arc;

use oauth2::basic::{BasicClient, BasicErrorResponse, BasicErrorResponseType, BasicTokenType};
use oauth2::reqwest::async_http_client;
use oauth2::{
    AuthUrl, AuthorizationCode, ClientId, ClientSecret, EmptyExtraTokenFields, RedirectUrl,
    RequestTokenError, StandardErrorResponse, StandardTokenResponse, TokenUrl,
};
use once_cell::sync::OnceCell;
use server_config::Config;

use crate::response::{SpecialClient, SpecialTokenResponse};

static INVITE_OAUTH_CLIENT: OnceCell<SpecialClient> = OnceCell::new();
static VERIFY_OAUTH_CLIENT: OnceCell<BasicClient> = OnceCell::new();

pub fn init_oauth_clients(cfg: Arc<Config>) {
    let client_id = cfg.oauth.client_id;
    let client_secret = &cfg.oauth.client_secret;

    // this is where config diverges
    let invite_auth_url = format!(
        "https://discord.com/api/oauth2/authorize?client_id={}&permissions={}&response_type=code",
        client_id, cfg.oauth.permissions,
    );
    let invite_redirect_url = format!("{}/oauth/callback/discord/invite", cfg.host);
    let verify_auth_url = format!(
        "https://discord.com/api/oauth2/authorize?client_id={}&response_type=code",
        client_id,
    );
    let verify_redirect_url = format!("{}/oauth/callback/discord/verify", cfg.host);

    let invite_client = SpecialClient::new(
        ClientId::new(client_id.to_string()),
        Some(ClientSecret::new(client_secret.clone())),
        AuthUrl::new(invite_auth_url).unwrap(),
        Some(TokenUrl::new("https://discord.com/api/oauth2/token".to_string()).unwrap()),
    )
    .set_redirect_uri(RedirectUrl::new(invite_redirect_url).unwrap());
    INVITE_OAUTH_CLIENT
        .set(invite_client)
        .unwrap_or_else(|_| panic!("don't init oauth more than once"));

    let verify_client = BasicClient::new(
        ClientId::new(client_id.to_string()),
        Some(ClientSecret::new(client_secret.clone())),
        AuthUrl::new(verify_auth_url).unwrap(),
        Some(TokenUrl::new("https://discord.com/api/oauth2/token".to_string()).unwrap()),
    )
    .set_redirect_uri(RedirectUrl::new(verify_redirect_url).unwrap());
    VERIFY_OAUTH_CLIENT
        .set(verify_client)
        .unwrap_or_else(|_| panic!("don't init oauth more than once"));
}

pub fn get_invite_client() -> &'static SpecialClient {
    INVITE_OAUTH_CLIENT
        .get()
        .expect("call `init_oauth_clients()` before trying to get the client")
}

pub fn get_verify_client() -> &'static BasicClient {
    VERIFY_OAUTH_CLIENT
        .get()
        .expect("call `init_oauth_clients()` before trying to get the client")
}

pub async fn exchange_code_invite<RE, T>(
    code: String,
) -> Result<
    SpecialTokenResponse,
    RequestTokenError<
        oauth2::reqwest::Error<reqwest::Error>,
        StandardErrorResponse<BasicErrorResponseType>,
    >,
> {
    get_invite_client()
        .exchange_code(AuthorizationCode::new(code))
        .request_async(async_http_client)
        .await
}

pub async fn exchange_code_verify(
    code: String,
) -> Result<
    StandardTokenResponse<EmptyExtraTokenFields, BasicTokenType>,
    RequestTokenError<
        oauth2::reqwest::Error<reqwest::Error>,
        StandardErrorResponse<BasicErrorResponseType>,
    >,
> {
    get_verify_client()
        .exchange_code(AuthorizationCode::new(code))
        .request_async(async_http_client)
        .await
}
