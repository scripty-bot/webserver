use std::sync::Arc;

use oauth2::url::Url;
use oauth2::{CsrfToken, Scope};
use server_config::Config;

use crate::client::{get_invite_client, get_verify_client};

pub fn get_auth_url_and_token_invite(config: Arc<Config>) -> (Url, CsrfToken) {
    get_invite_client()
        .authorize_url(CsrfToken::new_random)
        .add_scopes(
            config
                .oauth
                .invite_scopes
                .iter()
                .map(|x| Scope::new(x.clone())),
        )
        .add_extra_param("auth_type", "invite")
        .url()
}

pub fn get_auth_url_and_token_verify(config: Arc<Config>) -> (Url, CsrfToken) {
    get_verify_client()
        .authorize_url(CsrfToken::new_random)
        .add_scopes(
            config
                .oauth
                .verify_scopes
                .iter()
                .map(|x| Scope::new(x.clone())),
        )
        .add_extra_param("auth_type", "verify")
        .url()
}
