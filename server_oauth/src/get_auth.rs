use oauth2::url::Url;
use oauth2::{CsrfToken, Scope};

use crate::client::{get_invite_client, get_verify_client};

pub fn get_auth_url_and_token_invite() -> (Url, CsrfToken) {
    get_invite_client()
        .authorize_url(CsrfToken::new_random)
        .add_scopes(
            server_config::get_cfg()
                .oauth
                .invite_scopes
                .iter()
                .map(|x| Scope::new(x.clone())),
        )
        .add_extra_param("auth_type", "invite")
        .url()
}

pub fn get_auth_url_and_token_verify() -> (Url, CsrfToken) {
    get_verify_client()
        .authorize_url(CsrfToken::new_random)
        .add_scopes(
            server_config::get_cfg()
                .oauth
                .verify_scopes
                .iter()
                .map(|x| Scope::new(x.clone())),
        )
        .add_extra_param("auth_type", "verify")
        .url()
}
