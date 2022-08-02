use axum::extract::Query;
use axum::response::Response;
use axum::Form;
use axum_auth::AuthBasic;
use oidc_types::token_request::TokenRequest;

async fn token(auth: AuthBasic, query: Query<TokenRequest>, body: Form<TokenRequest>) -> Response {
    todo!()
}
