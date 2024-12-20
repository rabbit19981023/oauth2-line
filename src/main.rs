use axum::{
    extract::Query,
    response::{Html, IntoResponse, Redirect},
    routing::get,
    Router,
};
use dotenv::dotenv;
use oauth2::{
    basic::BasicClient, AuthUrl, AuthorizationCode, ClientId, ClientSecret, CsrfToken, RedirectUrl,
    Scope, TokenResponse, TokenUrl,
};
use serde::Deserialize;
use std::env;
use tokio::net::TcpListener;
use tower_http::trace::{DefaultMakeSpan, DefaultOnRequest, DefaultOnResponse, TraceLayer};
use tracing::Level;

#[tokio::main]
async fn main() {
    dotenv().ok();
    tracing_subscriber::fmt::init();

    let app = Router::new()
        .route("/", get(index))
        .route("/auth/line", get(line_auth))
        .route("/auth/line/callback", get(line_callback))
        .layer(
            TraceLayer::new_for_http()
                .make_span_with(DefaultMakeSpan::new().level(Level::INFO))
                .on_request(DefaultOnRequest::new().level(Level::INFO))
                .on_response(DefaultOnResponse::new().level(Level::INFO)),
        );

    let addr = env::var("SERVER_ADDR").unwrap();
    let listener = TcpListener::bind(&addr).await.unwrap();

    tracing::info!("Listening on http://{}", addr);
    axum::serve(listener, app).await.unwrap();
}

async fn index() -> impl IntoResponse {
    Html(
        r#"
            <h1>Line OAuth Example</h1>
            <a href="/auth/line">Login with Line</a>
        "#,
    )
}

#[derive(Deserialize)]
struct AuthRequest {
    code: String,
    state: String,
}

async fn line_auth() -> impl IntoResponse {
    let client = create_oauth_client();

    let (auth_url, _csrf_token) = client
        .authorize_url(CsrfToken::new_random)
        .add_scope(Scope::new("profile".to_string()))
        .add_scope(Scope::new("openid".to_string()))
        .url();

    Redirect::to(auth_url.as_str())
}

async fn line_callback(Query(params): Query<AuthRequest>) -> impl IntoResponse {
    let client = create_oauth_client();

    let token_result = client
        .exchange_code(AuthorizationCode::new(params.code))
        .request_async(oauth2::reqwest::async_http_client)
        .await;

    match token_result {
        Ok(token) => {
            let client = reqwest::Client::new();
            let profile_response = client
                .get(env::var("LINE_API_PROFILE").unwrap())
                .bearer_auth(token.access_token().secret())
                .send()
                .await;

            match profile_response {
                Ok(response) => {
                    let profile = response.json::<serde_json::Value>().await.unwrap();
                    Html(format!(
                        r#"
                            <h1>Authentication Successful!</h1>
                            <pre>{}</pre>
                            <a href="/">Back to home</a>
                        "#,
                        serde_json::to_string_pretty(&profile).unwrap()
                    ))
                }
                Err(e) => Html(format!("<h1>Error fetching profile: {}</h1>", e)),
            }
        }
        Err(e) => Html(format!("<h1>Authentication Error: {}</h1>", e)),
    }
}

fn create_oauth_client() -> BasicClient {
    let client_id = ClientId::new(env::var("LINE_CHANNEL_ID").unwrap());
    let client_secret = ClientSecret::new(env::var("LINE_CHANNEL_SECRET").unwrap());
    let redirect_url = RedirectUrl::new(env::var("REDIRECT_URL").unwrap()).unwrap();

    BasicClient::new(
        client_id,
        Some(client_secret),
        AuthUrl::new(env::var("LINE_API_AUTHORIZE").unwrap()).unwrap(),
        Some(TokenUrl::new(env::var("LINE_API_TOKEN").unwrap()).unwrap()),
    )
    .set_redirect_uri(redirect_url)
}
