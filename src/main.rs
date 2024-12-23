use axum::{
    extract::{Query, State},
    response::{Html, IntoResponse, Redirect},
    routing::get,
    Router,
};
use axum_extra::extract::{cookie::Cookie, CookieJar};
use dotenv::dotenv;
use oauth2::{
    basic::BasicClient, AuthUrl, AuthorizationCode, ClientId, ClientSecret, CsrfToken, RedirectUrl,
    Scope, TokenResponse, TokenUrl,
};
use serde::{Deserialize, Serialize};
use std::{
    collections::HashMap,
    env,
    sync::{Arc, Mutex},
};
use tokio::net::TcpListener;
use tower_http::trace::{DefaultMakeSpan, DefaultOnRequest, DefaultOnResponse, TraceLayer};
use tracing::Level;
use uuid::Uuid;

#[derive(Clone, Default)]
struct AppState {
    sessions: Arc<Mutex<HashMap<SessionId, AuthState>>>,
}

type SessionId = String;

#[derive(Clone)]
struct AuthState {
    csrf_token: CsrfToken,
    profile: Option<Profile>,
    access_token: Option<String>,
    refresh_token: Option<String>,
}

#[derive(Clone, Serialize, Deserialize)]
#[serde(rename_all(serialize = "snake_case", deserialize = "camelCase"))]
struct Profile {
    user_id: String,
    display_name: String,
    picture_url: String,
    status_message: String,
}

#[derive(Deserialize)]
struct AuthRequest {
    code: String,
    state: String,
}

impl AppState {
    fn get_auth_state(&self, session_id: &str) -> Option<AuthState> {
        self.sessions.lock().unwrap().get(session_id).cloned()
    }

    fn set_auth_state(&self, session_id: String, auth_state: AuthState) {
        self.sessions.lock().unwrap().insert(session_id, auth_state);
    }
}

impl Default for AuthState {
    fn default() -> Self {
        Self {
            csrf_token: CsrfToken::new_random(),
            profile: None,
            access_token: None,
            refresh_token: None,
        }
    }
}

impl AuthState {
    fn set_tokens(&mut self, access_token: String, refresh_token: String) {
        self.access_token = Some(access_token);
        self.refresh_token = Some(refresh_token);
    }

    fn set_profile(&mut self, profile: Profile) {
        self.profile = Some(profile);
    }
}

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
        )
        .with_state(AppState::default());

    let addr = env::var("SERVER_ADDR").unwrap();
    let listener = TcpListener::bind(&addr).await.unwrap();

    tracing::info!("Listening on http://{}", addr);
    axum::serve(listener, app).await.unwrap();
}

async fn index(State(state): State<AppState>, jar: CookieJar) -> impl IntoResponse {
    let session_id = match jar.get("session_id") {
        Some(session_id) => session_id.value(),
        None => "",
    };

    match state.get_auth_state(session_id) {
        Some(auth_state) => {
            let profile = auth_state.profile.unwrap();

            Html(format!(
                r#"
                    <h1>You are logged in!</h1>
                    <pre>{}</pre>
                    <a href="/auth/line">Login with Line</a>
                "#,
                serde_json::to_string_pretty(&profile).unwrap(),
            ))
        }
        None => Html(
            r#"
                <h1>Line OAuth Example</h1>
                <a href="/auth/line">Login with Line</a>
            "#
            .to_string(),
        ),
    }
}

async fn line_auth(State(state): State<AppState>, jar: CookieJar) -> impl IntoResponse {
    let client = create_oauth_client();

    let session_id = Uuid::new_v4().to_string();
    let auth_state = AuthState::default();

    let (auth_url, _csrf_token) = client
        .authorize_url(|| auth_state.csrf_token.clone())
        .add_scope(Scope::new("profile".to_string()))
        .add_scope(Scope::new("openid".to_string()))
        .url();

    state.set_auth_state(session_id.clone(), auth_state);
    let updated_jar = jar.add(Cookie::build(("session_id", session_id)).path("/"));

    (updated_jar, Redirect::to(auth_url.as_str()))
}

async fn line_callback(
    State(state): State<AppState>,
    jar: CookieJar,
    Query(params): Query<AuthRequest>,
) -> impl IntoResponse {
    let session_id = jar.get("session_id").unwrap().value();
    let csrf_token = state
        .get_auth_state(session_id)
        .unwrap()
        .csrf_token
        .secret()
        .clone();

    if params.state != *csrf_token {
        return Html("<h1>Invalid state</h1>".to_string());
    }

    let client = create_oauth_client();

    let token_result = client
        .exchange_code(AuthorizationCode::new(params.code))
        .request_async(oauth2::reqwest::async_http_client)
        .await;

    match token_result {
        Ok(token) => {
            let mut auth_state = state.get_auth_state(session_id).unwrap();

            auth_state.set_tokens(
                token.access_token().secret().to_string(),
                token.refresh_token().unwrap().secret().to_string(),
            );

            let client = reqwest::Client::new();
            let profile_response = client
                .get(env::var("LINE_API_PROFILE").unwrap())
                .bearer_auth(token.access_token().secret())
                .send()
                .await;

            match profile_response {
                Ok(response) => {
                    let profile: Profile = response.json().await.unwrap();

                    auth_state.set_profile(profile.clone());
                    state.set_auth_state(session_id.to_string(), auth_state);

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
