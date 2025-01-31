// src/main.rs
use axum::{
    extract::State,
    http::{Request, StatusCode},
    middleware::{self, Next},
    response::{IntoResponse, Response},
    routing::{get, post},
    Json, Router,
    body::Body,
};
use jsonwebtoken::{decode, encode, DecodingKey, EncodingKey, Header, Validation};
use serde::{Deserialize, Serialize};
use std::{sync::Arc, time::{SystemTime, UNIX_EPOCH}};
use tower_http::trace::TraceLayer;

// JWT Claims structure
#[derive(Debug, Serialize, Deserialize, Clone)]
struct Claims {
    sub: String,
    exp: usize,
    iat: usize,
}

// App configuration
#[derive(Clone)]
struct AppConfig {
    jwt_secret: String,
}

// Custom error type
#[derive(thiserror::Error, Debug)]
enum AppError {
    #[error("Authentication failed")]
    AuthError,
    #[error("JWT token error")]
    JWTError(#[from] jsonwebtoken::errors::Error),
}

impl IntoResponse for AppError {
    fn into_response(self) -> Response {
        let (status, message) = match self {
            AppError::AuthError => (StatusCode::UNAUTHORIZED, "Authentication failed"),
            AppError::JWTError(_) => (StatusCode::UNAUTHORIZED, "Invalid token"),
        };
        
        (status, message).into_response()
    }
}

// Authentication middleware
async fn auth_middleware(
    State(config): State<Arc<AppConfig>>,
    mut req: Request<Body>,
    next: Next,
) -> Result<Response, AppError> {
    // Extract token from Authorization header
    let auth_header = req
        .headers()
        .get("Authorization")
        .and_then(|header| header.to_str().ok())
        .and_then(|header| header.strip_prefix("Bearer "))
        .ok_or(AppError::AuthError)?;

    // Verify JWT token
    let token_data = decode::<Claims>(
        auth_header,
        &DecodingKey::from_secret(config.jwt_secret.as_bytes()),
        &Validation::default(),
    )?;

    // Add verified claims to request extensions
    req.extensions_mut().insert(token_data.claims);
    
    Ok(next.run(req).await)
}

// Login request structure
#[derive(Debug, Deserialize)]
struct LoginRequest {
    username: String,
    password: String,
}

// Login response structure
#[derive(Debug, Serialize)]
struct LoginResponse {
    token: String,
}

// Get current timestamp in seconds
fn get_current_timestamp() -> usize {
    SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .unwrap()
        .as_secs() as usize
}

// Login handler
async fn login_handler(
    State(config): State<Arc<AppConfig>>,
    Json(login): Json<LoginRequest>,
) -> Result<Json<LoginResponse>, AppError> {
    // In a real application, validate credentials against a database
    if login.username == "test" && login.password == "password" {
        let now = get_current_timestamp();
        let claims = Claims {
            sub: login.username,
            exp: now + 24 * 3600, // 24 hours from now
            iat: now,
        };

        let token = encode(
            &Header::default(),
            &claims,
            &EncodingKey::from_secret(config.jwt_secret.as_bytes()),
        )?;

        Ok(Json(LoginResponse { token }))
    } else {
        Err(AppError::AuthError)
    }
}

// Protected route handler
async fn protected_handler() -> &'static str {
    "This is a protected route!"
}

#[tokio::main]
async fn main() {
    // Initialize tracing
    tracing_subscriber::fmt::init();

    // Initialize app configuration
    let config = Arc::new(AppConfig {
        jwt_secret: "your-secret-key".to_string(), // In production, use environment variables
    });

    // Define public routes that don't require authentication
    let public_routes = Router::new()
        .route("/login", post(login_handler));

    // Define protected routes that require authentication
    let protected_routes = Router::new()
        .route("/protected", get(protected_handler))
        .layer(middleware::from_fn_with_state(config.clone(), auth_middleware));

    // Combine routes and add middleware
    let app = Router::new()
        .merge(public_routes)
        .merge(protected_routes)
        .layer(TraceLayer::new_for_http())
        .with_state(config);

    // Start server
    let listener = tokio::net::TcpListener::bind("127.0.0.1:3000").await.unwrap();
    tracing::info!("Server running on http://127.0.0.1:3000");
    axum::serve(listener, app).await.unwrap();
}