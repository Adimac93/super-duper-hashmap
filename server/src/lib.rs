mod routes;

use std::env;
use axum::extract::FromRef;
use axum::{debug_handler, Router};
use axum::http::{StatusCode, Uri};
use axum::response::IntoResponse;
use sqlx::{migrate, PgPool};
// use tower_http::cors::{Any, CorsLayer};
use crate::routes::{auth};


pub fn app(app_state: AppState) -> Router {
    Router::new()
        .nest("/auth", auth::router())
        .fallback(not_found)
        .with_state(app_state)
}

async fn not_found(
) -> impl IntoResponse {
    (StatusCode::NOT_FOUND, "Endpoint not found")
}


#[derive(FromRef, Clone)]
pub struct AppState {
    pub pool: PgPool
}

impl AppState {
    pub async fn new(environment: Environment) -> Self {
        let pool = PgPool::connect(&env::var("DATABASE_URL").expect("DATABASE_URL var missing")).await.unwrap();
        if environment == Environment::Production {
            migrate!("./migrations").run(&pool).await.expect("Failed to migrate");
        }
        Self { pool }
    }
}

#[derive(PartialEq)]
pub enum Environment {
    Development,
    Production
}

impl TryFrom<String> for Environment {
    type Error = String;

    fn try_from(value: String) -> Result<Self, Self::Error> {
        match value.to_lowercase().as_str() {
            "development" | "dev" => Ok(Self::Development),
            "production" | "prod" => Ok(Self::Production),
            other => Err(format!(
                "{other} is not supported environment. Use either `local` or `production`"
            )),
        }
    }
}