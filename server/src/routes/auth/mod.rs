pub mod errors;
mod password;
pub mod session;

use std::io::stdout;
use serde::Deserialize;
use sqlx::query;
use std::str::FromStr;
use axum::extract::{FromRef, FromRequestParts, State};
use axum::response::{Html, IntoResponse, Response};
use axum::{debug_handler, Json, RequestPartsExt, Router};
use axum::routing::{get, post};
use axum_extra::extract::cookie::{Cookie, SameSite};
use axum_extra::extract::CookieJar;
use sqlx::PgPool;
use sqlx::types::Uuid;
use tracing::{debug, trace};
use crate::AppState;
use crate::routes::auth::errors::AuthError;

const SESSION_COOKIE_NAME: &str = "session";

pub fn router() -> Router<AppState> {
    Router::new()
        .route("/login",post(login))
        .route("/register", post(register))
        .route("/logout", post(logout))
}

#[derive(Deserialize)]
struct RegisterCredentials {
    username: String,
    email: String,
    password: String,
}

async fn register(pool: State<PgPool>, jar: CookieJar, Json(body): Json<RegisterCredentials>) -> Result<CookieJar, AuthError> {
    trace!("Register");
    let mut transaction = pool.begin().await?;
    let res = query!(r#"
    SELECT *
    FROM credentials
    WHERE email = $1
    "#, &body.email
    ).fetch_optional(&mut *transaction).await?;

    if res.is_some() {
        return Err(AuthError::UserAlreadyExists);
    }

    if !password::is_strong(&body.password, &[&body.email, &body.username]) {
        return Err(AuthError::WeakPassword);
    }

    let user_id = query!(r#"
    INSERT INTO users (username)
    VALUES ($1)
    RETURNING id
    "#, &body.username).fetch_one(&mut *transaction).await?.id;

    let hashed_password = password::hash(body.password)?;
    query!(r#"
    INSERT INTO credentials (email, password, user_id)
    VALUES ($1, $2, $3)
    "#, &body.email, hashed_password, &user_id
    ).execute(&mut *transaction).await?;

    let session_id = query!(r#"
    INSERT INTO sessions (user_id)
    VALUES ($1)
    RETURNING id
    "#, &user_id).fetch_one(&mut *transaction).await?.id;

    transaction.commit().await?;

    debug!("Registered");
    return Ok(jar.add(session_cookie(session_id)));
}

#[derive(Deserialize)]
struct LoginCredentials {
    email: String,
    password: String,
}

#[debug_handler]
async fn login(pool: State<PgPool>, jar: CookieJar, Json(body): Json<LoginCredentials>) -> Result<CookieJar,AuthError> {
    trace!("Login");
    let mut transaction = pool.begin().await?;
    let credentials = query!(r#"
    SELECT password, user_id
    FROM credentials
    WHERE email = $1
    "#, &body.email).fetch_optional(&mut *transaction).await?.ok_or(AuthError::WrongLoginOrPassword)?;

    let is_verified = password::verify(body.password,credentials.password)?;
    if is_verified {
        let session_id =  query!(r#"
        INSERT INTO sessions (user_id)
        VALUES ($1)
        RETURNING id
        "#, credentials.user_id).fetch_one(&mut *transaction).await?.id;

        transaction.commit().await?;

        debug!("Logged in");
        return Ok(jar.add(session_cookie(session_id)));
    }
    Err(AuthError::WrongLoginOrPassword)
}


async fn logout(pool: State<PgPool>, jar: CookieJar) -> Result<CookieJar, AuthError> {
    if let Some(session_cookie) = jar.get(SESSION_COOKIE_NAME) {
        let session_id = Uuid::from_str(session_cookie.value()).or(Err(AuthError::InvalidSession))?;
        let mut conn = pool.acquire().await?;
        let res = query!(r#"
        DELETE FROM sessions
        WHERE id = $1
        "#, session_id).fetch_optional(&mut *conn).await?;
        if let Some(r) = res {
            debug!("Deleted session from db");
        }
        return Ok(jar.remove(Cookie::named(SESSION_COOKIE_NAME)));
    }
    Ok(jar)
}

fn session_cookie<'c>(session_id: Uuid) -> Cookie<'c> {
    Cookie::build(SESSION_COOKIE_NAME, session_id.to_string())
        .path("/")
        .http_only(true)
        .secure(false)
        .same_site(SameSite::Strict)
        .finish()
}