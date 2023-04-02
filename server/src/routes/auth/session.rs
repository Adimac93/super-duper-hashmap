use std::str::FromStr;
use anyhow::Context;
use axum::extract::{FromRef, FromRequestParts};
use axum::http::request::Parts;
use axum::{async_trait, RequestPartsExt};
use axum_extra::extract::CookieJar;
use sqlx::{PgPool, query};
use uuid::Uuid;
use crate::routes::auth::errors::AuthError;
use crate::routes::auth::SESSION_COOKIE_NAME;

pub struct Session {
    pub user_id: Uuid
}

#[async_trait]
impl<S> FromRequestParts<S> for Session
    where S: Send + Sync, PgPool: FromRef<S>
{
    type Rejection = AuthError;

    async fn from_request_parts(req: &mut Parts, state: &S) -> Result<Self, Self::Rejection> {

        let pool = PgPool::from_ref(state);
        let jar = req.extract::<CookieJar>().await.context("Failed to get cookie jar")?;
        if let Some(cookie)  = jar.get(SESSION_COOKIE_NAME) {
            let session_id = Uuid::from_str(cookie.value()).context("Failed to parse session id")?;
            let res = query!(r#"
            SELECT user_id
            FROM sessions
            JOIN users ON sessions.user_id = users.id
            WHERE sessions.id = $1
            "#, session_id
            ).fetch_optional(&pool).await?;

            if let Some(session) = res {
                return Ok(Session { user_id: session.user_id });
            }


        }

        Err(AuthError::InvalidSession)
    }
}