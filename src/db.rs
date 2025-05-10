use std::time::SystemTime;

use diesel::prelude::*;
use diesel_migrations::{EmbeddedMigrations, embed_migrations};

pub type PooledConnection =
    diesel::r2d2::PooledConnection<diesel::r2d2::ConnectionManager<PgConnection>>;
pub type ConnectionPool = diesel::r2d2::Pool<diesel::r2d2::ConnectionManager<PgConnection>>;

diesel::table! {
    payment_addresses (id) {
        id -> Integer,
        username -> VarChar,
        domain -> VarChar,
        payment_uri -> Text,
        payment_uri_type -> VarChar,
        password_hash -> Binary,
        created_at -> Timestamp,
        updated_at -> Timestamp,
    }
}

/// Lnaddress table entry
#[derive(Queryable)]
pub struct PaymentAddress {
    pub id: i32,
    pub username: String,
    pub domain: String,
    pub payment_uri: String,
    pub payment_uri_type: String,
    pub password_hash: Vec<u8>,
    pub created_at: SystemTime,
    pub updated_at: SystemTime,
}

/// Query the lnaddress entry for a given username and domain
pub async fn get_lnaddress(
    conn: &mut PooledConnection,
    domain: &str,
    username: &str,
) -> anyhow::Result<Option<PaymentAddress>> {
    match payment_addresses::table
        .filter(payment_addresses::domain.eq(domain))
        .filter(payment_addresses::username.eq(username))
        .first(conn)
    {
        Ok(lnaddress) => Ok(Some(lnaddress)),
        Err(diesel::result::Error::NotFound) => Ok(None),
        Err(e) => Err(e.into()),
    }
}

pub const MIGRATIONS: EmbeddedMigrations = embed_migrations!("migrations");
