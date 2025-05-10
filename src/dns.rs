use anyhow::{Context, Result};
use async_trait::async_trait;
use diesel::PgConnection;
use diesel::r2d2::{ConnectionManager, Pool};
use diesel_migrations::MigrationHarness;
use hickory_proto::op::ResponseCode;
use hickory_proto::rr::{LowerName, Name, Record, RecordSet, RecordType, rdata};
use hickory_server::ServerFuture;
use hickory_server::authority::{
    AuthLookup, Authority, Catalog, LookupError, LookupOptions, LookupRecords, MessageRequest,
    UpdateResult, ZoneType,
};
use hickory_server::server::RequestInfo;
use std::fmt::Display;
use std::iter::once;
use std::sync::Arc;
use tokio::net::UdpSocket;
use tracing::{debug, info, trace, warn};
use url::Url;

use crate::config::Config;
use crate::db::{ConnectionPool, MIGRATIONS, get_lnaddress};

pub struct DnsServer {
    config: Config,
    db: ConnectionPool,
}

impl DnsServer {
    pub fn new(config: Config) -> anyhow::Result<Self> {
        let db = get_connection_pool(&config.database)?;
        Ok(Self { config, db })
    }

    fn run_migrations(&self) -> Result<()> {
        let mut conn = self.db.get()?;
        let migrations = conn
            .run_pending_migrations(MIGRATIONS)
            .map_err(|e| anyhow::anyhow!("Failed to run migrations: {}", e))?;

        if !migrations.is_empty() {
            info!("Applied migrations {}", migrations.len());
        }

        Ok(())
    }

    pub async fn run(&self) -> Result<()> {
        self.run_migrations()?;

        info!("Starting DNS server on {}", self.config.dns_bind);

        // Create a new catalog
        let mut catalog = Catalog::new();

        for domain in self.config.domains.iter() {
            let zone = Name::from_labels(
                [b"user".as_ref(), b"_bitcoin-payment".as_ref()]
                    .into_iter()
                    .chain(domain.split('.').map(|s| s.as_bytes())),
            )
            .context("Could not create zone name")?;

            debug!("Adding zone: {:?}", zone);

            let authority = Arc::new(DbAuthority::new(LowerName::new(&zone), self.db.clone()));
            catalog.upsert(LowerName::new(&zone), Box::new(authority));
        }

        // Create the server
        let mut server = ServerFuture::new(catalog);
        server.register_socket(UdpSocket::bind(self.config.dns_bind).await?);

        // Start the server
        server.block_until_done().await?;

        Ok(())
    }
}

struct DbAuthority {
    zone: LowerName,
    db: Pool<ConnectionManager<PgConnection>>,
}

impl DbAuthority {
    pub fn new(zone: LowerName, db: Pool<ConnectionManager<PgConnection>>) -> Self {
        Self { zone, db }
    }

    async fn lookup_inner(
        &self,
        name: &LowerName,
        rtype: RecordType,
    ) -> Result<AuthLookup, LookupError> {
        if rtype != RecordType::TXT && rtype != RecordType::ANY {
            return Err(LookupError::ResponseCode(ResponseCode::NXDomain));
        }

        let mut conn = self.db.get().map_err(server_failure)?;

        let user = extract_username(&self.zone.clone().into(), &name.into())?;
        let domain = self.get_domain();

        info!("Lookup for user: {}, domain: {}", user, domain);

        let lnaddress = get_lnaddress(&mut conn, &domain, &user)
            .await
            .map_err(server_failure)?
            .ok_or_else(|| LookupError::ResponseCode(ResponseCode::NXDomain))?;

        Ok(AuthLookup::Records {
            answers: LookupRecords::Records {
                lookup_options: LookupOptions::default(),
                records: Arc::new(
                    create_record_set(&self.zone, &user, &lnaddress.payment_uri)
                        .map_err(server_failure)?,
                ),
            },
            additionals: None,
        })
    }

    fn get_domain(&self) -> String {
        let mut domain = Name::from_labels(Name::from(&self.zone).iter().skip(2)).expect("Shorter domain can always be created");
        domain.set_fqdn(false); // We don't want the point at the end
        domain.to_string()
    }
}

#[async_trait]
impl Authority for DbAuthority {
    type Lookup = AuthLookup;

    fn zone_type(&self) -> ZoneType {
        ZoneType::Primary
    }

    fn is_axfr_allowed(&self) -> bool {
        false
    }

    async fn update(&self, _update: &MessageRequest) -> UpdateResult<bool> {
        Err(ResponseCode::Refused)
    }

    fn origin(&self) -> &LowerName {
        &self.zone
    }

    async fn lookup(
        &self,
        name: &LowerName,
        rtype: RecordType,
        _lookup_options: LookupOptions,
    ) -> Result<Self::Lookup, LookupError> {
        self.lookup_inner(name, rtype)
            .await
            .inspect_err(|e| trace!("Lookup error: {}", e))
            .inspect(|val| trace!("Lookup result: {:?}", val))
    }

    async fn search(
        &self,
        request: RequestInfo<'_>,
        _lookup_options: LookupOptions,
    ) -> Result<Self::Lookup, LookupError> {
        self.lookup_inner(&request.query.name(), request.query.query_type())
            .await
            .inspect_err(|e| trace!("Search error: {}", e))
            .inspect(|val| trace!("Search result: {:?}", val))
    }

    async fn get_nsec_records(
        &self,
        _name: &LowerName,
        _lookup_options: LookupOptions,
    ) -> Result<Self::Lookup, LookupError> {
        warn!("get_nsec_records");
        Err(LookupError::ResponseCode(ResponseCode::Refused))
    }
}

pub fn get_connection_pool(database_url: &Url) -> anyhow::Result<ConnectionPool> {
    let manager = ConnectionManager::<PgConnection>::new(database_url.to_string());
    Pool::builder()
        .test_on_check_out(true)
        .build(manager)
        .context("Could not build connection pool")
}

fn server_failure(e: impl Display) -> LookupError {
    warn!("Server failure: {}", e);
    LookupError::ResponseCode(ResponseCode::ServFail)
}

fn extract_username(zone: &Name, lookup: &Name) -> Result<String, LookupError> {
    let mut lookup_labels = lookup.iter();
    let zone_labels = zone.iter();

    let username = String::from_utf8(
        lookup_labels
            .next()
            .ok_or(LookupError::ResponseCode(ResponseCode::NXDomain))?
            .to_owned(),
    )
    .map_err(|_| LookupError::ResponseCode(ResponseCode::NXDomain))?;

    if lookup_labels.collect::<Vec<_>>() != zone_labels.collect::<Vec<_>>() {
        return Err(LookupError::ResponseCode(ResponseCode::NXDomain));
    }

    Ok(username)
}

fn create_record_set(zone: &LowerName, user: &str, lnaddress: &str) -> anyhow::Result<RecordSet> {
    let zone: Name = zone.into();
    let fqdn = Name::from_labels(once(user.as_bytes()).chain(zone.iter()))?;

    Ok(Record::from_rdata(
        fqdn,
        120,
        hickory_proto::rr::RData::TXT(rdata::TXT::from_bytes(vec![lnaddress.as_bytes()])),
    )
    .into())
}

#[cfg(test)]
mod tests {
    use std::str::FromStr;

    use hickory_proto::rr::Name;

    use crate::dns::extract_username;

    #[test]
    fn test_extract_username() {
        let zone = Name::from_str("user._bitcoin-payment.example.com.").unwrap();
        let lookup = Name::from_str("foobar.user._bitcoin-payment.example.com.").unwrap();
        let username = extract_username(&zone, &lookup).unwrap();
        assert_eq!(username.as_str(), "foobar");
    }
}
