use anyhow::{Context, Result};
use async_trait::async_trait;
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

use crate::config::Config;
use crate::repositroy::pg::PgPaymentAddressRepository;
use crate::repositroy::PaymentAddressRepository;

pub struct DnsServer {
    config: Config,
}

impl DnsServer {
    pub fn new(config: Config) -> anyhow::Result<Self> {
        Ok(Self { config })
    }

    pub async fn run(&self) -> Result<()> {
        info!("Starting DNS server on {}", self.config.dns_bind);

        let repository = PgPaymentAddressRepository::new(&self.config.database)?.into_dyn();

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

            let authority = Arc::new(Bip353Authority::new(LowerName::new(&zone), repository.clone()));
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

struct Bip353Authority {
    zone: LowerName,
    repository: PaymentAddressRepository,
}

impl Bip353Authority {
    pub fn new(zone: LowerName, repository: PaymentAddressRepository) -> Self {
        Self { zone, repository }
    }

    async fn lookup_inner(
        &self,
        name: &LowerName,
        rtype: RecordType,
    ) -> Result<AuthLookup, LookupError> {
        if rtype != RecordType::TXT && rtype != RecordType::ANY {
            return Err(LookupError::ResponseCode(ResponseCode::NXDomain));
        }

        let user = extract_username(&self.zone.clone().into(), &name.into())?;
        let domain = self.get_domain();

        info!("Lookup for user: {}, domain: {}", user, domain);

        let lnaddress = self.repository.get_payment_address(&domain, &user)
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
        let mut domain = Name::from_labels(Name::from(&self.zone).iter().skip(2))
            .expect("Shorter domain can always be created");
        domain.set_fqdn(false); // We don't want the point at the end
        domain.to_string()
    }
}

#[async_trait]
impl Authority for Bip353Authority {
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
