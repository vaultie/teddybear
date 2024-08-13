use hickory_proto::{
    error::ProtoError,
    op::{Message, Query},
    rr::{Name, RData, RecordType},
    serialize::binary::{BinDecodable, BinEncodable},
};

#[derive(Debug, thiserror::Error)]
pub enum DnsError {
    #[error("invalid rdata type")]
    InvalidRdataType,

    #[error("invalid rdata contents")]
    InvalidRdataContents,

    #[error(transparent)]
    ProtoError(#[from] ProtoError),

    #[error(transparent)]
    Reqwest(#[from] reqwest::Error),
}

pub async fn resolve_uri_record(name: &str) -> Result<Option<String>, DnsError> {
    let rdata = resolve_record(name, RecordType::Unknown(256)).await?;

    Ok(match rdata {
        Some(rdata) => {
            let null = rdata
                .into_unknown()
                .map_err(|_| DnsError::InvalidRdataType)?
                .1;

            let raw = null
                .anything()
                .get(4..)
                .ok_or(DnsError::InvalidRdataContents)?;

            Some(String::from_utf8(raw.to_owned()).map_err(|_| DnsError::InvalidRdataContents)?)
        }
        None => None,
    })
}

async fn resolve_record(name: &str, rr_type: RecordType) -> Result<Option<RData>, DnsError> {
    let name = Name::from_utf8(name)?;

    let query = Query::query(name.clone(), rr_type);

    let mut message = Message::new();
    message.add_query(query);
    message.set_recursion_desired(true);

    let response_bytes = reqwest::Client::new()
        .post("https://cloudflare-dns.com/dns-query")
        .header("accept", "application/dns-message")
        .header("content-Type", "application/dns-message")
        .body(message.to_bytes()?)
        .send()
        .await?
        .bytes()
        .await?;

    let mut response = Message::from_bytes(&response_bytes)?;

    let suitable_response = response
        .take_answers()
        .into_iter()
        .find_map(|record| {
            if name == *record.name() && rr_type == record.record_type() {
                Some(record.into_data())
            } else {
                None
            }
        })
        .flatten();

    Ok(suitable_response)
}
