# ezwhois-rs

A crate for retrieving WHOIS data comfortably. It seperates the WHOIS information parser and querying part. By default the parser implementation is included. Disable ``default-futures`` for this crate if you would like to use a different parser.

#### Usage
```rust
#[tokio::test]
async fn test_client() {
    let client = Whois::new(WhoisOpt{
        whois_server: "whois.iana.org:43", 
        domain2lookup: "simpaix.net"
    });
    let res = client.query().await.expect("expected a response");

    let parser = parser::Parser::new();
    let info = parser.parse(res).unwrap();
    println!("creation date: {}\nexpire: {}\n\nor the complete whois info:\n\n-------------{:#?}------------", 
        info.creation_date.unwrap().format("%d/%m/%Y %H:%M"),
        info.registry_expirity_date.unwrap().format("%d/%m/%Y %H:%M"),
        info
    );
}
/*
successes:

---- test_client stdout ----
creation date: 20/06/2023 12:13
expire: 20/06/2025 12:13

or the complete whois info:

-------------WhoisInformation {
    domain_name: Some(
        "SIMPAIX.NET",
    ),
    registry_domain_id: Some(
        "2791830160_DOMAIN_NET-VRSN",
    ),
    registrar_whois_server: Some(
        "whois.namecheap.com",
    ),
    registrar_url: Some(
        "http://www.namecheap.com",
    ),
    updated_date: Some(
        2024-05-21T08:07:15Z,
    ),
    creation_date: Some(
        2023-06-20T12:13:22Z,
    ),
    registry_expirity_date: Some(
        2025-06-20T12:13:22Z,
    ),
    registrar: Some(
        "NameCheap, Inc.",
    ),
    registrar_iana_id: Some(
        "1068",
    ),
    registrar_abuse_email_contact: Some(
        "abuse@namecheap.com",
    ),
    registrar_abuse_phone_contact: Some(
        "+1.6613102107",
    ),
    domain_status: Some(
        "clientTransferProhibited https://icann.org/epp#clientTransferProhibited",
    ),
    name_servers: Some(
        [
            "IRENA.NS.CLOUDFLARE.COM",
        ],
    ),
    dnssec: Some(
        "unsigned",
    ),
}------------
*/