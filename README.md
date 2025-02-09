# ezwhois-rs

A crate for retrieving WHOIS data comfortably. It seperates the WHOIS information parser and querying part. By default the parser implementation is included. Disable ``default-futures`` for this trait if you would like to use a different parser.

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
    println!("creation date: {}\nexpire: {}", 
        info.creation_date.unwrap().format("%d/%m/%Y %H:%M"),
        info.registry_expirity_date.unwrap()
    ); // info.registry_domain_id , etc etc
}
/// running 1 test
/// test test_client ... ok
///
// successes:
///
// ---- test_client stdout ----
// creation date: 20/06/2023 12:13
// expire: 2025-06-20 12:13:22 UTC
```