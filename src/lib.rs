#![crate_type = "lib"]
//! Whois information parsing and querying crate. Provides a high level API.
//!
//! Enable the 'parser' flag if you want to use the parser.
//! Everything related to the parser can be found at [parser]
//!
#![doc = include_str!("../README.md")]

use tokio::io::{AsyncReadExt, AsyncWriteExt};
use tokio::net::TcpStream;
use std::future::Future;

#[cfg(feature = "parser")]
pub mod parser;

#[derive(Clone)]
/// Configuration for your WHOIS instance
pub struct WhoisOpt {
    pub whois_server: &'static str,
    pub domain2lookup: &'static str
}

#[derive(Clone)]
/// Whois instance, used for querying a domain to a specific WHOIS server for WHOIS data
/// ```
/// use ezwhois_rs::{
///     parser::Parser,
///     Whois,
///     WhoisOpt,
///     WhoisResolver
/// };
/// 
/// #[tokio::main]
/// async fn main() {
///     let client = Whois::new(WhoisOpt{
///         whois_server: "whois.iana.org:43", 
///         domain2lookup: "simpaix.net"
///     });
///     let res = client.query().await.expect("expected a response");
///
///     let parser = Parser::new();
///     let info = parser.parse(res).unwrap();
///     println!("creation date: {}\nexpire: {}", 
///         info.creation_date.unwrap().format("%d/%m/%Y %H:%M"),
///         info.registry_expirity_date.unwrap().format("%d/%m/%Y %H:%M")
///     ); // info.registry_domain_id , etc etc
/// }
/// ```
pub struct Whois{
    target: WhoisOpt
}

pub trait WhoisResolver: Sized {
    type Error;

    /// Creates a new whois instance and configures the target
    fn new(opt: WhoisOpt) -> Whois;
    
    /// Queries the WHOIS server and retrieves domain information.
    /// Returns WHOIS information as a string.
    ///
    /// So that you can use any arbitrary parser.
    fn query(&self) -> impl Future<Output = Result<String, Self::Error>>;
}

impl WhoisResolver for Whois {
    type Error = Box<dyn std::error::Error>;

    fn new(opt: WhoisOpt) -> Whois {
        Whois{target: opt}
    }
    
    async fn query(&self) -> Result<String, Self::Error> {
        let q1 = Whois::lookup(self.target.whois_server, self.target.domain2lookup).await?;
        let main_server = 
        if let Some((_, b)) = q1.split_once("whois:") {
            b.trim().split_once("\n").ok_or_else(|| errors::WhoisError::MissingNewline)?.0
        } else { return Err(Box::new(errors::WhoisError::GeneralErr { ctx: "could not find whois server to lookup" }));};

        let port: &str = self.target.whois_server.split_once(":").ok_or_else(|| {
            Box::new(errors::WhoisError::GeneralErr{ ctx: "whois server should be in host:port format" })
        })?.1;
        Ok(Whois::lookup(&format!("{main_server}:{port}"), self.target.domain2lookup).await?)
    }
}

impl Whois {
    /// private!
    /// Sends a query request to the WHOIS server and returns a String that holds WHOIS information
    async fn lookup(whois_server: &str, domain2_lookup: &str) -> Result<String, Box<dyn std::error::Error>> {
        let mut conn = TcpStream::connect(whois_server).await?;
        conn.write(format!("{domain2_lookup}\r\n").as_bytes()).await?;
    
        let mut data: Vec<u8> = vec![];
        conn.read_to_end(&mut data).await?;
        
        if data.len() == 0 {
            return Err(Box::new(errors::WhoisError::WhoisServerIO { ctx: "Wrote to WHOIS server, but got no response" }));
        }
        Ok(String::from_utf8(data)?)
    }
}

// Errors that may occur for parent module
pub mod errors {
    use thiserror::Error;

    #[derive(Error, Debug)]
    pub enum WhoisError {
        #[error("Error caused by I/O on the WHOIS server: {ctx}")]
        WhoisServerIO{ctx: &'static str},
        
        #[error("error: {ctx}")]
        GeneralErr{ctx: &'static str},

        #[error("couldn't find newline seperator")]
        MissingNewline
    }
}

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
