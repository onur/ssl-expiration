//! Checks SSL certificate expiration.
//! 
//! This crate will try to connect a remote server and check SSL certificate expiration.
//! 
//! Example:
//! 
//! ```rust
//! use ssl_expiration::SslExpiration;
//! 
//! let expiration = SslExpiration::from_domain_name("google.com").unwrap();
//! if expiration.is_expired() {
//!     // do something if SSL certificate expired
//! }
//! ```

extern crate openssl;
extern crate openssl_sys;
#[macro_use]
extern crate error_chain;

use std::os::raw::c_int;
use std::net::{TcpStream, ToSocketAddrs};
use std::error::Error;
use openssl::ssl::{Ssl, SslContext, SslMethod, SslVerifyMode};
use openssl::asn1::Asn1Time;
use openssl_sys::ASN1_TIME;
use openssl::types::{OpenSslType, OpenSslTypeRef};
use error::Result;


extern "C" {
    fn ASN1_TIME_diff(pday: *mut c_int,
                      psec: *mut c_int,
                      from: *const ASN1_TIME,
                      to: *const ASN1_TIME);
}


pub struct SslExpiration(c_int);


impl SslExpiration {
    /// Creates new SslExpiration from domain name.
    /// 
    /// This function will use default SSL port (443) to check SSL certificate.
    pub fn from_domain_name(domain: &str) -> Result<SslExpiration> {
        SslExpiration::from_addr(format!("{}:443", domain))
    }

    /// Creates new SslExpiration from SocketAddr.
    pub fn from_addr<A: ToSocketAddrs>(addr: A) -> Result<SslExpiration> {
        let context = {
            let mut context = SslContext::builder(SslMethod::tls())?;
            context.set_verify(SslVerifyMode::empty());
            context.build()
        };
        let connector = Ssl::new(&context)?;
        let stream = TcpStream::connect(addr)?;
        let stream = connector.connect(stream)
            .map_err(|e| error::ErrorKind::HandshakeError(e.description().to_owned()))?;
        let cert = stream.ssl()
            .peer_certificate()
            .ok_or("Certificate not found")?;

        let now = Asn1Time::days_from_now(0)?;

        let (mut pday, mut psec) = (0, 0);
        unsafe {
            let ptr_pday: *mut c_int = &mut pday;
            let ptr_psec: *mut c_int = &mut psec;
            ASN1_TIME_diff(ptr_pday,
                           ptr_psec,
                           now.as_ptr(),
                           cert.not_after().as_ptr());
        }

        Ok(SslExpiration(pday * 24 * 60 * 60 - psec))
    }

    /// How long until SSL certificate expires.
    /// 
    /// This function will return minus if SSL certificate is already expired.
    pub fn secs(&self) -> i32 {
        self.0
    }

    /// Returns true if SSL certificate is expired
    pub fn is_expired(&self) -> bool {
        self.0 < 0
    }
}



pub mod error {
    use std::io;
    use openssl;

    error_chain! {
        foreign_links {
            OpenSslErrorStack(openssl::error::ErrorStack);
            IoError(io::Error);
        }
        errors {
            HandshakeError(e: String) {
                description("HandshakeError")
                display("HandshakeError: {}", e)
            }
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    #[test]
    fn test_ssl_expiration() {
        assert!(!SslExpiration::from_domain_name("google.com").unwrap().is_expired());
        assert!(SslExpiration::from_domain_name("expired.identrustssl.com").unwrap().is_expired());
    }
}
