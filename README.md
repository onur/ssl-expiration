# ssl-expiration

[![Build Status](https://secure.travis-ci.org/onur/ssl-expiration.svg?branch=master)](https://travis-ci.org/onur/ssl-expiration)
[![License](https://img.shields.io/badge/license-MIT-blue.svg)](https://raw.githubusercontent.com/onur/ssl-expiration/master/LICENSE)
[![Crates.io](https://img.shields.io/crates/v/ssl-expiration.svg)](https://crates.io/crates/ssl-expiration)
[![docs.rs](https://docs.rs/ssl-expiration/badge.svg)](https://docs.rs/ssl-expiration)

Checks SSL certificate expiration.

## Usage

```rust
use ssl_expiration::SslExpiration;

let expiration = SslExpiration::from_domain_name("google.com").unwrap();
if expiration.is_expired() {
    // do something if SSL certificate expired
}

```

## CLI

This crate also comes with a handy command line program. You can install it
with: `cargo install ssl-expires` and check expiration of SSL certificates with:

```sh
$ ssl-expiration google.com docs.rs github.com
google.com SSL certificate will expire in 69 days.
docs.rs SSL certificate will expire in 8 days.
github.com SSL certificate will expire in 399 days.
```
