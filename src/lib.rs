//! Password leak checking using the Have I Been Pwned range API.

use reqwest::blocking::Client;
use sha1::{Digest, Sha1};
use std::error::Error;

pub const HIBP_RANGE_URL: &str = "https://api.pwnedpasswords.com/range";

pub fn hash_password(password: &str) -> (String, String) {
    let digest = Sha1::digest(password.as_bytes());
    let hex = format!("{digest:X}");
    (hex[..5].to_owned(), hex[5..].to_owned())
}

pub fn parse_pwned_hashes(body: &str) -> impl Iterator<Item = (&str, u64)> {
    body.lines().filter_map(|line| {
        let (suffix, count) = line.trim().split_once(':')?;
        Some((suffix, count.parse().ok()?))
    })
}

pub fn check_password_at(
    password: &str,
    endpoint: &str,
) -> Result<Option<(String, u64)>, Box<dyn Error>> {
    let (prefix, suffix) = hash_password(password);
    let body = Client::new()
        .get(format!("{endpoint}/{prefix}"))
        .header("Add-Padding", "true")
        .send()?
        .error_for_status()?
        .text()?;

    let result = parse_pwned_hashes(&body)
        .find(|(candidate, _)| candidate.eq_ignore_ascii_case(&suffix))
        .map(|(_, count)| (format!("{prefix}{suffix}"), count));
    Ok(result)
}

pub fn check_password(password: &str) -> Result<Option<(String, u64)>, Box<dyn Error>> {
    check_password_at(password, HIBP_RANGE_URL)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn hashes_hello() {
        assert_eq!(
            hash_password("hello"),
            ("AAF4C".into(), "61DDCC5E8A2DABEDE0F3B482CD9AEA9434D".into())
        );
    }

    #[test]
    fn queries_and_matches_case_insensitively() {
        let mut server = mockito::Server::new();
        let suffix = hash_password("hello").1;
        let _mock = server
            .mock("GET", "/AAF4C")
            .with_status(200)
            .with_body(format!("{}:3\nBADLINE\n", suffix.to_lowercase()))
            .create();
        assert_eq!(
            check_password_at("hello", &server.url())
                .unwrap()
                .unwrap()
                .1,
            3
        );
    }

    #[test]
    fn uncommon_password_is_not_found() {
        assert!(parse_pwned_hashes("ABC:4\nDEF:2\n")
            .all(|(suffix, _)| suffix != "61DDCC5E8A2DABEDE0F3B482CD9AEA9434D"));
    }
}
