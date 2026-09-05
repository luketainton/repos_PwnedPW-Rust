# PwnedPW (Rust)

Checks whether a password has appeared in known data breaches using the [Have I Been Pwned](https://haveibeenpwned.com/) range API.

The password is hashed locally with SHA-1. Only the first five characters of the hash are sent to the API; matching suffixes are checked locally.

## Usage

```sh
cargo run --release
```

For non-interactive use, pipe the password on standard input:

```sh
printf '%s\n' 'password' | cargo run --release
```
