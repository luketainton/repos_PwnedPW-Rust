use std::io::{self, Read, Write};

fn main() {
    print!("Password: ");
    io::stdout().flush().expect("failed to flush prompt");

    let password = match read_password() {
        Ok(password) => password,
        Err(error) => {
            eprintln!("Unable to read password: {error}");
            std::process::exit(1);
        }
    };

    match pwnedpw::check_password(&password) {
        Ok(Some((hash, occurrences))) => {
            println!("Password found as hash {hash}");
            println!("Occurrences: {occurrences}");
        }
        Ok(None) => println!("Password not found."),
        Err(error) => {
            eprintln!("Unable to check password: {error}");
            std::process::exit(1);
        }
    }
}

fn read_password() -> io::Result<String> {
    if atty::is(atty::Stream::Stdin) {
        rpassword::read_password()
    } else {
        let mut password = String::new();
        io::stdin().read_to_string(&mut password)?;
        Ok(password.trim_end_matches(['\r', '\n']).to_owned())
    }
}
