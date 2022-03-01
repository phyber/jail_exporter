// bcrypt: Handle bcrypt password creation
#![forbid(unsafe_code)]
#![deny(missing_docs)]
use crate::errors::ExporterError;
use dialoguer::Password;
use rand::{
    distributions::Alphanumeric,
    thread_rng,
    Rng,
};

// Handles hashing and outputting bcrypted passwords for the bcrypt sub
// command.
pub fn generate_from(matches: &clap::ArgMatches) -> Result<(), ExporterError> {
    // Cost argument is validated and has a default, we can unwrap right
    // away.
    let cost: u32 = matches.value_of("COST")
        .expect("no bcrypt cost given")
        .parse()
        .expect("couldn't parse cost as u32");
    let random = matches.is_present("RANDOM");

    // If a password was given on the CLI, just unwrap it. If none was given,
    // we either generate a random password or interactively prompt for it.
    let password = match matches.value_of("PASSWORD") {
        Some(password) => password.into(),
        None           => {
            if random {
                // length was validated by the CLI, we should be safe to
                // unwrap and parse to usize here.
                let length: usize = matches.value_of("LENGTH")
                    .expect("no password length given")
                    .parse()
                    .expect("couldn't parse length as usize");

                thread_rng()
                    .sample_iter(&Alphanumeric)
                    .take(length)
                    .map(char::from)
                    .collect()
            }
            else {
                Password::new()
                    .with_prompt("Password")
                    .with_confirmation(
                        "Confirm password",
                        "Password mismatch",
                    )
                    .interact()?
            }
        },
    };

    let hash = bcrypt::hash(&password, cost)?;

    if random {
        println!("Password: {}", password);
    }

    println!("Hash: {}", hash);

    Ok(())
}