//! Credential Provider (SPEC Section 9.2).
//!
//! Resolution: environment variable > interactive input. Interactive input
//! is only attempted when stdin is a terminal; otherwise fail immediately
//! with `credentials_unavailable`. Credentials are never stored or logged.

use std::io::{BufRead, IsTerminal, Write};

use crate::config::{ENV_APPLE_ID, ENV_APPLE_PASSWORD, Env};
use crate::{Error, ErrorCode, Result};

pub struct Credentials {
    pub apple_id: String,
    password: String,
}

impl Credentials {
    pub fn password(&self) -> &str {
        &self.password
    }
}

impl std::fmt::Debug for Credentials {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("Credentials")
            .field("apple_id", &self.apple_id)
            .field("password", &"<redacted>")
            .finish()
    }
}

pub fn resolve(env: &dyn Env) -> Result<Credentials> {
    let from_env = |key| {
        env.get_non_empty(key)
            .map(|v| v.to_string_lossy().into_owned())
    };
    let apple_id = from_env(ENV_APPLE_ID);
    let password = from_env(ENV_APPLE_PASSWORD);

    if (apple_id.is_none() || password.is_none()) && !std::io::stdin().is_terminal() {
        return Err(Error::new(
            ErrorCode::CredentialsUnavailable,
            format!(
                "standard input is not a terminal; set {ENV_APPLE_ID} and {ENV_APPLE_PASSWORD}"
            ),
        ));
    }

    let apple_id = match apple_id {
        Some(v) => v,
        None => prompt_line("Apple ID: ")?,
    };
    let password = match password {
        Some(v) => v,
        None => prompt_password("Password: ")?,
    };
    // Upstream lowercases the Apple ID before SRP and the key path (SPEC 4.1.2).
    Ok(Credentials {
        apple_id: apple_id.to_lowercase(),
        password,
    })
}

fn prompt_line(prompt: &str) -> Result<String> {
    eprint!("{prompt}");
    let _ = std::io::stderr().flush();
    let mut line = String::new();
    let read = std::io::stdin()
        .lock()
        .read_line(&mut line)
        .map_err(|e| Error::new(ErrorCode::CredentialsUnavailable, e.to_string()))?;
    if read == 0 {
        return Err(Error::new(
            ErrorCode::CredentialsUnavailable,
            "unexpected end of input",
        ));
    }
    Ok(line.trim_end_matches(['\r', '\n']).to_owned())
}

fn prompt_password(_prompt: &str) -> Result<String> {
    // TODO: no-echo input (add `rpassword`); MUST NOT echo (SPEC Section 9.2).
    Err(Error::not_implemented("interactive password input"))
}

// TODO: 2FA code input with `resend` and EOF handling (SPEC Section 9.2 step 5).
