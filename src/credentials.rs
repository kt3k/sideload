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

fn prompt_password(prompt: &str) -> Result<String> {
    // `rpassword` disables echo on the terminal (SPEC Section 9.2).
    let password = rpassword::prompt_password(prompt)
        .map_err(|e| Error::new(ErrorCode::CredentialsUnavailable, e.to_string()))?;
    if password.is_empty() {
        return Err(Error::new(
            ErrorCode::CredentialsUnavailable,
            "empty password",
        ));
    }
    Ok(password)
}

/// What the user typed at the 2FA prompt.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum CodeInput {
    Code(String),
    /// `resend`: ask for a new code.
    Resend,
}

pub const TWO_FACTOR_PROMPT: &str =
    "Enter the verification code sent to your devices (type `resend` to send a new one): ";

/// Reads one 2FA answer (SPEC Section 9.2 step 5). Blank lines re-prompt;
/// end of input fails with `two_factor_failed`. Works with piped input.
pub fn read_two_factor_code(
    input: &mut impl BufRead,
    prompt: &mut impl Write,
) -> Result<CodeInput> {
    loop {
        let _ = prompt.write_all(TWO_FACTOR_PROMPT.as_bytes());
        let _ = prompt.flush();
        let mut line = String::new();
        let read = input
            .read_line(&mut line)
            .map_err(|e| Error::new(ErrorCode::TwoFactorFailed, e.to_string()))?;
        if read == 0 {
            return Err(Error::new(
                ErrorCode::TwoFactorFailed,
                "end of input while waiting for the verification code",
            ));
        }
        let answer = line.trim();
        if answer.is_empty() {
            continue;
        }
        if answer.eq_ignore_ascii_case("resend") {
            return Ok(CodeInput::Resend);
        }
        return Ok(CodeInput::Code(answer.to_owned()));
    }
}

/// `read_two_factor_code` on stdin, prompting on stderr.
pub fn prompt_two_factor_code() -> Result<CodeInput> {
    read_two_factor_code(&mut std::io::stdin().lock(), &mut std::io::stderr())
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::io::Cursor;

    #[test]
    fn two_factor_input() {
        let mut out = Vec::new();
        let mut input = Cursor::new(b"\n  123456 \nresend\nRESEND\n".to_vec());
        assert_eq!(
            read_two_factor_code(&mut input, &mut out).unwrap(),
            CodeInput::Code("123456".into())
        );
        assert_eq!(
            read_two_factor_code(&mut input, &mut out).unwrap(),
            CodeInput::Resend
        );
        assert_eq!(
            read_two_factor_code(&mut input, &mut out).unwrap(),
            CodeInput::Resend
        );
        let e = read_two_factor_code(&mut input, &mut out).unwrap_err();
        assert_eq!(e.code, ErrorCode::TwoFactorFailed);
        // One prompt per read, including the re-prompt after the blank line and the final EOF.
        assert_eq!(
            String::from_utf8(out)
                .unwrap()
                .matches(TWO_FACTOR_PROMPT)
                .count(),
            5
        );
    }

    #[test]
    fn credentials_debug_redacts_password() {
        let c = Credentials {
            apple_id: "a@b.c".into(),
            password: "hunter2".into(),
        };
        let d = format!("{c:?}");
        assert!(d.contains("a@b.c") && !d.contains("hunter2"));
    }
}
