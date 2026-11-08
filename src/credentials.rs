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
    resolve_with(
        env,
        std::io::stdin().is_terminal(),
        &mut prompt_line,
        &mut prompt_password,
    )
}

/// Only the Apple ID (from the environment or a prompt), lowercased. Used
/// to look up a saved session before asking for the password.
pub fn resolve_apple_id(env: &dyn Env) -> Result<String> {
    apple_id_with(env, std::io::stdin().is_terminal(), &mut prompt_line)
}

/// The password for an already known `apple_id`.
pub fn resolve_for(env: &dyn Env, apple_id: &str) -> Result<Credentials> {
    password_with(
        env,
        apple_id,
        std::io::stdin().is_terminal(),
        &mut prompt_password,
    )
}

fn from_env(env: &dyn Env, key: &str) -> Option<String> {
    env.get_non_empty(key)
        .map(|v| v.to_string_lossy().into_owned())
}

fn unavailable() -> Error {
    Error::new(
        ErrorCode::CredentialsUnavailable,
        format!("standard input is not a terminal; set {ENV_APPLE_ID} and {ENV_APPLE_PASSWORD}"),
    )
}

fn apple_id_with(
    env: &dyn Env,
    interactive: bool,
    ask_line: &mut dyn FnMut(&str) -> Result<String>,
) -> Result<String> {
    let apple_id = match from_env(env, ENV_APPLE_ID) {
        Some(v) => v,
        None if interactive => ask_line("Apple ID: ")?,
        None => return Err(unavailable()),
    };
    // Upstream lowercases the Apple ID before SRP and the key path (SPEC 4.1.2).
    Ok(apple_id.to_lowercase())
}

fn password_with(
    env: &dyn Env,
    apple_id: &str,
    interactive: bool,
    ask_password: &mut dyn FnMut(&str) -> Result<String>,
) -> Result<Credentials> {
    let password = match from_env(env, ENV_APPLE_PASSWORD) {
        Some(v) => v,
        None if interactive => ask_password("Password: ")?,
        None => return Err(unavailable()),
    };
    Ok(Credentials {
        apple_id: apple_id.to_owned(),
        password,
    })
}

/// `resolve` with the terminal check and prompts injected (for tests).
/// Without a terminal, fails before prompting if either value is missing.
fn resolve_with(
    env: &dyn Env,
    interactive: bool,
    ask_line: &mut dyn FnMut(&str) -> Result<String>,
    ask_password: &mut dyn FnMut(&str) -> Result<String>,
) -> Result<Credentials> {
    if !interactive
        && (from_env(env, ENV_APPLE_ID).is_none() || from_env(env, ENV_APPLE_PASSWORD).is_none())
    {
        return Err(unavailable());
    }
    let apple_id = apple_id_with(env, interactive, ask_line)?;
    password_with(env, &apple_id, interactive, ask_password)
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

    struct MapEnv(Vec<(&'static str, &'static str)>);
    impl Env for MapEnv {
        fn get(&self, key: &str) -> Option<std::ffi::OsString> {
            self.0
                .iter()
                .find(|(k, _)| *k == key)
                .map(|(_, v)| v.into())
        }
    }

    fn no_prompt(_: &str) -> Result<String> {
        panic!("must not prompt")
    }

    #[test]
    fn credentials_from_env_skip_prompts() {
        let env = MapEnv(vec![
            (ENV_APPLE_ID, "Me@Example.com"),
            (ENV_APPLE_PASSWORD, "pw"),
        ]);
        let c = resolve_with(&env, false, &mut no_prompt, &mut no_prompt).unwrap();
        assert_eq!(c.apple_id, "me@example.com");
        assert_eq!(c.password(), "pw");
    }

    #[test]
    fn missing_credentials_without_terminal_fail() {
        // Only one variable set, and an empty one counts as unset.
        for env in [
            MapEnv(vec![(ENV_APPLE_ID, "me@example.com")]),
            MapEnv(vec![
                (ENV_APPLE_ID, "me@example.com"),
                (ENV_APPLE_PASSWORD, ""),
            ]),
            MapEnv(vec![]),
        ] {
            let e = resolve_with(&env, false, &mut no_prompt, &mut no_prompt).unwrap_err();
            assert_eq!(e.code, ErrorCode::CredentialsUnavailable);
        }
    }

    #[test]
    fn missing_credentials_are_prompted_on_a_terminal() {
        let env = MapEnv(vec![(ENV_APPLE_ID, "me@example.com")]);
        let mut asked = Vec::new();
        let mut password = |p: &str| {
            asked.push(p.to_owned());
            Ok("secret".to_owned())
        };
        let c = resolve_with(&env, true, &mut no_prompt, &mut password).unwrap();
        assert_eq!(c.password(), "secret");
        assert_eq!(asked, ["Password: "]);
    }
}
