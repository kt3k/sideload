//! The Core Interface (`ios/SPEC.md` Section 9): one JSON request in, one
//! JSON response out.

use std::path::PathBuf;

use sideload::formats::json::{self, Value};

use crate::account::{self, TwoFactor};
use crate::config::{Account, Config, req_str};
use crate::device;
use crate::error::{CoreError, invalid};
use crate::ops;

struct Response {
    result: Option<Value>,
    error: Option<CoreError>,
    session: Option<String>,
}

impl Response {
    fn ok(result: Value) -> Response {
        Response {
            result: Some(result),
            error: None,
            session: None,
        }
    }

    fn err(error: CoreError) -> Response {
        Response {
            result: None,
            error: Some(error),
            session: None,
        }
    }

    fn to_json(&self) -> Value {
        let mut entries = vec![("ok".to_owned(), Value::Bool(self.error.is_none()))];
        if let Some(r) = &self.result {
            entries.push(("result".into(), r.clone()));
        }
        if let Some(e) = &self.error {
            entries.push(("error".into(), error_json(e)));
        }
        if let Some(s) = &self.session {
            entries.push(("session".into(), Value::from(s.as_str())));
        }
        Value::Object(entries)
    }
}

fn error_json(e: &CoreError) -> Value {
    Value::object([
        ("code", Value::from(e.code.as_str())),
        ("phase", e.phase.as_deref().map_or(Value::Null, Value::from)),
        ("message", Value::from(e.message.as_str())),
    ])
}

/// Handles one request. Never panics on bad input.
pub fn handle(request: &str, two_factor: TwoFactor<'_>) -> String {
    let response = match json::parse(request) {
        Ok(v) => dispatch(&v, two_factor),
        Err(e) => Response::err(invalid(format!("request is not JSON: {e}"))),
    };
    response.to_json().to_string()
}

fn records_json(records: &[crate::registry::Record]) -> Value {
    Value::Array(records.iter().map(|r| r.to_json()).collect())
}

fn dispatch(req: &Value, two_factor: TwoFactor<'_>) -> Response {
    let op = match req.get("op").and_then(Value::as_str) {
        Some(op) => op,
        None => return Response::err(invalid("missing `op`")),
    };
    if op == "version" {
        return Response::ok(Value::object([(
            "version",
            Value::from(env!("CARGO_PKG_VERSION")),
        )]));
    }
    let cfg = match Config::from_json(req.get("config")) {
        Ok(c) => c,
        Err(e) => return Response::err(e),
    };
    let args = req.get("args");
    let account = || Account::from_json(req.get("account"));
    macro_rules! tryr {
        ($e:expr) => {
            match $e {
                Ok(v) => v,
                Err(e) => return Response::err(e),
            }
        };
    }
    match op {
        "prepare_anisette" => {
            tryr!(account::prepare_anisette(&cfg));
            Response::ok(Value::object([("ready", Value::Bool(true))]))
        }
        "apps" => {
            let records = tryr!(ops::list(&cfg));
            Response::ok(Value::object([("apps", records_json(&records))]))
        }
        "forget" => {
            let id = tryr!(req_str(args, "bundle_id"));
            tryr!(ops::forget(&cfg, &id));
            Response::ok(Value::object::<&str>([]))
        }
        "import_pairing" => {
            let path = PathBuf::from(tryr!(req_str(args, "path")));
            let udid = tryr!(device::import_pairing(&cfg, &path));
            Response::ok(Value::object([(
                "udid",
                udid.map_or(Value::Null, Value::from),
            )]))
        }
        "connect" => {
            let link = tryr!(
                device::connect(&cfg).map_err(|e| e.at(crate::error::phase::CONNECTING_DEVICE))
            );
            Response::ok(Value::object([
                ("udid", Value::from(link.info.udid)),
                ("name", Value::from(link.info.name)),
                ("product_version", Value::from(link.info.product_version)),
            ]))
        }
        "login" => {
            let acct = tryr!(account());
            let mut login = tryr!(account::log_in(&cfg, &acct, two_factor));
            let session = login.new_session.take();
            let teams = match login.dev.list_teams() {
                Ok(t) => t,
                Err(e) => {
                    return Response {
                        session,
                        ..Response::err(e.into())
                    };
                }
            };
            Response {
                session,
                ..Response::ok(Value::object([(
                    "teams",
                    Value::Array(
                        teams
                            .into_iter()
                            .map(|t| {
                                Value::object([
                                    ("team_id", Value::from(t.team_id)),
                                    ("name", t.name.map_or(Value::Null, Value::from)),
                                ])
                            })
                            .collect(),
                    ),
                )]))
            }
        }
        "install" => {
            let acct = tryr!(account());
            let ipa = PathBuf::from(tryr!(req_str(args, "ipa")));
            let out = ops::install(&cfg, &acct, &ipa, two_factor);
            let mut r = match out.result {
                Ok(record) => Response::ok(Value::object([("app", record.to_json())])),
                Err(e) => Response::err(e),
            };
            r.session = out.session;
            r
        }
        "refresh" => {
            let acct = tryr!(account());
            let bundle_ids = match args.and_then(|a| a.get("bundle_ids")) {
                None | Some(Value::Null) => None,
                Some(Value::Array(items)) => Some(tryr!(
                    items
                        .iter()
                        .map(|v| v
                            .as_str()
                            .map(str::to_owned)
                            .ok_or_else(|| invalid("`bundle_ids` must be strings")))
                        .collect::<Result<Vec<_>, _>>()
                )),
                Some(_) => return Response::err(invalid("`bundle_ids` must be an array")),
            };
            let within = match args.and_then(|a| a.get("within")) {
                None | Some(Value::Null) => None,
                Some(Value::Number(n)) if *n >= 0.0 => Some(*n as i64),
                Some(_) => {
                    return Response::err(invalid("`within` must be a non-negative number"));
                }
            };
            let out = ops::refresh(&cfg, &acct, bundle_ids.as_deref(), within, two_factor);
            let apps = Value::Array(
                out.apps
                    .iter()
                    .map(|a| {
                        Value::object([
                            ("bundle_id", Value::from(a.bundle_id.as_str())),
                            ("name", Value::from(a.name.as_str())),
                            ("ok", Value::Bool(a.error.is_none())),
                            (
                                "action",
                                a.action.map_or(Value::Null, |x| Value::from(x.as_str())),
                            ),
                            ("error", a.error.as_ref().map_or(Value::Null, error_json)),
                        ])
                    })
                    .collect(),
            );
            Response {
                result: Some(Value::object([("apps", apps)])),
                error: out.error,
                session: out.session,
            }
        }
        other => Response::err(invalid(format!("unknown op `{other}`"))),
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::registry::Registry;
    use crate::registry::tests::{record, temp_dir};

    fn call(req: &str) -> Value {
        let mut never = || -> Option<String> { panic!("must not ask") };
        json::parse(&handle(req, &mut never)).unwrap()
    }

    fn code(v: &Value) -> &str {
        v.get("error")
            .unwrap()
            .get("code")
            .unwrap()
            .as_str()
            .unwrap()
    }

    #[test]
    fn version_and_bad_requests() {
        let v = call(r#"{"op":"version"}"#);
        assert_eq!(v.get("ok").unwrap().as_bool(), Some(true));
        assert_eq!(
            v.get("result").unwrap().get("version").unwrap().as_str(),
            Some(env!("CARGO_PKG_VERSION"))
        );
        for bad in [
            "nope",
            "{}",
            r#"{"op":"apps"}"#,
            r#"{"op":"what","config":{"data_dir":"/x"}}"#,
        ] {
            let v = call(bad);
            assert_eq!(v.get("ok").unwrap().as_bool(), Some(false), "{bad}");
            assert_eq!(code(&v), "invalid_arguments", "{bad}");
        }
    }

    #[test]
    fn apps_and_forget() {
        let dir = temp_dir("api-apps");
        let mut reg = Registry::default();
        reg.upsert(record("a.T", "A"));
        reg.save(&dir).unwrap();
        let cfg = format!(
            r#""config":{{"data_dir":{}}}"#,
            Value::from(dir.to_str().unwrap())
        );
        let v = call(&format!(r#"{{"op":"apps",{cfg}}}"#));
        let apps = v
            .get("result")
            .unwrap()
            .get("apps")
            .unwrap()
            .as_array()
            .unwrap();
        assert_eq!(apps.len(), 1);
        assert_eq!(apps[0].get("bundle_id").unwrap().as_str(), Some("a.T"));

        let v = call(&format!(
            r#"{{"op":"forget",{cfg},"args":{{"bundle_id":"a.T"}}}}"#
        ));
        assert_eq!(v.get("ok").unwrap().as_bool(), Some(true));
        let v = call(&format!(
            r#"{{"op":"forget",{cfg},"args":{{"bundle_id":"a.T"}}}}"#
        ));
        assert_eq!(code(&v), "invalid_arguments");
    }

    #[test]
    fn refresh_reports_per_app_failure() {
        let dir = temp_dir("api-refresh");
        let mut reg = Registry::default();
        reg.upsert(record("a.T", "A"));
        reg.save(&dir).unwrap();
        let cfg = format!(
            r#""config":{{"data_dir":{}}}"#,
            Value::from(dir.to_str().unwrap())
        );
        let v = call(&format!(
            r#"{{"op":"refresh",{cfg},"account":{{"apple_id":"a@b.c"}},"args":{{"within":null}}}}"#
        ));
        assert_eq!(code(&v), "device_not_paired");
        let apps = v
            .get("result")
            .unwrap()
            .get("apps")
            .unwrap()
            .as_array()
            .unwrap();
        assert_eq!(apps[0].get("ok").unwrap().as_bool(), Some(false));
        let v = call(&format!(
            r#"{{"op":"refresh",{cfg},"account":{{"apple_id":"a@b.c"}},"args":{{"within":-1}}}}"#
        ));
        assert_eq!(code(&v), "invalid_arguments");
    }

    #[test]
    fn connect_without_pairing() {
        let dir = temp_dir("api-connect");
        let cfg = format!(
            r#""config":{{"data_dir":{}}}"#,
            Value::from(dir.to_str().unwrap())
        );
        let v = call(&format!(r#"{{"op":"connect",{cfg}}}"#));
        assert_eq!(code(&v), "device_not_paired");
        assert_eq!(
            v.get("error").unwrap().get("phase").unwrap().as_str(),
            Some("ConnectingDevice")
        );
    }
}
