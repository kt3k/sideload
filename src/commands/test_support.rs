//! Test support: a scripted Developer Services transport.

use std::collections::BTreeMap;

use crate::Result;
use crate::anisette::{AnisetteData, AnisetteProvider};
use crate::apple::Transport;
use crate::apple::developer::Developer;
use crate::apple::gsa::Session;
use crate::formats::plist::{Dictionary, Value};
use crate::net::NetResult;
use crate::net::http::{Request, Response};
use std::cell::RefCell;
use std::rc::Rc;

pub struct NoAnisette;
impl AnisetteProvider for NoAnisette {
    fn headers(&mut self) -> Result<AnisetteData> {
        Ok(AnisetteData::default())
    }
}

/// Replies per Developer Services action; records (action, request).
#[derive(Default)]
pub struct Script {
    pub replies: BTreeMap<&'static str, Dictionary>,
    pub calls: Vec<(String, Value)>,
}
pub struct Wire(pub Rc<RefCell<Script>>);
impl Transport for Wire {
    fn send(&mut self, r: &Request) -> NetResult<Response> {
        let action = r
            .url
            .rsplit('/')
            .next()
            .unwrap()
            .split(".action")
            .next()
            .unwrap()
            .to_owned();
        let body = crate::formats::plist::from_bytes(&r.body).unwrap();
        let mut script = self.0.borrow_mut();
        script.calls.push((action.clone(), body));
        let mut reply = script
            .replies
            .get(action.as_str())
            .cloned()
            .unwrap_or_default();
        reply.insert("resultCode", 0i64);
        Ok(Response {
            status: 200,
            headers: Vec::new(),
            body: Value::Dictionary(reply).to_xml(),
            url: r.url.clone(),
        })
    }
}

pub fn dict<const N: usize>(e: [(&str, Value); N]) -> Dictionary {
    e.into_iter().collect()
}

pub fn developer(script: &Rc<RefCell<Script>>) -> Developer<Wire> {
    Developer::with_transport(
        Session {
            adsid: "1".into(),
            token: "T".into(),
            expiry: None,
        },
        Box::new(NoAnisette),
        Wire(script.clone()),
    )
}
