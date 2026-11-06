//! Remote anisette-v3 client (SPEC Section 9.1).
//!
//! Protocol: `GET <server>/v3/client_info`, provisioning over a WebSocket
//! (`/v3/provisioning_session`) relaying Apple's `midStartProvisioning` /
//! `midFinishProvisioning`, then `POST <server>/v3/get_headers` with the
//! stored ADI state. Needs a minimal WebSocket client and JSON (`formats::json`).
//!
//! Reference: omnisette `remote_anisette_v3.rs` (MPL-2.0), isideload
//! `anisette/remote_v3` (MIT).
//!
//! TODO: implement.
