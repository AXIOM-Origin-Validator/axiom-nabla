//! Register a validator's FOB pool linkage (YP §19.6 / BoundedPools §10.0).
//!
//! Harness/operator tool — the ONE step that uses the validator's SPHINCS+
//! key ("SPHINCS+ is used only at link time, never in the tx"). Binds
//! `validator_id = BLAKE3(sphincs_pk)` to the stake wallet's address STRING
//! so `wallet.claim_validator_fees` can later fetch a claim attestation.
//!
//! Usage (per validator, idempotent — re-register bumps nothing unless
//! --epoch increases):
//!   cargo run -p axiom-nabla --features dev-mode --example register_pool_linkage -- \
//!     --sphincs-key ~/axiom/axiom-first-penguin-alpha/keys/sphincs.key \
//!     --wallet 'stake-alpha@axiom.test/ab12cd34ef-P' \
//!     --nabla 127.0.0.1:7300 --http 127.0.0.1:6226 [--epoch 1]
//!
//! The linkage store is per-node and in-memory: register against EVERY
//! hashmap (recording) node you want able to issue claim attestations.

use std::io::{Read, Write};
use std::net::TcpStream;
use std::time::Duration;

use axiom_nabla::transport::WireMessage;
use axiom_nabla::wire_client::RegisterValidatorPoolRequest;

fn arg(name: &str) -> Option<String> {
    let args: Vec<String> = std::env::args().collect();
    args.iter().position(|a| a == name).and_then(|i| args.get(i + 1).cloned())
}

/// GET /status on the node's HTTP port and pull `current_tick` — the link
/// signature must be over a tick inside the node's freshness window.
fn current_tick(http_addr: &str) -> Option<u64> {
    let mut s = TcpStream::connect(http_addr).ok()?;
    s.set_read_timeout(Some(Duration::from_millis(3000))).ok()?;
    write!(s, "GET /status HTTP/1.1\r\nHost: {http_addr}\r\nConnection: close\r\n\r\n").ok()?;
    let mut body = String::new();
    s.read_to_string(&mut body).ok()?;
    let key = "\"current_tick\":";
    let at = body.find(key)? + key.len();
    let rest = &body[at..];
    let end = rest.find(|c: char| !c.is_ascii_digit() && c != ' ')?;
    rest[..end].trim().parse().ok()
}

fn main() {
    let key_path = arg("--sphincs-key").expect("--sphincs-key <path> required");
    let wallet = arg("--wallet").expect("--wallet <address string> required");
    let nabla = arg("--nabla").expect("--nabla <host:port> required");
    let http = arg("--http").expect("--http <host:port> required (status port, for current_tick)");
    let epoch: u64 = arg("--epoch").map(|e| e.parse().expect("--epoch u64")).unwrap_or(1);

    let sk = std::fs::read(&key_path).expect("read sphincs key");
    assert_eq!(sk.len(), 64, "sphincs.key must be 64 bytes (sk; pk = sk[32..64])");
    let pk: Vec<u8> = sk[32..64].to_vec();
    let validator_id: [u8; 32] = *blake3::hash(&pk).as_bytes();

    let tick = current_tick(&http).expect("current_tick from /status");
    let payload = axiom_core_logic::compute::compute_validator_pool_link_payload(
        &validator_id, &wallet, epoch, tick,
    );
    let sig = axiom_core_logic::compute::sign_sphincs(&sk, &payload).expect("sphincs sign");

    let req = WireMessage::RegisterValidatorPoolRequest(RegisterValidatorPoolRequest {
        validator_id,
        linked_wallet_id: wallet.clone(),
        sphincs_pk: pk,
        sphincs_sig: sig,
        linkage_epoch: epoch,
        tick,
    });
    let bytes = bincode::serialize(&req).expect("serialize");

    let mut s = TcpStream::connect(&nabla).expect("connect nabla TCP");
    s.set_read_timeout(Some(Duration::from_millis(5000))).unwrap();
    s.write_all(&(bytes.len() as u32).to_be_bytes()).unwrap();
    s.write_all(&bytes).unwrap();
    s.flush().unwrap();

    let mut lb = [0u8; 4];
    s.read_exact(&mut lb).expect("read reply len");
    let n = u32::from_be_bytes(lb) as usize;
    assert!(n < 1_000_000, "oversized reply");
    let mut buf = vec![0u8; n];
    s.read_exact(&mut buf).expect("read reply");
    match bincode::deserialize::<WireMessage>(&buf).expect("decode reply") {
        WireMessage::RegisterValidatorPoolResponse(r) => {
            println!(
                "status={} validator_id={} stored_wallet={} epoch={} tick={}",
                r.status,
                hex::encode(validator_id),
                r.stored_linked_wallet_id,
                r.stored_linkage_epoch,
                r.stored_at_tick,
            );
            // ALREADY-LINKED: an epoch-monotonicity rejection whose stored
            // linkage names OUR wallet means the binding is in place — the
            // idempotent-re-register case, success for the caller.
            let already = r.status == "REJECTED_EPOCH" && r.stored_linked_wallet_id == wallet;
            std::process::exit(if r.status == "REGISTERED" || already { 0 } else { 1 });
        }
        other => {
            eprintln!("unexpected reply: {other:?}");
            std::process::exit(2);
        }
    }
}
