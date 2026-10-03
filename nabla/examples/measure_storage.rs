//! Measure Nabla's on-disk cost per REGISTERED WALLET.
//!
//! `cargo run -p axiom-nabla --release --features dev-mode \
//!     --features axiom-core-logic/dev-mode --example measure_storage`
//!
//! A registered wallet is an SMT leaf, persisted as a `WalOp::Put` in the WAL
//! (`nabla/src/wal.rs`). Sizes are taken at N = 0, 1_000 and 10_000 and the
//! per-wallet figure comes from the DIFFERENCE, so fixed overhead is excluded.
//!
//! Note for whoever reads the numbers: Lambda's `lambda.db` is a separate
//! store, is SQLCipher-encrypted, and scales with TRANSACTIONS rather than
//! wallets — it is not measured here.

use axiom_nabla::smt::SparseMerkleTree;
use axiom_nabla::types::NablaEntry;
use axiom_nabla::wal::{WalOp, WriteAheadLog};

fn entry(i: u64) -> NablaEntry {
    let mut wid = [0u8; 32];
    wid[..8].copy_from_slice(&i.to_le_bytes());
    NablaEntry {
        wallet_id: wid,
        current_state: [0xA1u8; 32],
        tx_hash: [0xB2u8; 32],
        tick: 1_789_180_000,
        wallet_seq: 1,
        group_members: None,
        status: axiom_nabla::types::WalletStatus::Normal,
        client_pk: [0u8; 32],
        client_sig: vec![0u8; 64],
        received_from: None,
    }
}

fn measure(n: u64, dir: &std::path::Path) -> (u64, usize) {
    let _ = std::fs::remove_file(dir.join("m.wal"));
    let mut wal = WriteAheadLog::open(&dir.join("m.wal")).expect("wal open");
    let mut smt = SparseMerkleTree::new();
    for i in 0..n {
        let e = entry(i);
        let value = {
            let mut v = Vec::new();
            ciborium::into_writer(&e, &mut v).unwrap();
            v
        };
        // `put` is #[cfg(test)]-only; this is the production entry point.
        smt.put_with_proof(&e, axiom_nabla::smt::PutProof::RestoredFromLocalState(None));
        wal.append(&WalOp::Put {
            key: e.wallet_id,
            value,
            client_pk: [0u8; 32],
            client_sig: vec![0u8; 64],
            seq_proof: None,
        })
        .expect("append");
    }
    drop(wal);
    let bytes = std::fs::metadata(dir.join("m.wal")).map(|m| m.len()).unwrap_or(0);
    (bytes, smt.len())
}

fn main() {
    let dir = std::env::temp_dir().join(format!("axiom_storage_{}", std::process::id()));
    std::fs::create_dir_all(&dir).unwrap();

    println!("== Nabla WAL bytes by registered-wallet count ==\n");
    let mut at = std::collections::BTreeMap::new();
    for n in [0u64, 1_000, 10_000] {
        let (bytes, leaves) = measure(n, &dir);
        println!("{:>7} wallets -> {:>12} bytes on disk  (SMT leaves: {})", n, bytes, leaves);
        at.insert(n, bytes);
    }

    let per_1k = (at[&1_000] as f64 - at[&0] as f64) / 1_000.0;
    let per_10k = (at[&10_000] as f64 - at[&0] as f64) / 10_000.0;
    println!("\nbytes/wallet from (1k - 0)/1k   = {:.1}", per_1k);
    println!("bytes/wallet from (10k - 0)/10k = {:.1}   <- use this one", per_10k);
    println!("fixed overhead at 0 wallets     = {} bytes", at[&0]);

    let per = per_10k;
    println!("\n== projected WAL size, wallets only, before compaction ==");
    for w in [10_000u64, 100_000, 1_000_000] {
        println!("{:>9} wallets -> {:>8.2} MB", w, (w as f64 * per) / 1_048_576.0);
    }
    let _ = std::fs::remove_dir_all(&dir);
}
