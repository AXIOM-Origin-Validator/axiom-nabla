// KI#232 diagnostic — READ-ONLY. Opens a COPY of a node's data dir and prints,
// for each txid given, the origin record and this node's judgment of it:
// contested, legs under its key, the verdict of the state it consumed (roots),
// and origin_vouch. The answer comes from the node's own records (RULE 0 §2).
//
//   cargo run -p axiom-nabla --example ki232_verdict_probe --features dev-mode \
//     --features axiom-core-logic/dev-mode -- <copied_data_dir> <txid_hex>...
use axiom_nabla::bloom::TxidServiceMode;
use axiom_nabla::crypto::Ed25519Signer;
use axiom_nabla::node::NablaNode;

fn main() {
    let args: Vec<String> = std::env::args().collect();
    let dir = &args[1];
    let signer = Ed25519Signer::from_seed(&[7u8; 32]);
    let mut n = NablaNode::open_with_options(dir, Box::new(signer), TxidServiceMode::Hashmap, true)
        .expect("open copied data dir");
    n.drain_fork_side_effects();
    for t in &args[2..] {
        let mut txid = [0u8; 32];
        txid.copy_from_slice(&hex::decode(t).expect("hex"));
        println!("== txid {}", &t[..16]);
        match n.smt().vouch_record(&txid) {
            None => println!("  origin record: NONE"),
            Some(e) => {
                let key = e.leg.key();
                println!("  origin record: contested={} first_seen={} key.pk={} key.consumed={}",
                    e.contested, e.first_seen_secs, hex::encode(&key.0[..4]), hex::encode(&key.1[..4]));
                println!("  legs_under(key)={} consumed_state_consumed={}",
                    n.smt().legs_under(&key).len(), n.smt().is_state_consumed(&key.1));
                println!("  judge_send={:?}", n.provenance().judge_send(n.smt(), &txid));
                println!("  producer admission: state_bound={}", axiom_nabla::ban::leg_is_state_bound(&e.leg));
                for s in &e.leg.seq_proof.sigs {
                    println!("    witness {} in_directory={}", hex::encode(&s.validator_pk[..4]),
                        n.is_directory_witness(&s.validator_pk));
                }
                println!("  verdict_of(consumed)={:?}", n.provenance().verdict_of(&key.0, &key.1));
                println!("  verdict_of(produced {})={:?}", hex::encode(&e.leg.new_state[..4]),
                    n.provenance().verdict_of(&key.0, &e.leg.new_state));
            }
        }
        println!("  origin_vouch={:?}", n.origin_vouch(&txid, Some(0)));
    }
}
