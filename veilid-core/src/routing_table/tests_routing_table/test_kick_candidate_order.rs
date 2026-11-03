use super::*;

fn node_id(last_byte: u8) -> BareNodeId {
    let mut bytes = [0u8; 32];
    bytes[31] = last_byte;
    BareNodeId::new(&bytes)
}

fn candidate(
    last_byte: u8,
    state: BucketEntryState,
    time_added: u64,
    expired: bool,
) -> KickCandidate {
    KickCandidate {
        node_id: node_id(last_byte),
        state,
        time_added: Timestamp::new(time_added),
        expired,
    }
}

fn kick_order(mut candidates: Vec<KickCandidate>) -> Vec<u8> {
    candidates.sort_unstable();
    candidates
        .iter()
        .map(|c| *c.node_id.bytes().last().expect("node id has bytes"))
        .collect()
}

pub fn test_kick_candidates_sort_in_kick_order() {
    assert_eq!(
        kick_order(vec![
            candidate(5, BucketEntryState::Reliable, 100, false),
            candidate(4, BucketEntryState::Unreliable, 100, false),
            candidate(3, BucketEntryState::Unreliable, 100, true),
            candidate(2, BucketEntryState::Unreliable, 200, true),
            candidate(1, BucketEntryState::Dead, 100, false),
            candidate(0, BucketEntryState::Punished, 100, false),
        ]),
        vec![0, 1, 2, 3, 4, 5],
        "kick order is state ascending, then expired before unexpired, then most recently added \
         first"
    );
}

pub fn test_kick_candidate_order_breaks_ties_on_node_id() {
    assert_eq!(
        kick_order(vec![
            candidate(2, BucketEntryState::Unreliable, 100, false),
            candidate(1, BucketEntryState::Unreliable, 100, false),
        ]),
        vec![1, 2],
        "candidates alike in every other field are ordered by node id"
    );
}
