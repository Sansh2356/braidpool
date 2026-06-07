use super::*;
use bitcoin::BlockHash;
use libp2p::identity::Keypair;

fn peer() -> PeerId {
    PeerId::from(Keypair::generate_ed25519().public())
}

/// Deterministic distinct bead hash from a seed.
fn hash(n: u32) -> BeadHash {
    let mut bytes = [0u8; 32];
    bytes[..4].copy_from_slice(&n.to_be_bytes());
    BlockHash::from_byte_array(bytes)
}

fn hashes(range: std::ops::Range<u32>) -> Vec<BeadHash> {
    range.map(hash).collect()
}

/// A cheap, distinct bead: a default bead whose only varied field is the header
/// nonce, which is enough to give it a unique block hash without any crypto.
fn bead(n: u32) -> Bead {
    let mut b = Bead::default();
    b.block_header.nonce = n;
    b
}

fn beads(range: std::ops::Range<u32>) -> Vec<Bead> {
    range.map(bead).collect()
}

fn page_hashes(beads: &[Bead]) -> Vec<BeadHash> {
    beads.iter().map(|b| b.block_header.block_hash()).collect()
}

/// Map the hashes the engine asked for back to the beads in `page`, simulating
/// the adapter answering a `GetBeads(batch)` request.
fn lookup(requested: &[BeadHash], page: &[Bead]) -> Vec<Bead> {
    let by_hash: std::collections::HashMap<BeadHash, &Bead> = page
        .iter()
        .map(|b| (b.block_header.block_hash(), b))
        .collect();
    requested.iter().map(|h| by_hash[h].clone()).collect()
}

fn engine() -> SyncEngine {
    SyncEngine::new(RetryPolicy::default())
}

/// Pull the hashes out of the (single) `GetBeads` request in an action list.
fn get_beads(actions: &[SyncAction]) -> Option<Vec<BeadHash>> {
    actions.iter().find_map(|a| match a {
        SyncAction::SendRequest {
            request: BeadRequest::GetBeads(BeadHashes(h)),
            ..
        } => Some(h.clone()),
        _ => None,
    })
}

fn has_request_hash_page(actions: &[SyncAction]) -> bool {
    actions
        .iter()
        .any(|a| matches!(a, SyncAction::RequestHashPage { .. }))
}

/// Drive an engine to `FetchingBeads` with `page` as the hash page and an empty
/// peer-tip set (so no pruning), returning the engine, peer, and emitted actions.
fn engine_downloading(page: &[Bead]) -> (SyncEngine, PeerId, Vec<SyncAction>) {
    let mut e = engine();
    let p = peer();
    e.on_event(SyncEvent::Start { peer: p });
    e.on_event(SyncEvent::TipsReceived {
        peer: p,
        peer_tips: Vec::new(),
        already_synced: false,
    });
    let acts = e.on_event(SyncEvent::HashPageReceived {
        peer: p,
        hashes: page_hashes(page),
    });
    (e, p, acts)
}

#[test]
fn start_requests_tips() {
    let mut e = engine();
    let p = peer();
    let acts = e.on_event(SyncEvent::Start { peer: p });
    assert_eq!(
        acts,
        vec![SyncAction::SendRequest {
            peer: p,
            request: BeadRequest::GetTips
        }]
    );
    assert_eq!(*e.state(), SyncState::AwaitingTips);
}

#[test]
fn tips_already_synced_completes() {
    let mut e = engine();
    let p = peer();
    e.on_event(SyncEvent::Start { peer: p });
    let acts = e.on_event(SyncEvent::TipsReceived {
        peer: p,
        peer_tips: vec![hash(1)],
        already_synced: true,
    });
    assert_eq!(acts, vec![SyncAction::MarkComplete]);
    assert_eq!(*e.state(), SyncState::Complete);
}

#[test]
fn tips_requests_hash_page() {
    let mut e = engine();
    let p = peer();
    e.on_event(SyncEvent::Start { peer: p });
    let acts = e.on_event(SyncEvent::TipsReceived {
        peer: p,
        peer_tips: vec![hash(9)],
        already_synced: false,
    });
    // The engine asks the adapter to fetch a page after the *current* braid tips
    // (filled in at execution time), rather than embedding tips itself.
    assert_eq!(acts, vec![SyncAction::RequestHashPage { peer: p }]);
    assert_eq!(*e.state(), SyncState::FetchingHashes);
}

#[test]
fn hash_page_requests_first_batch() {
    let page = beads(1..4); // 3 beads, single batch
    let (e, p, acts) = engine_downloading(&page);
    assert_eq!(
        acts,
        vec![SyncAction::SendRequest {
            peer: p,
            request: BeadRequest::GetBeads(BeadHashes(page_hashes(&page)))
        }]
    );
    assert_eq!(*e.state(), SyncState::FetchingBeads);
}

#[test]
fn final_short_page_completes() {
    let page = beads(1..4);
    let (mut e, p, acts) = engine_downloading(&page);
    let batch = lookup(&get_beads(&acts).unwrap(), &page);
    let acts = e.on_event(SyncEvent::BeadsReceived {
        peer: p,
        beads: batch.clone(),
    });
    assert_eq!(
        acts,
        vec![
            SyncAction::ApplyBeads { beads: batch },
            SyncAction::MarkComplete
        ]
    );
    assert_eq!(*e.state(), SyncState::Complete);
}

#[test]
fn multiple_batches_within_a_page() {
    // 600 beads -> first batch 500, then a final batch of 100.
    let page = beads(1..601);
    let (mut e, p, acts) = engine_downloading(&page);
    let first = lookup(&get_beads(&acts).unwrap(), &page);
    assert_eq!(first.len(), IBD_BATCH_SIZE);

    let acts = e.on_event(SyncEvent::BeadsReceived {
        peer: p,
        beads: first.clone(),
    });
    // Authorises applying the first batch and requests the remaining 100.
    assert_eq!(acts[0], SyncAction::ApplyBeads { beads: first });
    let second = lookup(
        &get_beads(&acts).expect("expected second GetBeads batch"),
        &page,
    );
    assert_eq!(second.len(), 100);
    assert_eq!(*e.state(), SyncState::FetchingBeads);

    // Final batch -> complete (600 < page max).
    let acts = e.on_event(SyncEvent::BeadsReceived {
        peer: p,
        beads: second,
    });
    assert!(acts.contains(&SyncAction::MarkComplete));
    assert_eq!(*e.state(), SyncState::Complete);
}

#[test]
fn full_page_requests_next_page() {
    // A page filled to the cap signals more pages may follow.
    let page = beads(1..(IBD_HASH_PAGE_MAX as u32 + 1));
    let (mut e, p, acts) = engine_downloading(&page);
    let mut batch = lookup(&get_beads(&acts).unwrap(), &page);
    loop {
        let acts = e.on_event(SyncEvent::BeadsReceived {
            peer: p,
            beads: batch,
        });
        if has_request_hash_page(&acts) {
            assert_eq!(*e.state(), SyncState::FetchingHashes);
            assert!(!acts.contains(&SyncAction::MarkComplete));
            return;
        }
        batch = lookup(
            &get_beads(&acts).expect("expected next GetBeads batch before page end"),
            &page,
        );
    }
}

#[test]
fn unsolicited_bead_drops_peer() {
    let page = beads(1..4);
    let (mut e, p, _) = engine_downloading(&page);
    let acts = e.on_event(SyncEvent::BeadsReceived {
        peer: p,
        beads: vec![bead(999)], // never requested
    });
    assert_eq!(acts[0], SyncAction::DisconnectPeer { peer: p });
    assert!(matches!(acts[1], SyncAction::ScheduleRetry { .. }));
    assert_eq!(*e.state(), SyncState::Idle);
}

#[test]
fn oversize_hash_page_drops_peer() {
    let mut e = engine();
    let p = peer();
    e.on_event(SyncEvent::Start { peer: p });
    e.on_event(SyncEvent::TipsReceived {
        peer: p,
        peer_tips: Vec::new(),
        already_synced: false,
    });
    let oversize = hashes(1..(IBD_HASH_PAGE_MAX as u32 + 2));
    let acts = e.on_event(SyncEvent::HashPageReceived {
        peer: p,
        hashes: oversize,
    });
    assert_eq!(acts[0], SyncAction::DisconnectPeer { peer: p });
    assert!(matches!(acts[1], SyncAction::ScheduleRetry { .. }));
    assert_eq!(*e.state(), SyncState::Idle);
}

#[test]
fn failure_schedules_retry() {
    let mut e = engine();
    let p = peer();
    e.on_event(SyncEvent::Start { peer: p });
    let acts = e.on_event(SyncEvent::RequestFailed { peer: p });
    assert_eq!(acts.len(), 1);
    assert!(matches!(acts[0], SyncAction::ScheduleRetry { .. }));
    assert_eq!(*e.state(), SyncState::Idle);
    assert_eq!(e.active_peer(), None);
}

#[test]
fn peer_exhausted_after_max_retries() {
    // Mirrors #309's per-peer retry_count / MAX_IBD_RETRIES: after `max_retries`
    // consecutive failures the peer is reported as exhausted so the adapter can
    // exclude it from selection.
    let max = 3;
    let mut e = SyncEngine::new(RetryPolicy::new(
        std::time::Duration::from_secs(1),
        std::time::Duration::from_secs(10),
        max,
    ));
    let p = peer();
    for _ in 0..max {
        e.on_event(SyncEvent::Start { peer: p });
        e.on_event(SyncEvent::RequestFailed { peer: p });
    }
    assert!(e.is_exhausted(&p));
    assert_eq!(e.exhausted_peers(), vec![p]);

    // A completed sync clears the tally.
    e.on_event(SyncEvent::Start { peer: p });
    e.on_event(SyncEvent::TipsReceived {
        peer: p,
        peer_tips: vec![hash(1)],
        already_synced: true,
    });
    assert!(!e.is_exhausted(&p));
    assert!(e.exhausted_peers().is_empty());
}

#[test]
fn failure_for_non_active_peer_is_ignored() {
    let mut e = engine();
    let p = peer();
    let other = peer();
    e.on_event(SyncEvent::Start { peer: p });
    let acts = e.on_event(SyncEvent::Timeout { peer: other });
    assert!(acts.is_empty());
    assert_eq!(*e.state(), SyncState::AwaitingTips);
    assert_eq!(e.active_peer(), Some(p));
}

#[test]
fn responses_from_stale_peer_are_ignored() {
    let mut e = engine();
    let p = peer();
    let stale = peer();
    e.on_event(SyncEvent::Start { peer: p });
    let acts = e.on_event(SyncEvent::TipsReceived {
        peer: stale,
        peer_tips: Vec::new(),
        already_synced: false,
    });
    assert!(acts.is_empty());
    assert_eq!(*e.state(), SyncState::AwaitingTips);
}

#[test]
fn retry_backoff_grows_and_caps() {
    let policy = RetryPolicy::new(
        std::time::Duration::from_secs(2),
        std::time::Duration::from_secs(10),
        3,
    );
    assert_eq!(policy.delay(0), std::time::Duration::from_secs(2));
    assert_eq!(policy.delay(1), std::time::Duration::from_secs(4));
    assert_eq!(policy.delay(2), std::time::Duration::from_secs(8));
    // 2 * 2^3 = 16, capped at 10.
    assert_eq!(policy.delay(3), std::time::Duration::from_secs(10));
    assert!(!policy.is_exhausted(2));
    assert!(policy.is_exhausted(3));
}
