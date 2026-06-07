use crate::bead::Bead;
use crate::braid::{AddBeadStatus, Braid};
use crate::db::{BraidpoolDBTypes, InsertTupleTypes};
use crate::utils::BeadHash;
use std::collections::HashMap;
use tracing::{debug, warn};

/// Everything the adapter needs after extending the braid with a batch of
/// downloaded beads: what to persist, and how to score the sync peer.
#[derive(Debug, Default, Clone)]
pub struct IngestOutcome {
    /// Beads newly added to the DAG (to be persisted).
    pub beads_to_persist: Vec<Bead>,
    /// Orphans promoted into the DAG by this batch (also persisted). May be
    /// non-empty even for beads that arrived earlier in the same batch than the
    /// parent that connected them.
    pub promoted_orphans: Vec<Bead>,
    /// Snapshot of the braid index mapping, required by the batch DB insert.
    /// Empty when nothing was added.
    pub bead_index_mapping: HashMap<BeadHash, (usize, u32)>,
    /// Count of beads the braid rejected as invalid (for peer penalisation).
    pub invalid: usize,
    /// Count of beads newly added (for peer reward).
    pub added: usize,
}

impl IngestOutcome {
    /// Build the batch DB insert command for the persisted beads, or `None` when
    /// nothing was added (so the adapter can skip an empty send).
    pub fn into_db_command(self) -> Option<BraidpoolDBTypes> {
        if self.beads_to_persist.is_empty() {
            return None;
        }
        Some(BraidpoolDBTypes::InsertTupleTypes {
            query: InsertTupleTypes::InsertBeadsBatch {
                beads_to_insert: self.beads_to_persist,
                removed_orphans: self.promoted_orphans,
                bead_index_mapping: self.bead_index_mapping,
            },
        })
    }
}

/// Extend `braid` with a batch of downloaded `beads`, collecting what to persist
/// and the per-batch scoring counts.
///
/// Duplicate beads and beads still missing parents (orphans parked for a later
/// batch) are silently skipped; only newly-added beads and the orphans they
/// promote are returned for persistence.
///
/// ```ignore
/// let outcome = {
///     let mut guard = braid_arc.write().await; // RwLockWriteGuard<Braid>
///     ingest_beads(&mut guard, &beads)          // &mut *guard : &mut Braid
/// }; // guard dropped here, lock released
/// if let Some(cmd) = outcome.into_db_command() {
///     db_tx.send(cmd).await?;                   // no braid lock held here
/// }
/// ```
pub fn ingest_beads(braid: &mut Braid, beads: &[Bead]) -> IngestOutcome {
    let mut outcome = IngestOutcome::default();
    for bead in beads {
        match braid.extend(bead) {
            AddBeadStatus::BeadAdded { promoted_orphans } => {
                outcome.added += 1;
                debug!(beadhash = %bead.block_header.block_hash(), "Bead added to batch for insertion");
                if !promoted_orphans.is_empty() {
                    debug!(
                        count = promoted_orphans.len(),
                        "Orphan beads removed from the orphan set upon extension of current bead"
                    );
                }
                outcome.beads_to_persist.push(bead.clone());
                outcome.promoted_orphans.extend(promoted_orphans);
            }
            AddBeadStatus::InvalidBead => outcome.invalid += 1,
            // Already in the DAG, or parents not yet present (a later bead in
            // this or a future batch may promote it). Nothing to persist now.
            AddBeadStatus::DagAlreadyContainsBead => {
                warn!("A duplicate bead received during IBD !");
            }
            AddBeadStatus::ParentsNotYetReceived => {
                warn!("Received an orphan bead during IBD.");
            }
        }
    }
    if outcome.added > 0 {
        outcome.bead_index_mapping = braid.bead_index_mapping.clone();
    }
    outcome
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::utils::test_utils::test_utility_functions::emit_bead;

    /// A fresh bead whose only parent is `parent`.
    fn child_of(parent: &Bead) -> Bead {
        let mut b = emit_bead();
        b.committed_metadata
            .parents
            .insert(parent.block_header.block_hash());
        b
    }

    #[test]
    fn applies_in_order_batch() {
        let genesis = emit_bead();
        let mut braid = Braid::new(vec![genesis.clone()]);
        let c1 = child_of(&genesis);
        let c2 = child_of(&c1);

        let outcome = ingest_beads(&mut braid, &[c1.clone(), c2.clone()]);

        assert_eq!(outcome.added, 2);
        assert_eq!(outcome.invalid, 0);
        assert_eq!(outcome.beads_to_persist.len(), 2);
        assert!(outcome.promoted_orphans.is_empty());
        assert!(!outcome.bead_index_mapping.is_empty());
    }

    #[test]
    fn out_of_order_batch_persists_promoted_orphan() {
        // Grandchild arrives before its parent within the same batch.
        let genesis = emit_bead();
        let mut braid = Braid::new(vec![genesis.clone()]);
        let child = child_of(&genesis);
        let grandchild = child_of(&child);

        let outcome = ingest_beads(&mut braid, &[grandchild.clone(), child.clone()]);

        // Only `child` reports BeadAdded directly; `grandchild` is promoted by it.
        assert_eq!(outcome.added, 1);
        assert_eq!(outcome.beads_to_persist.len(), 1);
        assert_eq!(
            outcome.beads_to_persist[0].block_header.block_hash(),
            child.block_header.block_hash()
        );
        assert_eq!(outcome.promoted_orphans.len(), 1);
        assert_eq!(
            outcome.promoted_orphans[0].block_header.block_hash(),
            grandchild.block_header.block_hash()
        );
        // The whole chain is now connected.
        assert!(braid.orphan_beads.is_empty());
    }

    #[test]
    fn invalid_bead_counted_not_persisted() {
        let genesis = emit_bead();
        let mut braid = Braid::new(vec![genesis]);
        // A non-genesis bead with no parents is invalid.
        let invalid = emit_bead();

        let outcome = ingest_beads(&mut braid, &[invalid]);

        assert_eq!(outcome.added, 0);
        assert_eq!(outcome.invalid, 1);
        assert!(outcome.beads_to_persist.is_empty());
        assert!(outcome.bead_index_mapping.is_empty());
    }

    #[test]
    fn into_db_command_maps_to_batch_insert() {
        let genesis = emit_bead();
        let mut braid = Braid::new(vec![genesis.clone()]);
        let child = child_of(&genesis);
        let outcome = ingest_beads(&mut braid, &[child.clone()]);

        match outcome.into_db_command() {
            Some(BraidpoolDBTypes::InsertTupleTypes {
                query:
                    InsertTupleTypes::InsertBeadsBatch {
                        beads_to_insert,
                        removed_orphans,
                        bead_index_mapping,
                    },
            }) => {
                assert_eq!(beads_to_insert.len(), 1);
                assert!(removed_orphans.is_empty());
                assert!(!bead_index_mapping.is_empty());
            }
            other => panic!("expected InsertBeadsBatch, got {:?}", other),
        }
    }

    #[test]
    fn into_db_command_is_none_when_nothing_added() {
        let outcome = IngestOutcome::default();
        assert!(outcome.into_db_command().is_none());
    }
}
