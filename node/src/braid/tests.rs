use super::algorithms::*;
use super::{AddBeadStatus, BeadIdx, Braid, ExtendStrategy};
use crate::bead::Bead;
use crate::config::PoolNetwork;
use crate::make_test_braid;
use crate::utils::test_utils::emit_Bead;
use crate::utils::test_utils::JSONBraid;
use crate::{beadset, cohorts, relatives};
use bitcoin::Work;
use rand::{rngs::StdRng, seq::SliceRandom, Rng, SeedableRng};
use std::collections::{HashMap, HashSet};
use std::thread;
use std::time::Duration;

/// Validates that caches are populated and all relationships are localized within cohorts
fn check_cache(braid: &Braid) {
    println!("\n=== Cache Validation ===");

    // Count beads across all cohorts
    let total_beads: usize = braid.cohorts.iter().map(|c| c.len()).sum();

    // Check ancestor_cache population
    println!("Ancestor cache size: {}", braid.ancestor_cache.len());
    println!("Total beads in cohorts: {}", total_beads);

    // For linear blockchain (single bead per cohort), each bead should have an entry with an empty set
    // For braids with multiple beads per cohort, entries should be populated with intra-cohort ancestors

    // Check descendant_cache population
    println!("Descendant cache size: {}", braid.descendant_cache.len());

    // Descendant cache should have entries for beads that have descendants in their cohort
    // For linear chains, this might be empty or have entries with empty sets
    // The important thing is to check that populated entries are properly localized

    // Check tail_cache population
    println!("Tail cache size: {}", braid.tail_cache.len());
    assert_eq!(
        braid.tail_cache.len(),
        braid.cohorts.len(),
        "Tail cache should have one entry per cohort"
    );

    // Build a map from bead to its cohort for validation
    let mut bead_to_cohort: HashMap<BeadIdx, usize> = HashMap::new();
    for (cohort_idx, cohort) in braid.cohorts.iter().enumerate() {
        for &bead_idx in cohort {
            bead_to_cohort.insert(bead_idx, cohort_idx);
        }
    }

    // Validate ancestor_cache: all ancestors should be within the same cohort
    let mut ancestor_violations = 0;
    for (bead_idx, ancestors) in &braid.ancestor_cache {
        if let Some(&cohort_idx) = bead_to_cohort.get(bead_idx) {
            let cohort = &braid.cohorts[cohort_idx];
            for ancestor in ancestors {
                if !cohort.contains(ancestor) {
                    ancestor_violations += 1;
                    println!(
                        "Bead {} in cohort {} has ancestor {} outside the cohort",
                        bead_idx, cohort_idx, ancestor
                    );
                }
            }
        }
    }
    assert_eq!(
        ancestor_violations, 0,
        "Found {} ancestors outside their cohort boundaries",
        ancestor_violations
    );

    // Validate descendant_cache: all descendants should be within the same cohort
    let mut descendant_violations = 0;
    for (bead_idx, descendants) in &braid.descendant_cache {
        if let Some(&cohort_idx) = bead_to_cohort.get(bead_idx) {
            let cohort = &braid.cohorts[cohort_idx];
            for descendant in descendants {
                if !cohort.contains(descendant) {
                    descendant_violations += 1;
                    println!(
                        "⚠️  Bead {} in cohort {} has descendant {} outside the cohort",
                        bead_idx, cohort_idx, descendant
                    );
                }
            }
        }
    }
    assert_eq!(
        descendant_violations, 0,
        "Found {} descendants outside their cohort boundaries",
        descendant_violations
    );

    println!("All cache entries are properly localized within cohorts");
}

/// Helper to create Work from u64 for testing
fn work(v: u64) -> Work {
    let mut bytes = [0u8; 32];
    bytes[24..32].copy_from_slice(&v.to_be_bytes());
    Work::from_be_bytes(bytes)
}

#[test]
pub fn test_orphanage_occupancy() {
    // Construct a braid with a single genesis bead
    let genesis = emit_Bead(&[]);
    let parent = emit_Bead(&[&genesis]);
    let orphan_child = emit_Bead(&[&parent]); // will be missing parent initially

    let mut braid = Braid::new(vec![genesis.clone()], PoolNetwork::Cpunet);

    // The child arrives before its parent and is parked in the orphanage
    let status = braid.extend(&orphan_child);
    assert_eq!(status, AddBeadStatus::ParentsMissing);

    // Occupancy should be >0 immediately after orphan enters
    let occ_now = braid.orphanage_occupancy(Duration::from_micros(1));
    assert!(occ_now.is_some());

    // Wait a bit to accumulate occupancy time
    thread::sleep(Duration::from_millis(5));
    let occ_avg = braid
        .orphanage_occupancy(Duration::from_millis(1))
        .expect("should have enough elapsed time");
    assert!(
        occ_avg >= 1.0,
        "average occupancy should be at least 1, got {}",
        occ_avg
    );

    // The parent arrives and the orphan is adopted
    assert_eq!(
        braid.extend(&parent),
        AddBeadStatus::BeadAdded {
            promoted_orphans: vec![orphan_child.clone()]
        }
    );
    assert!(braid.orphanage.is_empty());

    // After adoption, occupancy should go to 0
    thread::sleep(Duration::from_millis(1));
    let occ_after = braid
        .orphanage_occupancy(Duration::from_millis(1))
        .expect("should have elapsed time");
    assert!(
        occ_after < 1.0,
        "occupancy should drop after adoption, got {}",
        occ_after
    );
}

#[test]
pub fn test_extend_functionality() {
    // Create a braid with one bead.
    let test_bead_0 = emit_Bead(&[]);

    let mut test_braid = Braid::new(vec![test_bead_0.clone()], PoolNetwork::Cpunet);

    // Verify initial state
    assert_eq!(test_braid.beads.len(), 1);
    assert_eq!(test_braid.cohorts, cohorts!([0]));

    // Test simple chain extension: 0 -> 1 -> 2
    let test_bead_1 = emit_Bead(&[&test_bead_0]);
    let result = test_braid.extend(&test_bead_1);
    assert_eq!(
        result,
        AddBeadStatus::BeadAdded {
            promoted_orphans: vec![]
        }
    );
    assert_eq!(test_braid.beads.len(), 2);
    assert_eq!(test_braid.cohorts, cohorts!([0], [1]));

    let test_bead_2 = emit_Bead(&[&test_bead_1]);
    let result = test_braid.extend(&test_bead_2);
    assert_eq!(
        result,
        AddBeadStatus::BeadAdded {
            promoted_orphans: vec![]
        }
    );
    assert_eq!(test_braid.beads.len(), 3);
    assert_eq!(test_braid.cohorts, cohorts!([0], [1], [2])); // Should have at least 3 cohorts

    // Test branching: beads 3 and 4 both branch from bead 2
    let test_bead_3 = emit_Bead(&[&test_bead_2]);
    let test_bead_4 = emit_Bead(&[&test_bead_2]);
    let result = test_braid.extend(&test_bead_3);
    assert_eq!(
        result,
        AddBeadStatus::BeadAdded {
            promoted_orphans: vec![]
        }
    );
    let result = test_braid.extend(&test_bead_4);
    assert_eq!(
        result,
        AddBeadStatus::BeadAdded {
            promoted_orphans: vec![]
        }
    );
    assert_eq!(test_braid.beads.len(), 5);
    assert_eq!(test_braid.cohorts, cohorts!([0], [1], [2], [3, 4]));

    // Test merge: bead 5 merges from beads 3 and 4
    let test_bead_5 = emit_Bead(&[&test_bead_3, &test_bead_4]);
    let result = test_braid.extend(&test_bead_5);
    //println!(
    //    "\nFinal cohorts before multi-cohort reference: {:?}",
    //    test_braid.cohorts
    //);
    assert_eq!(
        result,
        AddBeadStatus::BeadAdded {
            promoted_orphans: vec![]
        }
    );
    assert_eq!(test_braid.beads.len(), 6);
    assert_eq!(test_braid.cohorts, cohorts!([0], [1], [2], [3, 4], [5]));

    // Verify braid integrity
    assert_eq!(test_braid.geneses, beadset![0]); // Still only one genesis
    assert_eq!(test_braid.tips, beadset![5]); // Bead 5 is the only tip
    assert!(
        test_braid.orphanage.is_empty() && test_braid.missing_parents.is_empty(),
        "No orphans should remain"
    );

    // Add bead 6 that references a parent from multiple cohorts back (bead 1).
    // Bead 6 is not a descendant of 2..5, so the cuts after cohort {1} disappear
    // and everything from bead 2 onwards merges into one cohort.
    let test_bead_6 = emit_Bead(&[&test_bead_1]);
    let result = test_braid.extend(&test_bead_6);
    assert_eq!(
        result,
        AddBeadStatus::BeadAdded {
            promoted_orphans: vec![]
        }
    );
    assert_eq!(test_braid.beads.len(), 7);
    assert_eq!(test_braid.cohorts, cohorts!([0], [1], [2, 3, 4, 5, 6]));
    assert_eq!(test_braid.tips, beadset![5, 6]);

    // The incremental result must match a from-scratch computation
    let mut scratch = HashMap::new();
    let expected = cohorts(
        &test_braid.parents,
        &test_braid.children,
        &geneses(&test_braid.parents),
        &mut scratch,
    );
    assert_eq!(test_braid.cohorts, expected);
    check_cache(&test_braid);
}

#[test]
pub fn test_non_head_cohort_extension() {
    // This test validates that cohorts maintain proper boundaries when extending
    // with a bead that does not point to the tail (head) of the braid.
    //
    // The braid looks like this:
    //
    // 0 - 1 - 2 - 4 - 6
    //       \   /    /
    //         3-----5
    //
    // (5 has parent 3 only; 6 has parents 4 and 5)
    //
    // Test that the cohorts after 0,1,2,3,4 are added are:
    //   {0} {1} {2,3} {4}
    // After adding 5, the cohorts must be:
    //   {0} {1} {2,3,4,5} with tips {4, 5}
    // After adding 6, the cohorts must be:
    //   {0} {1} {2,3,4,5} {6}
    //

    // Create initial braid with beads 0, 1, 2, 3, 4
    let mut test_braid = make_test_braid!(
        0 => [],
        1 => [0],
        2 => [1],
        3 => [1],
        4 => [2,3],
    );

    // This should print [{0}, {1}, {2,3}, {4}]
    println!("Cohorts after adding 0,1,2,3,4: {:?}", test_braid.cohorts);

    // Verify correct behavior: beads 2 and 3 should be in the same cohort
    // because they both have the same ancestors {0}, making them topologically equivalent
    assert_eq!(
        test_braid.cohorts.len(),
        4,
        "Correct behavior: should have 4 cohorts: {{0}} {{1}} {{2,3}} {{4}}"
    );

    assert_eq!(test_braid.cohorts, cohorts!([0], [1], [2, 3], [4]));

    // Add bead 5 (references only 3, which is not in the head cohort), so the
    // cut between {2,3} and {4} disappears
    let test_bead_5 = emit_Bead(&[&test_braid.beads[3]]);
    assert_eq!(
        test_braid.extend(&test_bead_5),
        AddBeadStatus::BeadAdded {
            promoted_orphans: vec![]
        }
    );
    assert_eq!(test_braid.cohorts, cohorts!([0], [1], [2, 3, 4, 5]));
    assert_eq!(test_braid.tips, beadset![4, 5]);

    // Add bead 6 (references both tips 4 and 5), which forms a new cohort
    let test_bead_6 = emit_Bead(&[&test_braid.beads[4], &test_braid.beads[5]]);
    assert_eq!(
        test_braid.extend(&test_bead_6),
        AddBeadStatus::BeadAdded {
            promoted_orphans: vec![]
        }
    );
    assert_eq!(test_braid.cohorts, cohorts!([0], [1], [2, 3, 4, 5], [6]));
}

#[test]
pub fn test_json_braid_end_to_end() {
    // This test validates orphan processing by adding beads in random order, which also exercises
    // our ancestor_cache in finding cohorts.
    // After all beads are added (and orphans processed), the final braid structure
    // should match the expected structure from the JSON file.

    // Test with ALL available JSON braid files
    for (json_braid, filename) in JSONBraid::tests() {
        println!("\n=== Testing with {} ===", filename);
        println!(
            "JSON braid has {} beads and {} cohorts",
            json_braid.parents.len(),
            json_braid.cohorts.len()
        );

        // Create beads based on the JSON structure using JSONBraid::make_Braid()
        let reference_braid = json_braid.make_Braid();

        println!(
            "Created reference braid with {} beads",
            reference_braid.beads.len()
        );
        println!("Reference cohorts: {:?}", reference_braid.cohorts);

        // Separate genesis and non-genesis beads for random order testing
        let mut genesis_beads = Vec::new();
        let mut non_genesis_beads = Vec::new();

        for bead in &reference_braid.beads {
            if bead.committed_metadata.parents.is_empty() {
                genesis_beads.push(bead.clone());
            } else {
                non_genesis_beads.push(bead.clone());
            }
        }

        // Fixed seed so a failing order can be reproduced
        let seed: u64 = 0x5eed_b12a;
        let mut rng = StdRng::seed_from_u64(seed);
        non_genesis_beads.shuffle(&mut rng);

        // Create braid with genesis beads first
        let mut braid = Braid::new(genesis_beads, PoolNetwork::Cpunet);

        // Extend with other beads in random order
        for (i, bead) in non_genesis_beads.iter().enumerate() {
            let result = braid.extend(bead);

            match result {
                AddBeadStatus::BeadAdded { .. } => {
                    // Successfully added
                }
                AddBeadStatus::ParentsMissing => {
                    // This is acceptable for this test - we just want to see cohort behavior
                }
                ref other => {
                    panic!("Unexpected result when adding bead {}: {:?}", i, other);
                }
            }
        }

        println!(
            "Final cohort structure for {}: {:?}",
            filename, braid.cohorts
        );
        println!("Final cohort count: {}", braid.cohorts.len());

        // Verify all orphans have been processed
        assert!(
            braid.orphanage.is_empty() && braid.missing_parents.is_empty(),
            "File {}: All orphans should be processed. Remaining: orphanage={}, missing_parents={}",
            filename,
            braid.orphanage.len(),
            braid.missing_parents.len()
        );

        // Verify all beads are present
        assert_eq!(
            braid.beads.len(),
            reference_braid.beads.len(),
            "File {}: Expected {} beads, got {}",
            filename,
            reference_braid.beads.len(),
            braid.beads.len()
        );

        // Build hash-to-index mappings for both braids to compare structures
        let ref_hash_to_idx: HashMap<_, _> = reference_braid
            .beads
            .iter()
            .enumerate()
            .map(|(idx, bead)| (bead.hash(), idx))
            .collect();

        let test_hash_to_idx: HashMap<_, _> = braid
            .beads
            .iter()
            .enumerate()
            .map(|(idx, bead)| (bead.hash(), idx))
            .collect();

        // Compare geneses by index (already stored as BeadSet/BeadIdx)
        //assert_eq!(
        //    braid.geneses, reference_braid.geneses,
        //    "File {}: Geneses mismatch",
        //    filename
        //);
        assert_eq!(
            braid
                .geneses
                .iter()
                .map(|&i| braid.beads[i].hash())
                .collect::<HashSet<_>>(),
            reference_braid
                .geneses
                .iter()
                .map(|&i| reference_braid.beads[i].hash())
                .collect::<HashSet<_>>(),
            "File {}: Geneses mismatch",
            filename
        );

        // Compare tips by index (already stored as BeadSet/BeadIdx)
        //assert_eq!(
        //    braid.tips, reference_braid.tips,
        //    "File {}: Tips mismatch",
        //    filename
        //);
        assert_eq!(
            braid
                .tips
                .iter()
                .map(|&i| braid.beads[i].hash())
                .collect::<HashSet<_>>(),
            reference_braid
                .tips
                .iter()
                .map(|&i| reference_braid.beads[i].hash())
                .collect::<HashSet<_>>(),
            "File {}: Tips mismatch",
            filename
        );

        // Compare parent relationships by index (much more readable than hashes)
        //        for (hash, &test_idx) in &test_hash_to_idx {
        //            let test_parent_indices: HashSet<_> =
        //                braid.parents[&test_idx].iter().copied().collect();
        //
        //            let ref_idx = ref_hash_to_idx[hash];
        //            let ref_parent_indices: HashSet<_> =
        //                reference_braid.parents[&ref_idx].iter().copied().collect();
        //
        //            assert_eq!(
        //                test_parent_indices, ref_parent_indices,
        //                "File {}: Parent mismatch for bead with hash {:?}",
        //                filename, hash
        //            );
        //        }
        for (hash, &test_idx) in &test_hash_to_idx {
            let test_parent_set = braid.parents.get(&test_idx).cloned().unwrap_or_default();
            let test_parent_hashes: HashSet<_> = test_parent_set
                .iter()
                .map(|&p| braid.beads[p].hash())
                .collect();

            let ref_idx = *ref_hash_to_idx.get(hash).unwrap();
            let ref_parent_set = reference_braid
                .parents
                .get(&ref_idx)
                .cloned()
                .unwrap_or_default();
            let ref_parent_hashes: HashSet<_> = ref_parent_set
                .iter()
                .map(|&p| reference_braid.beads[p].hash())
                .collect();

            assert_eq!(
                test_parent_hashes, ref_parent_hashes,
                "File {}: Parent mismatch for bead with hash {:?}",
                filename, hash
            );
        }

        // Validate cache integrity before checking cohort structure
        check_cache(&braid);
        // Compare cohorts by index (much more readable than hashes)
        let test_cohort_indices: Vec<HashSet<_>> = braid
            .cohorts
            .iter()
            .map(|cohort| cohort.iter().copied().collect())
            .collect();
        let ref_cohort_indices: Vec<HashSet<_>> = reference_braid
            .cohorts
            .iter()
            .map(|cohort| cohort.iter().copied().collect())
            .collect();
        assert_eq!(
            test_cohort_indices, ref_cohort_indices,
            "File {}: Cohorts mismatch.\n  Expected: {:?}\n  Got: {:?}",
            filename, ref_cohort_indices, test_cohort_indices
        );

        let test_cohort_hashes: Vec<HashSet<_>> = braid
            .cohorts
            .iter()
            .map(|cohort| cohort.iter().map(|&i| braid.beads[i].hash()).collect())
            .collect();
        let ref_cohort_hashes: Vec<HashSet<_>> = reference_braid
            .cohorts
            .iter()
            .map(|cohort| {
                cohort
                    .iter()
                    .map(|&i| reference_braid.beads[i].hash())
                    .collect()
            })
            .collect();
        assert_eq!(
            test_cohort_hashes, ref_cohort_hashes,
            "File {}: Cohorts mismatch.\n  Expected: {:?}\n  Got: {:?}",
            filename, ref_cohort_hashes, test_cohort_hashes
        );

        println!("✅ {} passed all validation checks", filename);
    }
}

#[test]
pub fn test_diamond_path_highest_work() {
    // Test diamond pattern: 0 -> (1,2) -> 3
    // This tests highest work path selection in a complex braid structure
    let parents = relatives!(
        0 => [],
        1 => [0],
        2 => [0],
        3 => [1, 2],
    );

    let children = reverse(&parents);

    // Test the highest work path algorithm
    let bead_work: HashMap<BeadIdx, Work> = parents.keys().map(|&k| (k, work(1))).collect();
    let path = highest_work_path(&parents, &children, &bead_work).expect("non-empty braid");

    // Beads 1 and 2 tie on descendant and ancestor work, so the lower index wins
    assert_eq!(path, vec![0, 1, 3]);

    // The path should start at genesis (0) and end at tip (3)
    assert_eq!(path[0], 0);
    assert_eq!(path[path.len() - 1], 3);
}

#[test]
pub fn test_make_test_braid_macro() {
    // Test the make_test_braid! macro with a simple braid structure:
    // 0 -> 1 -> 2
    //       -> 3
    let braid = make_test_braid!(
        0 => [],
        1 => [0],
        2 => [1],
        3 => [1],
    );

    println!("Beads: {}", braid.beads.len());
    println!("Cohorts: {:?}", braid.cohorts);
    println!("Tips: {:?}", braid.tips);

    // Verify the braid has 4 beads
    assert_eq!(braid.beads.len(), 4);

    // Verify there are 2 tips (beads 2 and 3)
    assert_eq!(braid.tips.len(), 2);

    // Verify we have the correct number of cohorts
    // Expected: [{0}, {1}, {2,3}]
    assert_eq!(braid.cohorts.len(), 3);
}

// ============================================================================
// Orphan promotion
// ============================================================================

/// A bead added with no parked orphans depending on it reports no promotions.
#[test]
fn test_extend_without_orphans_promotes_nothing() {
    let genesis = emit_Bead(&[]);
    let mut braid = Braid::new(vec![genesis.clone()], PoolNetwork::Cpunet);

    let child = emit_Bead(&[&genesis]);
    assert_eq!(
        braid.extend(&child),
        AddBeadStatus::BeadAdded {
            promoted_orphans: vec![]
        }
    );
}

/// An orphan that arrives before its parent is parked; when the parent arrives
/// the orphan is connected and reported back through `BeadAdded`.
#[test]
fn test_extend_reports_promoted_orphan() {
    let genesis = emit_Bead(&[]);
    let mut braid = Braid::new(vec![genesis.clone()], PoolNetwork::Cpunet);

    let child = emit_Bead(&[&genesis]);
    let grandchild = emit_Bead(&[&child]);

    assert_eq!(braid.extend(&grandchild), AddBeadStatus::ParentsMissing);
    assert_eq!(braid.orphanage.len(), 1);
    assert_eq!(
        braid.cohorts,
        cohorts!([0]),
        "orphans must not change cohorts"
    );

    assert_eq!(
        braid.extend(&child),
        AddBeadStatus::BeadAdded {
            promoted_orphans: vec![grandchild.clone()]
        }
    );
    assert!(braid.orphanage.is_empty() && braid.missing_parents.is_empty());
    assert_eq!(braid.cohorts, cohorts!([0], [1], [2]));
    assert_eq!(braid.index[&braid.compute_bead_hash(&grandchild)], 2);
}

/// Parking the same orphan twice is reported as a duplicate.
#[test]
fn test_extend_duplicate_orphan() {
    let genesis = emit_Bead(&[]);
    let mut braid = Braid::new(vec![genesis.clone()], PoolNetwork::Cpunet);
    let child = emit_Bead(&[&genesis]);
    let grandchild = emit_Bead(&[&child]);

    assert_eq!(braid.extend(&grandchild), AddBeadStatus::ParentsMissing);
    assert_eq!(braid.extend(&grandchild), AddBeadStatus::DuplicateBead);
    assert_eq!(braid.orphanage.len(), 1);
}

/// A chain of orphans that arrive before their common ancestor is promoted
/// transitively, in dependency order, by a single `extend`.
#[test]
fn test_extend_promotes_transitive_orphan_chain() {
    let genesis = emit_Bead(&[]);
    let mut braid = Braid::new(vec![genesis.clone()], PoolNetwork::Cpunet);

    let a = emit_Bead(&[&genesis]);
    let b = emit_Bead(&[&a]);
    let c = emit_Bead(&[&b]);

    assert_eq!(braid.extend(&c), AddBeadStatus::ParentsMissing);
    assert_eq!(braid.extend(&b), AddBeadStatus::ParentsMissing);
    assert_eq!(braid.orphanage.len(), 2);

    assert_eq!(
        braid.extend(&a),
        AddBeadStatus::BeadAdded {
            promoted_orphans: vec![b.clone(), c.clone()]
        }
    );
    assert!(braid.orphanage.is_empty() && braid.missing_parents.is_empty());
    assert_eq!(braid.cohorts, cohorts!([0], [1], [2], [3]));
}

/// A long orphan chain is adopted iteratively; the old recursive adoption
/// overflowed the stack here (braidpool#532).
#[test]
fn test_extend_long_orphan_chain_does_not_overflow() {
    const CHAIN_LEN: usize = 5_000;
    let genesis = emit_Bead(&[]);
    let mut chain = vec![emit_Bead(&[&genesis])];
    for _ in 1..CHAIN_LEN {
        let next = emit_Bead(&[chain.last().unwrap()]);
        chain.push(next);
    }

    let mut braid = Braid::new(vec![genesis], PoolNetwork::Cpunet);
    for bead in chain.iter().skip(1).rev() {
        assert_eq!(braid.extend(bead), AddBeadStatus::ParentsMissing);
    }
    match braid.extend(&chain[0]) {
        AddBeadStatus::BeadAdded { promoted_orphans } => {
            assert_eq!(promoted_orphans.len(), CHAIN_LEN - 1)
        }
        other => panic!("expected BeadAdded, got {:?}", other),
    }
    assert_eq!(braid.beads.len(), CHAIN_LEN + 1);
    assert!(braid.orphanage.is_empty());
}

/// An orphan with two missing parents is only promoted once both arrive.
#[test]
fn test_orphan_waits_for_all_parents() {
    let genesis = emit_Bead(&[]);
    let mut braid = Braid::new(vec![genesis.clone()], PoolNetwork::Cpunet);

    let left = emit_Bead(&[&genesis]);
    let right = emit_Bead(&[&genesis]);
    let merge = emit_Bead(&[&left, &right]);

    assert_eq!(braid.extend(&merge), AddBeadStatus::ParentsMissing);
    assert_eq!(
        braid.extend(&left),
        AddBeadStatus::BeadAdded {
            promoted_orphans: vec![]
        }
    );
    assert_eq!(braid.orphanage.len(), 1, "merge still waits for `right`");
    assert_eq!(
        braid.extend(&right),
        AddBeadStatus::BeadAdded {
            promoted_orphans: vec![merge.clone()]
        }
    );
    assert!(braid.orphanage.is_empty() && braid.missing_parents.is_empty());
    assert_eq!(braid.cohorts, cohorts!([0], [1, 2], [3]));
}

// ============================================================================
// get_beads_after (IBD sync)
// ============================================================================

fn hashes_of(braid: &Braid, beads: &[Bead]) -> HashSet<crate::utils::BeadHash> {
    beads.iter().map(|b| braid.compute_bead_hash(b)).collect()
}

fn hashes_at(braid: &Braid, indices: &[BeadIdx]) -> HashSet<crate::utils::BeadHash> {
    indices
        .iter()
        .map(|&i| braid.compute_bead_hash(&braid.beads[i]))
        .collect()
}

#[test]
fn test_get_beads_after_linear_chain() {
    let braid = make_test_braid!(0 => [], 1 => [0], 2 => [1], 3 => [2]);
    let h = |i: BeadIdx| braid.compute_bead_hash(&braid.beads[i]);

    let after_genesis = braid
        .get_beads_after(vec![h(0)])
        .expect("beads after genesis");
    assert_eq!(
        hashes_of(&braid, &after_genesis),
        hashes_at(&braid, &[1, 2, 3])
    );

    let after_1 = braid
        .get_beads_after(vec![h(1)])
        .expect("beads after bead 1");
    assert_eq!(hashes_of(&braid, &after_1), hashes_at(&braid, &[2, 3]));

    assert!(braid.get_beads_after(vec![h(3)]).is_none());
}

#[test]
fn test_get_beads_after_diamond() {
    let braid = make_test_braid!(0 => [], 1 => [0], 2 => [0], 3 => [1, 2]);
    let h = |i: BeadIdx| braid.compute_bead_hash(&braid.beads[i]);

    let after_middle = braid
        .get_beads_after(vec![h(1), h(2)])
        .expect("beads after the middle cohort");
    assert_eq!(hashes_of(&braid, &after_middle), hashes_at(&braid, &[3]));

    // Input order does not matter
    let reordered = braid.get_beads_after(vec![h(2), h(1)]).unwrap();
    assert_eq!(
        hashes_of(&braid, &reordered),
        hashes_of(&braid, &after_middle)
    );
}

#[test]
fn test_get_beads_after_is_topologically_ordered() {
    let braid = make_test_braid!(
        0 => [],
        1 => [0], 2 => [0], 3 => [0],
        4 => [1], 5 => [2], 6 => [3],
        7 => [4, 5, 6],
    );
    let genesis_hash = braid.compute_bead_hash(&braid.beads[0]);
    let returned = braid.get_beads_after(vec![genesis_hash]).unwrap();
    assert_eq!(returned.len(), 7);

    // A syncing peer must be able to extend with these beads in order without orphans
    let mut replica = Braid::new(vec![braid.beads[0].clone()], PoolNetwork::Cpunet);
    for bead in &returned {
        assert!(matches!(
            replica.extend(bead),
            AddBeadStatus::BeadAdded { .. }
        ));
    }
    assert_eq!(replica.cohorts, braid.cohorts);
}

#[test]
fn test_get_beads_after_edge_cases() {
    let braid = make_test_braid!(0 => [], 1 => [0], 2 => [1]);
    let genesis_hash = braid.compute_bead_hash(&braid.beads[0]);
    let unknown = <crate::utils::BeadHash as bitcoin::hashes::Hash>::from_byte_array([1u8; 32]);

    // No tips, or only unknown tips: fall back to the whole braid
    assert_eq!(braid.get_beads_after(vec![]).unwrap().len(), 3);
    assert_eq!(braid.get_beads_after(vec![unknown]).unwrap().len(), 3);

    // Unknown hashes are ignored when a known one is present
    let mixed = braid.get_beads_after(vec![genesis_hash, unknown]).unwrap();
    assert_eq!(hashes_of(&braid, &mixed), hashes_at(&braid, &[1, 2]));
}

// ============================================================================
// Extend strategies must agree with the reference cohort algorithm
// ============================================================================

/// Builds a random DAG of `n` beads where each bead picks 1..=3 parents among
/// the previous `window` beads. Returned in a valid topological order.
fn random_dag_beads(rng: &mut StdRng, n: usize, window: usize) -> Vec<Bead> {
    let mut beads = vec![emit_Bead(&[])];
    for i in 1..n {
        let lo = i.saturating_sub(window);
        let k = rng.gen_range(1..=3);
        let mut picked: Vec<usize> = (0..k).map(|_| rng.gen_range(lo..i)).collect();
        picked.sort_unstable();
        picked.dedup();
        let parents: Vec<&Bead> = picked.iter().map(|&j| &beads[j]).collect();
        let bead = emit_Bead(&parents);
        beads.push(bead);
    }
    beads
}

fn assert_matches_reference(braid: &Braid, label: &str) {
    let mut scratch = HashMap::new();
    let expected = cohorts(
        &braid.parents,
        &braid.children,
        &geneses(&braid.parents),
        &mut scratch,
    );
    assert_eq!(
        braid.cohorts, expected,
        "{label}: cohorts diverge from algorithms::cohorts"
    );
    check_cache(braid);
}

fn check_strategy(strategy: ExtendStrategy, shuffle: bool) {
    let mut rng = StdRng::seed_from_u64(0xb2a1d);
    for trial in 0..60 {
        let n = rng.gen_range(5..40);
        let window = rng.gen_range(2..8);
        let mut beads = random_dag_beads(&mut rng, n, window);
        if shuffle {
            beads[1..].shuffle(&mut rng);
        }
        let braid = Braid::new_with_strategy(beads, strategy, PoolNetwork::Cpunet);
        assert!(braid.orphanage.is_empty());
        assert_eq!(braid.beads.len(), n);
        assert_matches_reference(&braid, &format!("{strategy:?} trial {trial}"));
    }
}

#[test]
fn test_heuristic_strategy_matches_reference() {
    check_strategy(ExtendStrategy::Heuristic, false);
}

#[test]
fn test_heuristic_strategy_matches_reference_out_of_order() {
    check_strategy(ExtendStrategy::Heuristic, true);
}

#[test]
fn test_cached_strategy_matches_reference() {
    check_strategy(ExtendStrategy::Cached, false);
}

#[test]
fn test_cached_strategy_matches_reference_out_of_order() {
    check_strategy(ExtendStrategy::Cached, true);
}

#[test]
fn test_cached_strategy_matches_json_braids() {
    for (json_braid, filename) in JSONBraid::tests() {
        let reference = json_braid.make_Braid();
        let braid = Braid::new_with_strategy(
            reference.beads.clone(),
            ExtendStrategy::Cached,
            PoolNetwork::Cpunet,
        );
        assert_eq!(
            braid.cohorts, reference.cohorts,
            "File {filename}: cohorts mismatch"
        );
        assert_eq!(
            braid.cohorts.len(),
            json_braid.cohorts.len(),
            "File {filename}"
        );
        check_cache(&braid);
    }
}

#[test]
fn test_cached_strategy_step_by_step() {
    // Every intermediate state, not only the final one, must match the reference
    let mut rng = StdRng::seed_from_u64(0xcac4e);
    for _ in 0..40 {
        let n = rng.gen_range(5..30);
        let window = rng.gen_range(2..6);
        let beads = random_dag_beads(&mut rng, n, window);
        let mut braid = Braid::new_with_strategy(
            vec![beads[0].clone()],
            ExtendStrategy::Cached,
            PoolNetwork::Cpunet,
        );
        for (i, bead) in beads.iter().enumerate().skip(1) {
            assert!(matches!(
                braid.extend(bead),
                AddBeadStatus::BeadAdded { .. }
            ));
            assert_matches_reference(&braid, &format!("Cached after bead {i}"));
        }
    }
}

#[test]
fn test_nocache_strategy_matches_reference() {
    check_strategy(ExtendStrategy::NoCache, false);
}

/// A new bead whose parent sits in a cohort with internal links must not erase the
/// cut after that cohort. `Cached` used to restart from the whole cohort and merged this
/// braid into one cohort.
#[test]
fn test_strategies_keep_cut_after_cohort_with_internal_links() {
    let b0 = emit_Bead(&[]);
    let b1 = emit_Bead(&[&b0]);
    let b2 = emit_Bead(&[&b0, &b1]);
    let b3 = emit_Bead(&[&b1]);
    let beads = vec![b0, b1, b2, b3];
    for strategy in [
        ExtendStrategy::Heuristic,
        ExtendStrategy::Cached,
        ExtendStrategy::NoCache,
    ] {
        let braid = Braid::new_with_strategy(beads.clone(), strategy, PoolNetwork::Cpunet);
        assert_eq!(braid.cohorts, cohorts!([0, 1], [2, 3]), "{strategy:?}");
    }
}
