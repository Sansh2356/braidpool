// Pure algorithm tests for braid consensus algorithms
// These tests only test pure algorithm functions that operate on HashMap data structures
// and do NOT depend on the Bead struct or braid integration.

use super::algorithms::*;
use crate::braid::BeadIdx;
use crate::braid::{BeadSet, Relatives};
use crate::relatives;
use bitcoin::Work;
use std::collections::{HashMap, HashSet};

use crate::utils::test_utils::JSONBraid;

// ============================================================================
// Test Helper Functions
// ============================================================================

/// Helper to create Work from u64 for testing
fn work(v: u64) -> Work {
    let mut bytes = [0u8; 32];
    bytes[24..32].copy_from_slice(&v.to_be_bytes());
    Work::from_be_bytes(bytes)
}

// ============================================================================
// Tests
// ============================================================================

#[test]
pub fn test_reverse() {
    let parents1 = relatives!(
        0 => [],
        1 => [],
        2 => [0],
        3 => [1, 2],
        4 => [3],
    );
    let reverse_children_mapping = reverse(&parents1);
    let expected_children_mapping = relatives!(
        0 => [2],
        1 => [3],
        2 => [3],
        3 => [4],
        4 => [],
    );
    assert_eq!(reverse_children_mapping, expected_children_mapping);
}

#[test]
pub fn test_genesis_empty() {
    let parents = relatives!();
    let genesis_indices = geneses(&parents);
    let empty_cohorts = cohorts(
        &parents,
        &relatives!(),
        &BeadSet::new(),
        &mut Relatives::new(),
    );
    assert_eq!(genesis_indices, HashSet::new());
    assert!(empty_cohorts.is_empty());
}

#[test]
pub fn test_genesis_single() {
    let parents = relatives!(
        0 => [],
    );
    let children = reverse(&parents);
    let genesis_indices = geneses(&parents);
    let single_cohorts = cohorts(&parents, &children, &BeadSet::new(), &mut Relatives::new());
    assert_eq!(genesis_indices, HashSet::from([0]));
    assert_eq!(single_cohorts, vec![HashSet::from([0])]);
}

#[test]
pub fn test_genesis_multiple() {
    let parents = relatives!(
        0 => [],
        1 => [],
        2 => [0, 1],
    );
    let genesis_indices = geneses(&parents);
    assert_eq!(genesis_indices, HashSet::from([0, 1]));
}

#[test]
pub fn test_genesis_chain() {
    let parents = relatives!(
        0 => [],
        1 => [0],
        2 => [1],
        3 => [2],
    );
    let genesis_indices = geneses(&parents);
    assert_eq!(genesis_indices, HashSet::from([0]));
}

#[test]
pub fn test_genesis_three_parallel() {
    let parents = relatives!(
        0 => [],
        1 => [],
        2 => [],
        3 => [1],
        4 => [0],
    );
    let genesis_indices = geneses(&parents);
    assert_eq!(genesis_indices, HashSet::from([0, 1, 2]));
}

#[test]
pub fn test_tips_empty() {
    let parents = relatives!();
    let children = reverse(&parents);
    let tips_indices = tips(&children);
    assert_eq!(tips_indices, HashSet::new());
}

#[test]
pub fn test_tips_single() {
    let parents = relatives!(
        0 => [],
    );
    let children = reverse(&parents);
    let tips_indices = tips(&children);
    assert_eq!(tips_indices, HashSet::from([0]));
}

#[test]
pub fn test_tips_simple() {
    let parents = relatives!(
        0 => [],
        1 => [0],
        2 => [0],
    );
    let children = reverse(&parents);
    let tips_indices = tips(&children);
    assert_eq!(tips_indices, HashSet::from([1, 2]));
}

#[test]
pub fn test_all_ancestors_simple() {
    let parents = relatives!(
        0 => [],
        1 => [0],
        2 => [1],
        3 => [2],
    );

    let mut cache = HashMap::new();
    all_ancestors(3, &parents, &mut cache);

    assert_eq!(cache.get(&0), Some(&HashSet::new()));
    assert_eq!(cache.get(&1), Some(&HashSet::from([0])));
    assert_eq!(cache.get(&2), Some(&HashSet::from([0, 1])));
    assert_eq!(cache.get(&3), Some(&HashSet::from([0, 1, 2])));
}

#[test]
pub fn test_cohorts_simple() {
    let parents = relatives!(
        0 => [],
        1 => [0],
        2 => [1],
        3 => [2],
    );

    let children = reverse(&parents);
    let geneses_set = geneses(&parents);
    let mut cache = HashMap::new();
    let simple_cohorts = cohorts(&parents, &children, &geneses_set, &mut cache);

    println!("Cohorts: {:?}", simple_cohorts);
    println!("Ancestor cache: {:?}", cache);
    println!("Parents: {:?}", parents);
    println!("Children: {:?}", children);
    // Each bead should be in its own cohort since it's a simple chain
    assert_eq!(simple_cohorts.len(), 4);
    assert!(simple_cohorts[0] == HashSet::from([0]));
    assert!(simple_cohorts[1] == HashSet::from([1]));
    assert!(simple_cohorts[2] == HashSet::from([2]));
    assert!(simple_cohorts[3] == HashSet::from([3]));
}

#[test]
pub fn test_cohorts_twotip() {
    let parents = relatives!(
        0 => [],
        1 => [0],
        2 => [0],
    );

    let children = reverse(&parents);
    let geneses_set = geneses(&parents);
    let mut cache = HashMap::new();
    let twotip_cohorts = cohorts(&parents, &children, &geneses_set, &mut cache);

    // Should have one cohort with [0] and another with [1, 2]
    assert_eq!(twotip_cohorts.len(), 2);
    assert!(twotip_cohorts[0] == HashSet::from([0]));
    assert!(twotip_cohorts[1] == HashSet::from([1, 2]));
}

#[test]
pub fn test_cohorts_non_head_cohort_extension() {
    let parents = relatives!(
        0 => [],
        1 => [0],
        2 => [1],
        3 => [1],
        4 => [2,3],
        5 => [3],
        6 => [4,5]
    );

    let children = reverse(&parents);
    let geneses_set = geneses(&parents);
    let mut cache = HashMap::new();
    let nhce_cohorts = cohorts(&parents, &children, &geneses_set, &mut cache);

    println!("Cohorts: {:?}", nhce_cohorts);
    println!("Ancestor cache: {:?}", cache);
    println!("Parents: {:?}", parents);
    println!("Children: {:?}", children);
    // Each bead should be in its own cohort since it's a simple chain
    assert_eq!(nhce_cohorts.len(), 4);
    assert!(nhce_cohorts[0] == HashSet::from([0]));
    assert!(nhce_cohorts[1] == HashSet::from([1]));
    assert!(nhce_cohorts[2] == HashSet::from([2, 3, 4, 5]));
    assert!(nhce_cohorts[3] == HashSet::from([6]));
}

#[test]
pub fn test_sub_braid_simple() {
    let parents = relatives!(
        0 => [],
        1 => [0],
        2 => [1],
        3 => [2],
        4 => [2],  // parallel branch
    );

    let cohort = HashSet::from([1, 2, 3, 4]);
    let sub_parents = sub_braid(&cohort, &parents);

    // Should include nodes and their descendants
    assert_eq!(sub_parents.len(), 4);
    assert!(sub_parents.contains_key(&1));
    assert!(sub_parents.contains_key(&2));
    assert!(sub_parents.contains_key(&3));
    assert!(sub_parents.contains_key(&4));

    // Should not include parent 0
    assert!(!sub_parents.contains_key(&0));

    // Only parents inside the cohort are retained
    assert_eq!(sub_parents[&1], HashSet::new());
    assert_eq!(sub_parents[&2], HashSet::from([1]));
    assert_eq!(sub_parents[&3], HashSet::from([2]));
    assert_eq!(sub_parents[&4], HashSet::from([2]));
}

#[test]
pub fn test_cohort_head_tail() {
    let parents = relatives!(
        0 => [],
        1 => [0],
        2 => [0],
        3 => [1, 2],
    );

    let children = reverse(&parents);
    let cohort = HashSet::from([1, 2, 3]);

    let head = cohort_head(&cohort, &parents, &children);
    let tail = cohort_tail(&cohort, &parents, &children);

    // Head should be genesis beads of the sub-braid (1 and 2)
    assert_eq!(head, HashSet::from([1, 2]));

    // Tail should be tip beads of the sub-braid (just 3)
    assert_eq!(tail, HashSet::from([3]));
}

#[test]
pub fn test_highest_work_path_simple() {
    let parents = relatives!(
        0 => [],
        1 => [0],
        2 => [0],
        3 => [1],
    );

    let children = reverse(&parents);
    let bead_work: HashMap<BeadIdx, Work> = parents.keys().map(|&k| (k, work(1))).collect();
    let path = highest_work_path(&parents, &children, &bead_work).expect("non-empty braid");

    // Bead 1 carries more descendant work than bead 2 (it has child 3), so the
    // highest work path must go through it.
    assert_eq!(path, vec![0, 1, 3]);
}

#[test]
pub fn test_highest_work_path_empty() {
    let parents = relatives!();
    let children = reverse(&parents);
    assert_eq!(
        highest_work_path(&parents, &children, &HashMap::new()),
        None
    );
}

#[test]
pub fn test_work_maps_chain() {
    let parents = relatives!(
        0 => [],
        1 => [0],
        2 => [1],
    );
    let children = reverse(&parents);
    let bead_work: HashMap<BeadIdx, Work> =
        HashMap::from([(0, work(1)), (1, work(2)), (2, work(3))]);

    let (dwork, awork) = work_maps(&parents, &children, &bead_work);

    // Descendant work accumulates towards the genesis, ancestor work towards the tip
    assert_eq!(
        dwork,
        HashMap::from([(0, work(6)), (1, work(5)), (2, work(3))])
    );
    assert_eq!(
        awork,
        HashMap::from([(0, work(1)), (1, work(3)), (2, work(6))])
    );
}

#[test]
pub fn test_work_maps_from_files() {
    for (file_braid, filename) in JSONBraid::tests() {
        let parents = file_braid.parents.clone();
        let children = reverse(&parents);
        let bead_work: HashMap<BeadIdx, Work> = file_braid
            .bead_work
            .iter()
            .map(|(k, v)| (*k, work(*v as u64)))
            .collect();
        let expected: HashMap<BeadIdx, Work> = file_braid
            .work
            .iter()
            .map(|(k, v)| (*k, work(*v as u64)))
            .collect();

        let (dwork, _) = work_maps(&parents, &children, &bead_work);
        assert_eq!(
            dwork, expected,
            "work_maps descendant work mismatch in file '{}' [{}]",
            filename, file_braid.description
        );
    }
}

#[test]
pub fn test_descendant_work() {
    let parents = relatives!(
        0 => [],
        1 => [0],
        2 => [1],
    );

    let children = reverse(&parents);

    // Create work HashMap
    let work_values: HashMap<BeadIdx, Work> =
        HashMap::from([(0, work(1)), (1, work(2)), (2, work(3))]);

    // Compute cohorts
    let mut cache = HashMap::new();
    let geneses_set = geneses(&parents);
    let cohorts = cohorts(&parents, &children, &geneses_set, &mut cache);

    let descendant_work = descendant_work(&children, &work_values, &cohorts);

    // 0: 1 + 2 + 3 = 6
    // 1: 2 + 3 = 5
    // 2: 3 = 3
    assert_eq!(descendant_work.get(&0), Some(&work(6)));
    assert_eq!(descendant_work.get(&1), Some(&work(5)));
    assert_eq!(descendant_work.get(&2), Some(&work(3)));
}

#[test]
pub fn test_bead_cmp() {
    // Create Work values
    let work_values: HashMap<BeadIdx, Work> =
        HashMap::from([(0, work(10)), (1, work(20)), (2, work(15))]);
    let awork_values: HashMap<BeadIdx, Work> =
        HashMap::from([(0, work(10)), (1, work(20)), (2, work(15))]);

    // Test ordering - bead_cmp returns Ordering
    assert_eq!(
        bead_cmp(1, 0, &work_values, &awork_values),
        std::cmp::Ordering::Greater
    );
    assert_eq!(
        bead_cmp(0, 1, &work_values, &awork_values),
        std::cmp::Ordering::Less
    );
    assert_eq!(
        bead_cmp(0, 2, &work_values, &awork_values),
        std::cmp::Ordering::Less
    );
    assert_eq!(
        bead_cmp(2, 0, &work_values, &awork_values),
        std::cmp::Ordering::Greater
    );
}

#[test]
pub fn test_bead_cmp_tie_breaks() {
    // Equal descendant work: higher ancestor work wins
    let dwork: HashMap<BeadIdx, Work> = HashMap::from([(0, work(5)), (1, work(5)), (2, work(5))]);
    let awork: HashMap<BeadIdx, Work> = HashMap::from([(0, work(1)), (1, work(3)), (2, work(3))]);
    assert_eq!(bead_cmp(1, 0, &dwork, &awork), std::cmp::Ordering::Greater);
    assert_eq!(bead_cmp(0, 1, &dwork, &awork), std::cmp::Ordering::Less);

    // Equal descendant and ancestor work: the lower index wins
    assert_eq!(bead_cmp(1, 2, &dwork, &awork), std::cmp::Ordering::Greater);
    assert_eq!(bead_cmp(2, 1, &dwork, &awork), std::cmp::Ordering::Less);
    assert_eq!(bead_cmp(1, 1, &dwork, &awork), std::cmp::Ordering::Equal);
}

#[test]
pub fn test_generation() {
    let parents = relatives!(
        0 => [],
        1 => [0],
        2 => [0],
        3 => [1, 2],
    );

    let children = reverse(&parents);

    // Test generation from genesis beads
    let genesis_beads = HashSet::from([0]);
    let gen0 = generation(&genesis_beads, &children);
    assert_eq!(gen0, HashSet::from([1, 2]));

    // Test generation from middle beads
    let middle_beads = HashSet::from([1, 2]);
    let gen1 = generation(&middle_beads, &children);
    assert_eq!(gen1, HashSet::from([3]));

    // Test generation from tips (no children)
    let tip_beads = HashSet::from([3]);
    let gen2 = generation(&tip_beads, &children);
    assert_eq!(gen2, HashSet::new());
}

// ============================================================================
// Ancestors Cache Tests
// ============================================================================

#[test]
pub fn test_all_ancestors_cache_miss_basic() {
    // Test basic cache functionality - first call should compute and cache
    let parents = relatives!(
        0 => [],
        1 => [0],
        2 => [1],
        3 => [2],
    );

    let mut cache = HashMap::new();

    // First call - should compute and cache results for bead 3 and its dependencies
    all_ancestors(3, &parents, &mut cache);

    // Verify ancestors were computed correctly for requested bead and its dependencies
    assert_eq!(cache.get(&0), Some(&HashSet::new()));
    assert_eq!(cache.get(&1), Some(&HashSet::from([0])));
    assert_eq!(cache.get(&2), Some(&HashSet::from([0, 1])));
    assert_eq!(cache.get(&3), Some(&HashSet::from([0, 1, 2])));

    // Every bead visited on the way is cached, not only the requested one
    assert_eq!(cache.len(), 4);
}

#[test]
pub fn test_all_ancestors_cache_hit_basic() {
    // Test cache hit functionality - second call should use cached results
    let parents = relatives!(
        0 => [],
        1 => [0],
        2 => [1],
        3 => [2],
    );

    let mut cache = HashMap::new();

    // Pre-populate bead 3 with a deliberately wrong sentinel value
    cache.insert(3, HashSet::from([99]));

    // Call with bead that is already cached
    all_ancestors(3, &parents, &mut cache);

    // A cache hit returns early: the sentinel survives and nothing else is computed
    assert_eq!(cache.get(&3), Some(&HashSet::from([99])));
    assert_eq!(cache.len(), 1);
}

#[test]
pub fn test_all_ancestors_cache_partial_hit() {
    // Test partial cache hit - some beads cached, some not
    let parents = relatives!(
        0 => [],
        1 => [0],
        2 => [1],
        3 => [2],
    );

    let mut cache = HashMap::new();

    // Pre-populate bead 2 with a sentinel so we can see it being reused
    cache.insert(2, HashSet::from([99]));
    // Note: 3 is NOT cached

    all_ancestors(3, &parents, &mut cache);

    // Bead 3 is built from its parent (2) plus 2's cached ancestors, and the walk
    // stops at 2 instead of descending to 0 and 1.
    assert_eq!(cache.get(&3), Some(&HashSet::from([2, 99])));
    assert!(!cache.contains_key(&1));
    assert!(!cache.contains_key(&0));
}

#[test]
pub fn test_all_ancestors_cache_complex_dag() {
    // Test cache with a more complex DAG structure
    let parents = relatives!(
        0 => [],      // Genesis
        1 => [0],     // Child of 0
        2 => [0],     // Another child of 0 (parallel)
        3 => [1, 2],  // Merge point
    );

    let mut cache = HashMap::new();

    // First compute ancestors for bead 3
    all_ancestors(3, &parents, &mut cache);

    // Verify complex ancestry relationships
    assert_eq!(cache.get(&3), Some(&HashSet::from([0, 1, 2])));
    assert_eq!(cache.get(&2), Some(&HashSet::from([0])));
    assert_eq!(cache.get(&1), Some(&HashSet::from([0])));
    assert_eq!(cache.get(&0), Some(&HashSet::new()));

    // Recomputing from an empty cache gives the same result
    let mut fresh = HashMap::new();
    all_ancestors(3, &parents, &mut fresh);
    assert_eq!(fresh, cache);
}

#[test]
pub fn test_all_ancestors_cache_multiple_calls() {
    // Results are independent of call order and of whether the cache was cleared
    let parents = relatives!(
        0 => [],
        1 => [0],
        2 => [1],
        3 => [0],     // Alternative path
    );

    let mut cache = HashMap::new();

    // First call - compute ancestors for bead 2
    all_ancestors(2, &parents, &mut cache);
    assert_eq!(cache.get(&2), Some(&HashSet::from([0, 1])));

    // Second call - compute ancestors for bead 3
    cache.clear();
    all_ancestors(3, &parents, &mut cache);
    assert_eq!(cache.get(&3), Some(&HashSet::from([0])));

    // Third call - ask for both previously computed beads
    cache.clear();
    all_ancestors(2, &parents, &mut cache);
    all_ancestors(3, &parents, &mut cache);
    assert_eq!(cache.get(&2), Some(&HashSet::from([0, 1])));
    assert_eq!(cache.get(&3), Some(&HashSet::from([0])));

    // Both calls share one cache, so the union of visited beads is cached
    assert!(cache.contains_key(&0));
    assert!(cache.contains_key(&1));
    assert!(cache.contains_key(&2));
    assert!(cache.contains_key(&3));
}

#[test]
pub fn test_all_ancestors_cache_isolated_beads() {
    // Test with beads that have no relationships
    let parents = relatives!(
        0 => [],  // Isolated genesis
        1 => [],  // Another isolated genesis
        2 => [],  // Yet another isolated genesis
    );

    let mut cache = HashMap::new();

    // Compute ancestors for isolated beads
    for bead in [0, 1, 2] {
        all_ancestors(bead, &parents, &mut cache);
    }

    // All should have empty ancestor sets
    assert_eq!(cache.get(&0), Some(&HashSet::new()));
    assert_eq!(cache.get(&1), Some(&HashSet::new()));
    assert_eq!(cache.get(&2), Some(&HashSet::new()));
}

/// ****
/// File-based tests for algorithm functions
/// ****

#[test]
pub fn test_genesis_from_files() {
    for (file_braid, filename) in JSONBraid::tests() {
        let parents = file_braid.parents.clone();

        let computed_genesis = geneses(&parents);
        let expected_genesis = file_braid.geneses.clone();

        assert_eq!(
            computed_genesis, expected_genesis,
            "Genesis mismatch in file '{}' [{}]",
            filename, file_braid.description
        );
    }
}

#[test]
pub fn test_tips_from_files() {
    for (file_braid, filename) in JSONBraid::tests() {
        let parents = file_braid.parents.clone();
        let children = reverse(&parents);

        let computed_tips = tips(&children);
        let expected_tips = file_braid.tips.clone();

        assert_eq!(
            computed_tips, expected_tips,
            "Tips mismatch in file '{}' [{}]",
            filename, file_braid.description
        );
    }
}

#[test]
pub fn test_reverse_from_files() {
    for (file_braid, filename) in JSONBraid::tests() {
        let parents = file_braid.parents.clone();
        let computed_children = reverse(&parents);
        let expected_children = file_braid.children.clone();

        assert_eq!(
            computed_children, expected_children,
            "Reverse mismatch in file '{}' [{}]",
            filename, file_braid.description
        );
    }
}

#[test]
pub fn test_cohorts_from_files() {
    for (file_braid, filename) in JSONBraid::tests() {
        let parents = file_braid.parents.clone();
        let children = reverse(&parents);
        let geneses_set = geneses(&parents);
        let mut cache = HashMap::new();
        let computed_cohorts = cohorts(&parents, &children, &geneses_set, &mut cache);
        let expected_cohorts = file_braid.cohorts.clone();

        // The algorithm must produce EXACT results matching the JSON test cases
        assert_eq!(
            computed_cohorts, expected_cohorts,
            "Cohorts mismatch in file '{}' [{}] (expected: {:?}, got: {:?})",
            filename, file_braid.description, expected_cohorts, computed_cohorts
        );
    }
}

#[test]
pub fn test_highest_work_path_from_files() {
    for (file_braid, filename) in JSONBraid::tests() {
        let parents = file_braid.parents.clone();
        let children = reverse(&parents);

        // Create bead work maps from file data
        let bead_work: HashMap<BeadIdx, Work> = file_braid
            .bead_work
            .iter()
            .map(|(k, v)| (*k, work(*v as u64)))
            .collect();

        let path =
            highest_work_path(&parents, &children, &bead_work).expect("test braids are non-empty");

        // The algorithm must produce EXACT results matching the JSON test cases
        assert_eq!(
            path, file_braid.highest_work_path,
            "Highest work path mismatch in file '{}' [{}] (expected: {:?}, got: {:?})",
            filename, file_braid.description, file_braid.highest_work_path, path
        );
    }
}

#[test]
pub fn test_descendant_work_from_files() {
    for (file_braid, filename) in JSONBraid::tests() {
        let parents = file_braid.parents.clone();
        let children = reverse(&parents);

        // Input is the per-bead work; `work` in the file is the expected descendant work
        let bead_work: HashMap<BeadIdx, Work> = file_braid
            .bead_work
            .iter()
            .map(|(k, v)| (*k, work(*v as u64)))
            .collect();
        let expected: HashMap<BeadIdx, Work> = file_braid
            .work
            .iter()
            .map(|(k, v)| (*k, work(*v as u64)))
            .collect();

        // descendant_work walks the cohorts in reverse, so it takes them genesis-first
        let mut cohort_cache = HashMap::new();
        let geneses_set = geneses(&parents);
        let fwd_cohorts = cohorts(&parents, &children, &geneses_set, &mut cohort_cache);

        let computed = descendant_work(&children, &bead_work, &fwd_cohorts);

        assert_eq!(
            computed, expected,
            "Descendant work mismatch in file '{}' [{}]",
            filename, file_braid.description
        );
    }
}

#[test]
pub fn test_cohort_head_tail_from_files() {
    for (file_braid, filename) in JSONBraid::tests() {
        let parents = file_braid.parents.clone();
        let children = reverse(&parents);

        // Test each cohort from the file
        for cohort in &file_braid.cohorts {
            if !cohort.is_empty() {
                let head = cohort_head(cohort, &parents, &children);
                let tail = cohort_tail(cohort, &parents, &children);

                // Documented property: the head/tail are the geneses/tips of the sub-braid
                let sub_parents = sub_braid(cohort, &parents);
                let sub_children = reverse(&sub_parents);
                assert_eq!(
                    head,
                    geneses(&sub_parents),
                    "Head != geneses(sub_braid) for cohort {:?} in file: {} [{}]",
                    cohort,
                    filename,
                    file_braid.description
                );
                assert_eq!(
                    tail,
                    tips(&sub_children),
                    "Tail != tips(sub_braid) for cohort {:?} in file: {} [{}]",
                    cohort,
                    filename,
                    file_braid.description
                );

                // Head should be non-empty for valid cohorts
                assert!(
                    !head.is_empty(),
                    "Empty head for cohort {:?} in file: {} [{}]",
                    cohort,
                    filename,
                    file_braid.description
                );

                // Tail should be non-empty for valid cohorts
                assert!(
                    !tail.is_empty(),
                    "Empty tail for cohort {:?} in file: {} [{}]",
                    cohort,
                    filename,
                    file_braid.description
                );

                // Head should consist of beads in the cohort
                assert!(
                    head.iter().all(|bead| cohort.contains(bead)),
                    "Head contains beads not in cohort for file: {} [{}]",
                    filename,
                    file_braid.description
                );

                // Tail should consist of beads in the cohort
                assert!(
                    tail.iter().all(|bead| cohort.contains(bead)),
                    "Tail contains beads not in cohort for file: {} [{}]",
                    filename,
                    file_braid.description
                );
            }
        }
    }
}
