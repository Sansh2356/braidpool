use crate::bead::Bead;
use crate::config::PoolNetwork;
use crate::error::BraidError;
use crate::utils::{compute_block_hash, BeadHash};
use bitcoin::{Target, Work};
use std::collections::{HashMap, HashSet, VecDeque};
use std::mem;
use std::sync::atomic::{AtomicU64, Ordering};
use std::time::{Duration, Instant};

pub mod algorithms;

/// Snapshot id of the corresponding braid.
static NEXT_REVISION: AtomicU64 = AtomicU64::new(0);

fn next_revision() -> u64 {
    NEXT_REVISION.fetch_add(1, Ordering::Relaxed)
}

/// Upper bound on the orphanage occupancy history kept by a braid.
const MAX_OCCUPANCY_EVENTS: usize = 4096;

/// A type alias which represents an index into Braid::beads
pub type BeadIdx = usize;
/// A type representing parents, children, ancestors, or descendants
pub type Relatives = HashMap<BeadIdx, HashSet<BeadIdx>>;
/// A type representing a set of beads indexed in Braid::beads
pub type BeadSet = HashSet<BeadIdx>;
/// A type representing the work for each bead
pub type BeadWork = HashMap<BeadIdx, Work>;
/// A type representing a cohort (a set of beads indexed in Braid::beads)
pub type Cohort = HashSet<BeadIdx>;
/// A type alias which represents an index into Braid::cohorts
pub type CohortIdx = usize;

#[derive(Debug, Clone, PartialEq)]
pub enum AddBeadStatus {
    /// Bead already exists in the DAG (duplicate)
    DuplicateBead,
    /// Bead was rejected: a parentless bead other than the genesis, or a `weak_target` that
    /// carries no work.
    InvalidBead,
    /// Bead was connected to the DAG. Carries any orphan beads whose parents
    /// became available as a result and were added too, in insertion order.
    BeadAdded {
        /// Orphans connected along with the bead, in insertion order
        promoted_orphans: Vec<Bead>,
    },
    /// Parents not yet in DAG, bead added to orphanage
    ParentsMissing,
}

#[derive(Debug, Clone)]
pub enum GenesisCheckStatus {
    /// The peer reported exactly our genesis bead
    GenesisBeadsValid,
    /// The peer's genesis is a different bead, so the peer follows another braid
    GenesisMismatch,
    /// The peer did not report exactly one genesis bead
    GenesisBeadsCountMismatch,
}

/// How [`Braid::extend`] updates the cohorts when a bead is connected.
#[derive(Clone, Debug, Copy, Default, PartialEq, Eq, Hash)]
pub enum ExtendStrategy {
    /// Optimized heuristic approach (default)
    #[default]
    Heuristic,
    /// Recomputes cohorts with `algorithms::cohorts`, starting from the head of the earliest
    /// cohort that holds a parent of the new bead; earlier cohorts are kept as they are.
    Cached,
    /// Recomputes every cohort with `algorithms::cohorts` and rebuilds all caches on each bead.
    NoCache,
}

/// The DAG of beads, with the cohorts and work totals maintained as beads are connected.
#[derive(Debug, Clone)]
pub struct Braid {
    /// Every connected bead; a bead's position here is its `BeadIdx`
    pub beads: Vec<Bead>,
    // Hash of every bead in `beads`, at the same index
    pub(crate) hashes: Vec<BeadHash>,
    /// Work each bead contributes, derived from its `weak_target`
    pub bead_work: BeadWork,
    /// Beads that have no children yet
    pub tips: BeadSet,
    /// Cohorts in order from the genesis to the tips
    pub cohorts: Vec<Cohort>,
    // Hash of the single genesis bead; known even when a restored braid does not hold the bead
    genesis: BeadHash,
    /// Index into `beads` of each connected bead, by bead hash
    pub index: HashMap<BeadHash, BeadIdx>,
    /// Parents of each bead
    pub parents: Relatives,
    /// Children of each bead
    pub children: Relatives,
    /// Beads waiting for a parent that is not in the braid yet, by bead hash
    pub orphanage: HashMap<BeadHash, Bead>,
    // Performance optimization caches (public to crate only -- no one else should need them)
    pub(crate) ancestor_cache: Relatives,
    pub(crate) descendant_cache: Relatives,
    pub(crate) tail_cache: Vec<BeadSet>,
    pub(crate) cohort_map: HashMap<BeadIdx, CohortIdx>,
    // Total work of each cohort, at the same index as `cohorts`
    pub(crate) cohort_work: Vec<Work>,
    // Work of each bead plus its descendants inside its own cohort
    pub(crate) local_dwork: BeadWork,
    // Work of each bead plus its ancestors inside its own cohort
    pub(crate) local_awork: BeadWork,
    // Orphan reverse index (parent hash -> orphan hash)
    pub(crate) missing_parents: HashMap<BeadHash, HashSet<BeadHash>>,
    /// How cohorts are updated when a bead is connected
    pub extend_strategy: ExtendStrategy,
    /// Network whose rules are used to compute bead hashes
    pub network: PoolNetwork,
    // (time, occupancy, cumulative area micros); holds at most MAX_OCCUPANCY_EVENTS entries
    occupancy_events: VecDeque<(Instant, u64, u64)>,
    // Whether events have been dropped from the front of `occupancy_events`
    occupancy_truncated: bool,
    // Changes whenever a bead is connected; unique across all braids, including replacements
    revision: u64,
}

impl Braid {
    /// Creates a braid with no beads yet, rooted at `genesis`, whose bead hashes are computed
    /// under `network`.
    fn empty(genesis: BeadHash, network: PoolNetwork, strategy: ExtendStrategy) -> Self {
        let now = Instant::now();
        Braid {
            beads: Vec::new(),
            hashes: Vec::new(),
            bead_work: HashMap::new(),
            tips: HashSet::new(),
            cohorts: Vec::new(),
            genesis,
            index: HashMap::new(),
            parents: HashMap::new(),
            children: HashMap::new(),
            orphanage: HashMap::new(),
            ancestor_cache: HashMap::new(),
            descendant_cache: HashMap::new(),
            tail_cache: Vec::new(),
            cohort_map: HashMap::new(),
            cohort_work: Vec::new(),
            local_dwork: HashMap::new(),
            local_awork: HashMap::new(),
            missing_parents: HashMap::new(),
            extend_strategy: strategy,
            network,
            occupancy_events: VecDeque::from([(now, 0, 0)]),
            occupancy_truncated: false,
            revision: next_revision(),
        }
    }

    /// Creates a braid holding only `genesis`, its single root.
    ///
    /// Nodes pass [`Bead::genesis`], audit mode passes its own genesis bead, and tests may pass
    /// a bead of their own. The genesis is the
    /// only parentless bead the braid accepts: `extend` rejects any other.
    pub fn new(genesis: Bead, network: PoolNetwork) -> Self {
        Self::new_with_strategy(genesis, ExtendStrategy::default(), network)
    }

    /// Same as [`Braid::new`], updating cohorts with `strategy`.
    pub fn new_with_strategy(
        genesis: Bead,
        strategy: ExtendStrategy,
        network: PoolNetwork,
    ) -> Self {
        let genesis_hash = compute_block_hash(&genesis.block_header, network);
        let mut braid = Self::empty(genesis_hash, network, strategy);
        braid.insert_roots([genesis]);
        braid
    }

    /// Creates a braid whose first bead is its genesis, then extends it with the rest in order.
    #[cfg(test)]
    pub(crate) fn from_beads(
        beads: impl IntoIterator<Item = Bead>,
        strategy: ExtendStrategy,
        network: PoolNetwork,
    ) -> Self {
        let mut beads = beads.into_iter();
        let genesis = beads.next().expect("a braid needs a genesis bead");
        assert!(
            genesis.committed_metadata.parents.is_empty(),
            "the first bead must be the genesis"
        );
        let mut braid = Self::new_with_strategy(genesis, strategy, network);
        for bead in beads {
            let _ = braid.extend(&bead);
        }
        braid
    }

    /// Creates a braid on `genesis` restored from `roots`, the tips loaded from storage, ignoring
    /// their committed parents.
    ///
    /// The genesis bead itself need not be among `roots`: the braid keeps its hash, so it still
    /// reports and checks the genesis after a restart.
    pub fn from_roots(
        genesis: BeadHash,
        roots: impl IntoIterator<Item = Bead>,
        network: PoolNetwork,
    ) -> Self {
        let mut braid = Self::empty(genesis, network, ExtendStrategy::default());
        braid.insert_roots(roots);
        braid
    }

    /// Inserts `roots` into an empty braid as parentless beads sharing the first cohort.
    fn insert_roots(&mut self, roots: impl IntoIterator<Item = Bead>) {
        let mut cohort = Cohort::new();
        for bead in roots {
            let bead_hash = self.compute_bead_hash(&bead);
            if self.index.contains_key(&bead_hash) {
                continue;
            }
            let Some(work) = Self::bead_work_of(&bead) else {
                continue;
            };
            let bead_index = self.beads.len();
            self.bead_work.insert(bead_index, work);
            self.beads.push(bead);
            self.hashes.push(bead_hash);
            self.index.insert(bead_hash, bead_index);
            self.parents.insert(bead_index, BeadSet::new());
            self.children.insert(bead_index, BeadSet::new());
            self.tips.insert(bead_index);
            cohort.insert(bead_index);
        }
        if !cohort.is_empty() {
            self.cohorts.push(cohort);
            self.rebuild_suffix(0);
        }
        self.revision = next_revision();
    }

    /// Returns the hash of the braid's genesis bead.
    pub fn genesis(&self) -> BeadHash {
        self.genesis
    }

    /// Returns an identifier for the current DAG state.
    ///
    /// It changes every time a bead is connected and is never reused, even by a braid that
    /// replaces this one, so callers can cache values derived from the DAG keyed on it.
    pub fn revision(&self) -> u64 {
        self.revision
    }

    /// Computes the highest work path from the work totals maintained as beads are connected.
    ///
    /// Gives the same path as [`algorithms::highest_work_path`] without rebuilding cohorts or
    /// descendant sets: the query only sums the per-cohort totals and walks the path.
    pub fn highest_work_path(&self) -> Option<Vec<BeadIdx>> {
        self.highest_work_path_with_hashes(&self.hashes)
    }

    /// [`Self::highest_work_path`], breaking work ties with `hashes` instead of the bead hashes.
    fn highest_work_path_with_hashes(&self, hashes: &[BeadHash]) -> Option<Vec<BeadIdx>> {
        let (work_before, work_after) = self.cumulative_cohort_work();
        let dwork = |b: BeadIdx| {
            algorithms::add_work(work_after[self.cohort_map[&b]], self.local_dwork[&b])
        };
        let awork = |b: BeadIdx| {
            algorithms::add_work(work_before[self.cohort_map[&b]], self.local_awork[&b])
        };
        let cmp =
            |a: &&BeadIdx, b: &&BeadIdx| algorithms::bead_cmp_by(**a, **b, dwork, awork, hashes);

        // Every parentless bead lives in the first cohort
        let mut current = *self
            .cohorts
            .first()?
            .iter()
            .filter(|b| self.parents[b].is_empty())
            .max_by(cmp)?;
        let mut hwpath = vec![current];
        while let Some(next) = self.children.get(&current)?.iter().max_by(cmp) {
            current = *next;
            hwpath.push(current);
        }
        Some(hwpath)
    }

    /// Returns, for each cohort, the total work of all cohorts before it and of all cohorts
    /// after it.
    ///
    /// Sums saturate, which keeps them independent of the order they are added in, so they
    /// match [`algorithms::descendant_work`].
    fn cumulative_cohort_work(&self) -> (Vec<Work>, Vec<Work>) {
        let mut before = Vec::with_capacity(self.cohort_work.len());
        let mut sum = algorithms::zero_work();
        for &work in &self.cohort_work {
            before.push(sum);
            sum = algorithms::add_work(sum, work);
        }
        let mut after = vec![algorithms::zero_work(); self.cohort_work.len()];
        let mut sum = algorithms::zero_work();
        for (i, &work) in self.cohort_work.iter().enumerate().rev() {
            after[i] = sum;
            sum = algorithms::add_work(sum, work);
        }
        (before, after)
    }

    /// Returns the hash of every bead, indexed by `BeadIdx`.
    pub fn hashes(&self) -> &[BeadHash] {
        &self.hashes
    }

    /// Returns the work a bead contributes, or `None` if its `weak_target` decodes to zero
    /// (a zero mantissa or a negative compact encoding), which no hash can meet.
    fn bead_work_of(bead: &Bead) -> Option<Work> {
        let target = Target::from_compact(bead.committed_metadata.weak_target);
        (target != Target::ZERO).then(|| target.to_work())
    }

    /// Computes the block hash for a bead using this braid's network configuration
    pub fn compute_bead_hash(&self, bead: &Bead) -> BeadHash {
        compute_block_hash(&bead.block_header, self.network)
    }

    /// Gets parent BeadSet for a bead.
    /// Parent hashes not found in the braid index are skipped.
    pub fn parent_indices(&self, bead: &Bead) -> BeadSet {
        bead.committed_metadata
            .parents
            .iter()
            .filter_map(|h| self.index.get(h).copied())
            .collect()
    }

    /// Maps each of `bead`'s parents to its braid index and start timestamp.
    pub fn resolve_parents(&self, bead: &Bead) -> Result<Vec<(u64, u64)>, BraidError> {
        bead.committed_metadata
            .parents
            .iter()
            .map(|parent_hash| {
                let &parent_index =
                    self.index
                        .get(parent_hash)
                        .ok_or_else(|| BraidError::MissingParent {
                            bead: self.compute_bead_hash(bead),
                            parent: *parent_hash,
                        })?;
                Ok((
                    parent_index as u64,
                    self.beads[parent_index]
                        .committed_metadata
                        .start_timestamp
                        .as_micros(),
                ))
            })
            .collect()
    }

    /// Records the occupancy integral up to `now`, appending an event and dropping the oldest
    /// one once the history is full.
    fn occupancy_event(&mut self, now: Instant) {
        if self.occupancy_events.len() >= MAX_OCCUPANCY_EVENTS {
            self.occupancy_events.pop_front();
            self.occupancy_truncated = true;
        }
        if let Some((last_t, _, last_area)) = self.occupancy_events.back().copied() {
            let delta = now.duration_since(last_t).as_micros();
            let occ = self.orphanage.len() as u64;
            // Saturate to avoid overflow; orphan stays ~1s, so micros is sufficient
            let area = last_area
                .saturating_add((delta.saturating_mul(occ as u128)).min(u64::MAX as u128) as u64);
            self.occupancy_events.push_back((now, occ, area));
        } else {
            let occ = self.orphanage.len() as u64;
            self.occupancy_events.push_back((now, occ, 0));
        }
    }

    /// Returns the average orphanage occupancy over the last `interval`, using the event history.
    /// The history is bounded: once events have been dropped, an `interval` reaching back past
    /// the oldest kept event returns the average over the time since that event instead, or
    /// `None` if no time has passed since it.
    ///
    /// A query records no event, so it never evicts history.
    pub fn orphanage_occupancy(&self, interval: Duration) -> Option<f64> {
        let now = Instant::now();

        let start = now.checked_sub(interval).unwrap_or(now);

        // Find the event just before or at `start`
        let mut idx = None;
        for (i, (t, _, _)) in self.occupancy_events.iter().enumerate().rev() {
            if *t <= start {
                idx = Some(i);
                break;
            }
        }

        let (prev_t, prev_occ, prev_area) = if let Some(i) = idx {
            self.occupancy_events[i]
        } else {
            // No earlier event: use the first
            self.occupancy_events.front().copied()?
        };

        let area_at_start = {
            let delta = start.duration_since(prev_t).as_micros();
            let incr = (delta.saturating_mul(prev_occ as u128)).min(u64::MAX as u128) as u64;
            prev_area.saturating_add(incr)
        };

        // The occupancy integral up to `now`, as `occupancy_event` would record it
        let area_now = {
            let (last_t, _, last_area) = self.occupancy_events.back().copied()?;
            let delta = now.duration_since(last_t).as_micros();
            let occ = self.orphanage.len() as u128;
            last_area.saturating_add(delta.saturating_mul(occ).min(u64::MAX as u128) as u64)
        };
        let window_area = area_now.saturating_sub(area_at_start);
        let mut interval_us = interval.as_micros();
        if idx.is_none() && self.occupancy_truncated {
            // The occupancy before the oldest kept event is unknown, so leave that time out
            interval_us = now.duration_since(prev_t).as_micros();
        }
        if interval_us == 0 {
            return None;
        }
        Some(window_area as f64 / interval_us as f64)
    }

    /// Rebuild caches (ancestor, descendant, tail, cohort_map, per-cohort work) for cohorts
    /// starting at `start_idx`.
    /// Does nothing if `start_idx` is past the last cohort.
    fn rebuild_suffix(&mut self, start_idx: CohortIdx) {
        // Truncating the tails after the start_idx due to cohort change .
        self.tail_cache.truncate(start_idx);
        self.cohort_work.truncate(start_idx);
        // Entries of the prefix cohorts are kept, their structure will remain as is .
        // Beads never leave the suffix, so clearing its beads drops every stale entry.
        for cohort in self.cohorts.iter().skip(start_idx) {
            for &bead in cohort {
                self.cohort_map.remove(&bead);
                self.ancestor_cache.remove(&bead);
                self.descendant_cache.remove(&bead);
            }
        }
        // Moving through the suffix cohort and rebuilding the suffix caches .
        for (cohort_idx, cohort) in self.cohorts.iter().enumerate().skip(start_idx) {
            // Updating descendant cache .
            for &bead in cohort {
                self.cohort_map.insert(bead, cohort_idx);
                self.descendant_cache.entry(bead).or_default();
            }
            let sub_parents = algorithms::sub_braid(cohort, &self.parents);
            let sub_children = algorithms::reverse(&sub_parents);
            let mut local_ancestors = Relatives::new();
            for &bead in cohort {
                algorithms::all_ancestors(bead, &sub_parents, &mut local_ancestors);
            }

            for (bead, ancestors) in local_ancestors {
                for &ancestor in &ancestors {
                    self.descendant_cache
                        .entry(ancestor)
                        .or_default()
                        .insert(bead);
                }
                self.ancestor_cache.insert(bead, ancestors);
            }

            // Within-cohort work; the work of earlier and later cohorts is added at query time.
            let mut total = algorithms::zero_work();
            for &bead in cohort {
                let own = self.bead_work[&bead];
                let sum_of = |relatives: Option<&BeadSet>| {
                    relatives
                        .into_iter()
                        .flatten()
                        .map(|r| self.bead_work[r])
                        .fold(own, algorithms::add_work)
                };
                self.local_dwork
                    .insert(bead, sum_of(self.descendant_cache.get(&bead)));
                self.local_awork
                    .insert(bead, sum_of(self.ancestor_cache.get(&bead)));
                total = algorithms::add_work(total, own);
            }
            self.cohort_work.push(total);

            self.tail_cache
                .push(algorithms::cohort_tail(cohort, &sub_parents, &sub_children));
        }
    }

    /// Connects every orphan that becomes connectable once `parent_hash` is in the braid,
    /// including orphans unblocked transitively by beads promoted along the way.
    fn adopt_orphans(&mut self, parent_hash: BeadHash) -> Vec<Bead> {
        let mut promoted = Vec::new();
        let mut connected = VecDeque::from([parent_hash]);
        while let Some(hash) = connected.pop_front() {
            // Removing parent hash that will resolve some orphans having only not
            // available .
            let waiting = match self.missing_parents.remove(&hash) {
                Some(waiting) => waiting,
                None => continue,
            };
            let now = Instant::now();
            self.occupancy_event(now);
            let mut waiting: Vec<BeadHash> = waiting.into_iter().collect();
            waiting.sort();

            let mut ready = Vec::new();
            // Iterating over child whose parent has resolved .
            for child_hash in waiting {
                // Checking if all the parents have been resolved .
                let all_parents_present = match self.orphanage.get(&child_hash) {
                    Some(orphan_bead) => orphan_bead
                        .committed_metadata
                        .parents
                        .iter()
                        .all(|p| self.index.contains_key(p)),
                    None => false,
                };
                // Children still missing another parent stay parked under that parent's bucket.
                if !all_parents_present {
                    continue;
                }
                // Removing beads from the orphan set as all parents have been resolved .
                let Some(ready_bead) = self.orphanage.remove(&child_hash) else {
                    continue;
                };
                for p in &ready_bead.committed_metadata.parents {
                    // Removing child hash from parent bucket .
                    if let Some(bucket) = self.missing_parents.get_mut(p) {
                        bucket.remove(&child_hash);
                        if bucket.is_empty() {
                            self.missing_parents.remove(p);
                        }
                    }
                }
                ready.push((child_hash, ready_bead));
            }
            if !ready.is_empty() {
                self.occupancy_event(now);
            }
            for (child_hash, bead) in ready {
                // Connecting the removed orphan bead .
                self.connect_bead(&bead, child_hash);
                // Adding the child hash in bfs manner to resolve the child
                // of newly promoted orphan bead .
                connected.push_back(child_hash);
                promoted.push(bead);
            }
        }
        promoted
    }

    /// Attempts to extend the braid with the given bead.
    ///
    /// Returns `BeadAdded` carrying every orphan that became connectable as a result,
    /// `ParentsMissing` if the bead was parked in the orphanage, `DuplicateBead`, or
    /// `InvalidBead` for a parentless bead other than the genesis or a zero `weak_target`.
    pub fn extend(&mut self, bead: &Bead) -> AddBeadStatus {
        let bead_hash = self.compute_bead_hash(bead);
        if self.index.contains_key(&bead_hash) {
            return AddBeadStatus::DuplicateBead;
        }
        if self.orphanage.contains_key(&bead_hash) {
            return AddBeadStatus::DuplicateBead;
        }
        // The genesis is the only parentless bead; a restored braid knows it without holding it.
        if bead.committed_metadata.parents.is_empty() {
            return if bead_hash == self.genesis {
                AddBeadStatus::DuplicateBead
            } else {
                AddBeadStatus::InvalidBead
            };
        }
        // Checked before parking orphans so every bead that reaches connect_bead has work.
        if Self::bead_work_of(bead).is_none() {
            return AddBeadStatus::InvalidBead;
        }

        let missing_parents: Vec<_> = bead
            .committed_metadata
            .parents
            .iter()
            .filter(|&&h| !self.index.contains_key(&h))
            .copied()
            .collect();
        // If an orphan bead is received.
        if !missing_parents.is_empty() {
            let now = Instant::now();
            self.occupancy_event(now);
            // Inserting to orphan set .
            self.orphanage.insert(bead_hash, bead.clone());
            // Parents that are missing .
            for parent_hash in missing_parents {
                self.missing_parents
                    .entry(parent_hash)
                    .or_default()
                    .insert(bead_hash);
            }
            self.occupancy_event(now);
            return AddBeadStatus::ParentsMissing;
        }

        self.connect_bead(bead, bead_hash);
        // This bead may be the last missing parent of parked orphans; connect those too
        // and surface them to the caller for persistence.
        let promoted_orphans = self.adopt_orphans(bead_hash);
        AddBeadStatus::BeadAdded { promoted_orphans }
    }

    /// Inserts a bead whose parents are all in the braid and updates tips and cohorts.
    ///
    /// The bead must have passed `extend`'s checks, so it has at least one parent and a
    /// non-zero `weak_target`.
    /// Does not touch the orphanage; callers adopt any orphans waiting on this bead afterwards.
    fn connect_bead(&mut self, bead: &Bead, bead_hash: BeadHash) {
        self.revision = next_revision();
        // Fetching bead parents .
        let bead_parents = self.parent_indices(bead);

        // Insert bead into storage
        self.beads.push(bead.clone());
        self.hashes.push(bead_hash);
        let new_bead_index = self.beads.len() - 1;
        // Reverse mapping from bead to its index .
        self.index.insert(bead_hash, new_bead_index);
        // Work map; extend has already rejected beads whose target has no work.
        let work = Self::bead_work_of(bead).unwrap_or_else(|| Target::MAX.to_work());
        self.bead_work.insert(new_bead_index, work);

        for &parent_index in &bead_parents {
            // The parent beads adding current bead as their child .
            self.children
                .entry(parent_index)
                .or_default()
                .insert(new_bead_index);
        }
        // Updating parents mapping .
        self.parents.insert(new_bead_index, bead_parents.clone());
        // Updating children mapping .
        self.children.entry(new_bead_index).or_default();

        for &parent_index in &bead_parents {
            self.tips.remove(&parent_index);
        }
        // Updating tips .
        self.tips.insert(new_bead_index);

        match self.extend_strategy {
            ExtendStrategy::Heuristic => {
                // --- O(W) Heuristic Cohort Update ---
                // Logic:
                // 1. Find the range [idx_min, idx_max] of cohorts containing parents.
                // 2. If idx_min < idx_max, merge all cohorts in that range.
                // 3. Identify tail of the (possibly merged) parent cohort.
                // 4. If the new bead's parents include ALL of the tail, it extends the cohort (New Cohort) i.e. a graph cut was found.
                // 5. Otherwise, it merges into that cohort (Merge).

                let parent_indices_set = &bead_parents;

                let mut idx_max = None;
                let mut idx_min = None;
                let mut parents_found_count = 0;
                let total_parents = parent_indices_set.len();

                for (i, cohort) in self.cohorts.iter().enumerate().rev() {
                    let count_in_cohort = parent_indices_set
                        .iter()
                        .filter(|&p| cohort.contains(p))
                        .count();
                    if count_in_cohort > 0 {
                        if idx_max.is_none() {
                            idx_max = Some(i);
                        }
                        idx_min = Some(i);
                        parents_found_count += count_in_cohort;

                        if parents_found_count == total_parents {
                            break;
                        }
                    }
                }

                let insertion_idx = if let (Some(max), Some(min)) = (idx_max, idx_min) {
                    // Check if parents cover all internal tips of the latest parent cohort.
                    // Use the cached tail (which represents internal tips).
                    // If we span multiple cohorts (min < max), the effective tail of the merged group
                    // is the tail of the latest cohort (max).
                    let covers_tips = self.tail_cache[max].is_subset(parent_indices_set);

                    // Merge Spanned Cohorts if necessary
                    if min < max {
                        for i in (min + 1)..=max {
                            let merged = mem::take(&mut self.cohorts[i]);
                            self.cohorts[min].extend(merged);
                        }

                        self.cohorts.drain((min + 1)..=max);
                    }

                    // If we cover tips, we extend (min + 1). Else we merge into min.
                    if covers_tips {
                        min + 1
                    } else {
                        min
                    }
                } else {
                    0
                };

                // Apply changes
                if insertion_idx == self.cohorts.len() {
                    self.cohorts.push(HashSet::new());
                }

                self.cohorts[insertion_idx].insert(new_bead_index);

                if insertion_idx < self.cohorts.len() - 1 {
                    for i in (insertion_idx + 1)..self.cohorts.len() {
                        let beads_to_merge: Vec<_> = self.cohorts[i].iter().copied().collect();
                        self.cohorts[insertion_idx].extend(beads_to_merge);
                    }
                    self.cohorts.truncate(insertion_idx + 1);
                }

                let rebuild_start = idx_min.unwrap_or(insertion_idx);
                self.rebuild_suffix(rebuild_start);
            }
            ExtendStrategy::Cached => {
                // Cuts before the earliest cohort holding a parent stay valid: the new bead
                // descends from that parent, which already descends from every earlier cohort.
                let start_cohort_idx = self
                    .cohorts
                    .iter()
                    .position(|cohort| cohort.iter().any(|p| bead_parents.contains(p)))
                    .unwrap_or(0);

                // Restart from the head of that cohort (its beads with no parent inside it).
                // Passing the whole cohort would blank the ancestry between its own beads and
                // hide the cuts that follow it.
                let head = match self.cohorts.get(start_cohort_idx) {
                    Some(cohort) => {
                        algorithms::geneses(&algorithms::sub_braid(cohort, &self.parents))
                    }
                    None => algorithms::geneses(&self.parents),
                };

                self.cohorts.truncate(start_cohort_idx);
                let mut scratch = Relatives::new();
                let new_cohorts =
                    algorithms::cohorts(&self.parents, &self.children, &head, &mut scratch);
                self.cohorts.extend(new_cohorts);
                self.rebuild_suffix(start_cohort_idx);
            }
            ExtendStrategy::NoCache => {
                let geneses = algorithms::geneses(&self.parents);
                let mut scratch = Relatives::new();

                self.cohorts =
                    algorithms::cohorts(&self.parents, &self.children, &geneses, &mut scratch);

                self.ancestor_cache.clear();
                self.descendant_cache.clear();
                self.tail_cache.clear();
                self.cohort_map.clear();
                self.rebuild_suffix(0);
            }
        }
    }

    /// Checks the genesis a peer reported against this braid's genesis.
    ///
    /// A peer must report exactly one genesis bead, equal to ours.
    pub fn check_genesis(&self, peer_genesis: &[BeadHash]) -> GenesisCheckStatus {
        match peer_genesis {
            [genesis] if *genesis == self.genesis => GenesisCheckStatus::GenesisBeadsValid,
            [_] => GenesisCheckStatus::GenesisMismatch,
            _ => GenesisCheckStatus::GenesisBeadsCountMismatch,
        }
    }

    /// Utility function for GetBeadsAfter request (IBD sync).
    ///
    /// Returns every bead from the cohort of the earliest known tip onward, leaving out the
    /// tips themselves, or all beads if `old_tips` is empty or names no known bead. `None`
    /// means the requester already has everything.
    pub fn get_beads_after(&self, old_tips: Vec<BeadHash>) -> Option<Vec<Bead>> {
        let indices = self.bead_indices_after(old_tips)?;
        Some(indices.into_iter().map(|i| self.beads[i].clone()).collect())
    }

    /// Same as [`Braid::get_beads_after`], returning only the hashes, so no bead is cloned.
    pub fn get_bead_hashes_after(&self, old_tips: Vec<BeadHash>) -> Option<Vec<BeadHash>> {
        let indices = self.bead_indices_after(old_tips)?;
        Some(indices.into_iter().map(|i| self.hashes[i]).collect())
    }

    /// Indices of the beads [`Braid::get_beads_after`] returns, in the order it returns them.
    fn bead_indices_after(&self, old_tips: Vec<BeadHash>) -> Option<Vec<BeadIdx>> {
        let old_tips_set: HashSet<BeadHash> = old_tips.into_iter().collect();
        tracing::debug!(
            old_tips=?old_tips_set, "Tips received for IBD sync"
        );

        // Find the cohort of the earliest known tip. With no tips, or none that we know,
        // return all beads.
        let smallest_index = old_tips_set
            .iter()
            .filter_map(|hash| self.index.get(hash).copied())
            .min();
        let Some(smallest_cohort_index) =
            smallest_index.and_then(|index| self.cohort_map.get(&index).copied())
        else {
            return Some((0..self.beads.len()).collect());
        };

        tracing::debug!(
            smallest_index,
            smallest_cohort_index,
            "Starting from cohort index"
        );

        // Collect beads from the smallest cohort onward, excluding old tips. Beads within a
        // cohort are sorted by index: a bead is only indexed after its parents, so this is a
        // deterministic topological order the receiver can apply without parking orphans.
        let mut response_beads = Vec::new();
        for cohort in self.cohorts.iter().skip(smallest_cohort_index) {
            let mut ordered: Vec<BeadIdx> = cohort.iter().copied().collect();
            ordered.sort_unstable();
            response_beads.extend(
                ordered
                    .into_iter()
                    .filter(|&bead_index| !old_tips_set.contains(&self.hashes[bead_index])),
            );
        }

        if response_beads.is_empty() {
            None
        } else {
            Some(response_beads)
        }
    }
}
