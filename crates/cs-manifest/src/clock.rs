use crate::types::DeviceId;
use serde::{Deserialize, Serialize};
use std::collections::BTreeMap;

/// A per-device counter map giving a partial order on events across machines.
#[derive(Clone, Debug, Default, PartialEq, Eq, Serialize, Deserialize)]
#[serde(transparent)]
pub struct VectorClock(pub BTreeMap<DeviceId, u64>);

impl VectorClock {
    pub fn new() -> Self {
        Self::default()
    }

    pub fn get(&self, d: &DeviceId) -> u64 {
        self.0.get(d).copied().unwrap_or(0)
    }

    /// Advance this device's component by one and return the new value.
    pub fn bump(&mut self, d: &DeviceId) -> u64 {
        let v = self.0.entry(d.clone()).or_insert(0);
        *v += 1;
        *v
    }

    /// Component-wise max — used when merging causal histories.
    pub fn merge(&mut self, other: &Self) {
        for (k, v) in &other.0 {
            let cur = self.0.get(k).copied().unwrap_or(0);
            self.0.insert(k.clone(), cur.max(*v));
        }
    }

    /// Strict partial order: self happens-before other iff every component of
    /// self is <= other and at least one is strictly <.
    pub fn happens_before(&self, other: &Self) -> bool {
        use std::collections::BTreeSet;
        let keys: BTreeSet<_> = self.0.keys().chain(other.0.keys()).collect();
        let mut strictly_less = false;
        for k in keys {
            let a = self.get(k);
            let b = other.get(k);
            if a > b {
                return false;
            }
            if a < b {
                strictly_less = true;
            }
        }
        strictly_less
    }

    pub fn equal(&self, other: &Self) -> bool {
        self.0 == other.0
    }

    pub fn is_empty(&self) -> bool {
        self.0.is_empty()
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn d(s: &str) -> DeviceId {
        DeviceId::new(s)
    }

    #[test]
    fn empty_clocks_do_not_happen_before() {
        let a = VectorClock::new();
        let b = VectorClock::new();
        assert!(!a.happens_before(&b));
        assert!(a.equal(&b));
    }

    #[test]
    fn bump_makes_clock_advance() {
        let mut a = VectorClock::new();
        a.bump(&d("A"));
        let b = VectorClock::new();
        assert!(b.happens_before(&a));
        assert!(!a.happens_before(&b));
    }

    #[test]
    fn concurrent_clocks_neither_happens_before() {
        // A={A:1}, B={B:1} → concurrent.
        let mut a = VectorClock::new();
        a.bump(&d("A"));
        let mut b = VectorClock::new();
        b.bump(&d("B"));
        assert!(!a.happens_before(&b));
        assert!(!b.happens_before(&a));
    }

    #[test]
    fn merge_is_union_of_components() {
        let mut a = VectorClock::new();
        a.bump(&d("A"));
        let mut b = VectorClock::new();
        b.bump(&d("B"));
        let mut m = a.clone();
        m.merge(&b);
        assert_eq!(m.get(&d("A")), 1);
        assert_eq!(m.get(&d("B")), 1);
    }

    #[test]
    fn merge_takes_componentwise_max() {
        let mut a = VectorClock::new();
        a.bump(&d("A"));
        a.bump(&d("A")); // A:2
        let mut b = VectorClock::new();
        b.bump(&d("A")); // A:1
        a.merge(&b);
        assert_eq!(a.get(&d("A")), 2);
    }

    #[test]
    fn happens_before_is_strict_not_reflexive() {
        // Equal clocks must NOT happen-before each other.
        let mut a = VectorClock::new();
        a.bump(&d("A"));
        let b = a.clone();
        assert!(!a.happens_before(&b));
    }

    #[test]
    fn happens_before_is_transitive() {
        // {} < {A:1} < {A:1,B:1}
        let z = VectorClock::new();
        let mut one = VectorClock::new();
        one.bump(&d("A"));
        let mut two = one.clone();
        two.bump(&d("B"));
        assert!(z.happens_before(&one));
        assert!(one.happens_before(&two));
        assert!(z.happens_before(&two));
    }

    #[test]
    fn bigger_on_one_device_fast_forwards() {
        // {A:1} happens-before {A:2}.
        let mut a = VectorClock::new();
        a.bump(&d("A"));
        let mut b = a.clone();
        b.bump(&d("A"));
        assert!(a.happens_before(&b));
        assert!(!b.happens_before(&a));
    }
}
