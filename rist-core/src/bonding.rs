#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum PeerSelection {
    DuplicateAll,
    Peer(usize),
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct WeightedPeerSelector {
    weights: Vec<u32>,
    current: Vec<i128>,
    total_weight: i128,
}

impl WeightedPeerSelector {
    pub fn new() -> Self {
        Self {
            weights: Vec::new(),
            current: Vec::new(),
            total_weight: 0,
        }
    }

    pub fn with_weights(weights: impl IntoIterator<Item = u32>) -> Self {
        let mut selector = Self::new();
        for weight in weights {
            selector.add_peer(weight);
        }
        selector
    }

    pub fn add_peer(&mut self, weight: u32) -> usize {
        let index = self.weights.len();
        self.weights.push(weight);
        self.current.push(0);
        self.recalculate_total_weight();
        index
    }

    pub fn set_weight(&mut self, index: usize, weight: u32) -> bool {
        let Some(slot) = self.weights.get_mut(index) else {
            return false;
        };
        *slot = weight;
        self.recalculate_total_weight();
        true
    }

    pub fn len(&self) -> usize {
        self.weights.len()
    }

    pub fn is_empty(&self) -> bool {
        self.weights.is_empty()
    }

    pub fn weights(&self) -> &[u32] {
        &self.weights
    }

    pub fn select(&mut self) -> PeerSelection {
        if self.total_weight == 0 {
            return PeerSelection::DuplicateAll;
        }

        let mut selected = None;
        let mut selected_weight = i128::MIN;
        for (index, weight) in self.weights.iter().enumerate() {
            let weight = i128::from(*weight);
            if weight == 0 {
                continue;
            }
            self.current[index] += weight;
            if self.current[index] > selected_weight {
                selected = Some(index);
                selected_weight = self.current[index];
            }
        }

        let selected = selected.expect("positive total weight requires a selectable peer");
        self.current[selected] -= self.total_weight;
        PeerSelection::Peer(selected)
    }

    fn recalculate_total_weight(&mut self) {
        self.total_weight = self.weights.iter().map(|weight| i128::from(*weight)).sum();
    }
}

impl Default for WeightedPeerSelector {
    fn default() -> Self {
        Self::new()
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn zero_weights_select_duplicate_mode() {
        let mut selector = WeightedPeerSelector::with_weights([0, 0]);
        assert_eq!(selector.select(), PeerSelection::DuplicateAll);
        assert_eq!(selector.select(), PeerSelection::DuplicateAll);
    }

    #[test]
    fn positive_weights_select_smooth_weighted_peers() {
        let mut selector = WeightedPeerSelector::with_weights([2, 1]);
        let selected = (0..6).map(|_| selector.select()).collect::<Vec<_>>();
        assert_eq!(
            selected,
            vec![
                PeerSelection::Peer(0),
                PeerSelection::Peer(1),
                PeerSelection::Peer(0),
                PeerSelection::Peer(0),
                PeerSelection::Peer(1),
                PeerSelection::Peer(0),
            ]
        );
    }
}
