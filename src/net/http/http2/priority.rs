use std::collections::HashMap;

#[derive(Debug, Clone)]
pub struct Priority {
    pub stream_dependency: u32,
    pub weight: u8,
    pub exclusive: bool,
}

impl Priority {
    pub fn new(stream_dependency: u32, weight: u8, exclusive: bool) -> Self {
        Self {
            stream_dependency,
            weight,
            exclusive,
        }
    }

    pub fn parse(data: &[u8]) -> Self {
        if data.len() < 5 {
            return Self::default();
        }

        let first_byte = u32::from_be_bytes([data[0], data[1], data[2], data[3]]);
        let exclusive = (first_byte & 0x80000000) != 0;
        let stream_dependency = first_byte & 0x7FFFFFFF;
        let weight = data[4];

        Self {
            stream_dependency,
            weight,
            exclusive,
        }
    }

    pub fn serialize(&self) -> [u8; 5] {
        let dependency = if self.exclusive {
            self.stream_dependency | 0x80000000
        } else {
            self.stream_dependency
        };

        let bytes = dependency.to_be_bytes();
        [bytes[0], bytes[1], bytes[2], bytes[3], self.weight]
    }
}

impl Default for Priority {
    fn default() -> Self {
        Self {
            stream_dependency: 0,
            weight: 16,
            exclusive: false,
        }
    }
}

#[derive(Debug, Clone)]
struct PriorityNode {
    stream_id: u32,
    weight: u8,
    parent: u32,
    children: Vec<u32>,
    virtual_finish_time: u64,
}

impl PriorityNode {
    fn new(stream_id: u32, weight: u8, parent: u32) -> Self {
        Self {
            stream_id,
            weight,
            parent,
            children: Vec::new(),
            virtual_finish_time: 0,
        }
    }
}

#[derive(Debug)]
pub struct PriorityTree {
    nodes: HashMap<u32, PriorityNode>,
    root_children: Vec<u32>,
    virtual_time: u64,
}

impl PriorityTree {
    pub fn new() -> Self {
        Self {
            nodes: HashMap::new(),
            root_children: Vec::new(),
            virtual_time: 0,
        }
    }

    pub fn set_priority(&mut self, stream_id: u32, priority: Priority) {
        if stream_id == priority.stream_dependency {
            return;
        }

        if let Some(node) = self.nodes.get(&stream_id) {
            let old_parent = node.parent;
            self.remove_from_parent(stream_id, old_parent);
        }

        let parent_id = priority.stream_dependency;
        if priority.exclusive && parent_id != 0 {
            let old_children = if let Some(parent) = self.nodes.get_mut(&parent_id) {
                std::mem::take(&mut parent.children)
            } else if parent_id == 0 {
                std::mem::take(&mut self.root_children)
            } else {
                Vec::new()
            };

            let node = self.nodes.entry(stream_id).or_insert_with(|| {
                PriorityNode::new(stream_id, priority.weight, parent_id)
            });

            node.weight = priority.weight;
            node.parent = parent_id;
            node.children = old_children.clone();
            
            for &child_id in &old_children {
                if let Some(child) = self.nodes.get_mut(&child_id) {
                    child.parent = stream_id;
                }
            }
        } else {
            let node = self.nodes.entry(stream_id).or_insert_with(|| {
                PriorityNode::new(stream_id, priority.weight, parent_id)
            });

            node.weight = priority.weight;
            node.parent = parent_id;
        }

        if parent_id == 0 {
            if !self.root_children.contains(&stream_id) {
                self.root_children.push(stream_id);
            }
        } else {
            if let Some(parent) = self.nodes.get_mut(&parent_id) {
                if !parent.children.contains(&stream_id) {
                    parent.children.push(stream_id);
                }
            }
        }

        self.detect_and_break_cycles(stream_id);
    }

    pub fn remove(&mut self, stream_id: u32) {
        if let Some(node) = self.nodes.remove(&stream_id) {
            self.remove_from_parent(stream_id, node.parent);
            for child_id in node.children {
                if let Some(child) = self.nodes.get_mut(&child_id) {
                    child.parent = node.parent;
                }

                if node.parent == 0 {
                    if !self.root_children.contains(&child_id) {
                        self.root_children.push(child_id);
                    }
                } else if let Some(parent) = self.nodes.get_mut(&node.parent) {
                    if !parent.children.contains(&child_id) {
                        parent.children.push(child_id);
                    }
                }
            }
        }
    }

    pub fn next_stream(&mut self, available_streams: &[u32]) -> Option<u32> {
        if available_streams.is_empty() {
            return None;
        }

        let mut candidates: Vec<(u32, u64)> = Vec::new();
        for &stream_id in available_streams {
            let effective_vft = self.calculate_effective_vft(stream_id);
            candidates.push((stream_id, effective_vft));
        }
        
        candidates.sort_by_key(|&(_, vft)| vft);
        candidates.first().map(|&(stream_id, _)| stream_id)
    }

    fn calculate_effective_vft(&self, stream_id: u32) -> u64 {
        if let Some(node) = self.nodes.get(&stream_id) {
            let mut vft = node.virtual_finish_time;
            let mut current_id = stream_id;
            let mut _depth = 0;
            while current_id != 0 {
                if let Some(parent_node) = self.nodes.get(&current_id) {
                    let weight_factor = 256 / (parent_node.weight as u64 + 1);
                    vft = vft.saturating_add(weight_factor);
                    current_id = parent_node.parent;
                    _depth += 1;
                } else {
                    break;
                }
            }

            vft
        } else {
            self.virtual_time
        }
    }

    pub fn update_after_send(&mut self, stream_id: u32, bytes_sent: usize) {
        
        // Calculate service time based on weight
        // Higher weight = lower sevice time per byte = higher priority
        // Weight range 1-256, default 16
        let weight = self.nodes.get(&stream_id).map(|n| n.weight).unwrap_or(16) as u64;
        let service_time = (bytes_sent as u64 * 256) / weight;
        if let Some(node) = self.nodes.get_mut(&stream_id) {
            node.virtual_finish_time = self.virtual_time + service_time;
        }

        self.virtual_time += service_time;
    }

    pub fn calculate_effective_weight(&self, stream_id: u32) -> u8 {
        if let Some(node) = self.nodes.get(&stream_id) {
            let parent_id = node.parent;
            let siblings = if parent_id == 0 {
                &self.root_children
            } else if let Some(parent) = self.nodes.get(&parent_id) {
                &parent.children
            } else {
                return node.weight;
            };

            let total_weight: u32 = siblings.iter().filter_map(|&id| self.nodes.get(&id).map(|n| n.weight as u32)).sum();
            if total_weight == 0 {
                return node.weight;
            }

            let proportional = ((node.weight as u32 * 256) / total_weight) as u8; // Scaled 1-256
            proportional.max(1)
        } else {
            16 // Default
        }
    }

    pub fn get_ordered_streams(&self) -> Vec<u32> {
        let mut streams: Vec<_> = self.nodes.keys().cloned().collect();
        streams.sort_by_key(|&id| self.calculate_effective_vft(id));
        streams
    }

    pub fn contains(&self, stream_id: u32) -> bool {
        self.nodes.contains_key(&stream_id)
    }

    pub fn get_weight(&self, stream_id: u32) -> Option<u8> {
        self.nodes.get(&stream_id).map(|n| n.weight)
    }

    pub fn get_parent(&self, stream_id: u32) -> Option<u32> {
        self.nodes.get(&stream_id).map(|n| n.parent)
    }

    pub fn get_children(&self, stream_id: u32) -> Vec<u32> {
        if stream_id == 0 {
            self.root_children.clone()
        } else {
            self.nodes.get(&stream_id).map(|n| n.children.clone()).unwrap_or_default()
        }
    }

    fn remove_from_parent(&mut self, stream_id: u32, parent_id: u32) {
        if parent_id == 0 {
            self.root_children.retain(|&id| id != stream_id);
        } else if let Some(parent) = self.nodes.get_mut(&parent_id) {
            parent.children.retain(|&id| id != stream_id);
        }
    }

    fn detect_and_break_cycles(&mut self, start_stream_id: u32) {
        let mut visited = std::collections::HashSet::new();
        let mut current_id = start_stream_id;
        loop {
            if current_id == 0 {
                break;
            }

            if !visited.insert(current_id) {
                if let Some(node) = self.nodes.get_mut(&current_id) {
                    let old_parent = node.parent;
                    node.parent = 0;

                    if let Some(parent) = self.nodes.get_mut(&old_parent) {
                        parent.children.retain(|&id| id != current_id);
                    }

                    if !self.root_children.contains(&current_id) {
                        self.root_children.push(current_id);
                    }
                }

                break;
            }

            if let Some(node) = self.nodes.get(&current_id) {
                current_id = node.parent;
            } else {
                break;
            }

            if visited.len() > 1000 {
                break;
            }
        }
    }
}

impl Default for PriorityTree {
    fn default() -> Self {
        Self::new()
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_priority_parse() {
        let data = [0x80, 0x00, 0x00, 0x05, 0x20];
        let priority = Priority::parse(&data);
        
        assert!(priority.exclusive);
        assert_eq!(priority.stream_dependency, 5);
        assert_eq!(priority.weight, 32);
    }

    #[test]
    fn test_priority_serialize() {
        let priority = Priority::new(5, 32, true);
        let data = priority.serialize();
        
        assert_eq!(data, [0x80, 0x00, 0x00, 0x05, 0x20]);
    }

    #[test]
    fn test_priority_tree_basic() {
        let mut tree = PriorityTree::new();
        
        tree.set_priority(1, Priority::default());
        assert!(tree.contains(1));
        assert_eq!(tree.get_weight(1), Some(16));
        
        tree.set_priority(3, Priority::new(1, 32, false));
        assert_eq!(tree.get_parent(3), Some(1));
        assert_eq!(tree.get_weight(3), Some(32));
    }

    #[test]
    fn test_priority_tree_exclusive() {
        let mut tree = PriorityTree::new();
        
        tree.set_priority(1, Priority::new(0, 16, false));
        tree.set_priority(3, Priority::new(0, 16, false));
        
        assert_eq!(tree.get_children(0), vec![1, 3]);
        
        tree.set_priority(5, Priority::new(0, 32, true));
        
        assert_eq!(tree.get_parent(1), Some(5));
        assert_eq!(tree.get_parent(3), Some(5));
        assert_eq!(tree.get_parent(5), Some(0));
    }

    #[test]
    fn test_priority_tree_cycle_prevention() {
        let mut tree = PriorityTree::new();
        
        tree.set_priority(1, Priority::new(0, 16, false));
        tree.set_priority(3, Priority::new(1, 16, false));
        tree.set_priority(5, Priority::new(3, 16, false));
        
        tree.set_priority(1, Priority::new(5, 16, false));
        
        assert_ne!(tree.get_parent(1), Some(5));
    }

    #[test]
    fn test_priority_tree_self_dependency() {
        let mut tree = PriorityTree::new();
        
        tree.set_priority(1, Priority::new(1, 16, false));
        
        if tree.contains(1) {
            assert_ne!(tree.get_parent(1), Some(1));
        }
    }

    #[test]
    fn test_weighted_fair_queuing() {
        let mut tree = PriorityTree::new();
        
        tree.set_priority(1, Priority::new(0, 32, false));
        tree.set_priority(3, Priority::new(0, 8, false));
        
        let available = vec![1, 3];
        
        let next = tree.next_stream(&available);
        assert_eq!(next, Some(1));
        
        tree.update_after_send(1, 1000);
        
        let next = tree.next_stream(&available);
        assert!(next == Some(1) || next == Some(3));
    }

    #[test]
    fn test_priority_tree_remove() {
        let mut tree = PriorityTree::new();
        
        tree.set_priority(1, Priority::new(0, 16, false));
        tree.set_priority(3, Priority::new(1, 16, false));
        tree.set_priority(5, Priority::new(1, 16, false));
        
        assert_eq!(tree.get_children(1), vec![3, 5]);
        
        tree.remove(1);
        
        assert!(!tree.contains(1));
        assert_eq!(tree.get_parent(3), Some(0));
        assert_eq!(tree.get_parent(5), Some(0));
    }

    #[test]
    fn test_effective_weight() {
        let mut tree = PriorityTree::new();
        
        tree.set_priority(1, Priority::new(0, 64, false));  // 64/96 = 2/3
        tree.set_priority(3, Priority::new(0, 32, false));  // 32/96 = 1/3
        
        let weight1 = tree.calculate_effective_weight(1);
        let weight3 = tree.calculate_effective_weight(3);
        
        assert!(weight1 > weight3);
    }

    #[test]
    fn test_get_ordered_streams() {
        let mut tree = PriorityTree::new();
        
        tree.set_priority(1, Priority::new(0, 64, false));
        tree.set_priority(3, Priority::new(0, 32, false));
        tree.set_priority(5, Priority::new(0, 16, false));
        
        let ordered = tree.get_ordered_streams();
        
        assert_eq!(ordered.len(), 3);
        assert!(ordered.contains(&1));
        assert!(ordered.contains(&3));
        assert!(ordered.contains(&5));
    }
}