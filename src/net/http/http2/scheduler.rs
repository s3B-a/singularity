use super::priority::Priority;
use std::collections::{HashMap, VecDeque};

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum StreamScheduleState {
    Ready,
    Blocked,
    Idle,
    Closed,
}

#[derive(Debug, Clone)]
struct ScheduleStream {
    stream_id: u32,
    state: StreamScheduleState,
    priority: Priority,
    pending_bytes: usize,
    quantum: usize, // Weighted fair queuing ( calculated from weight )
    deficit: i64,
}

impl ScheduleStream {
    fn new(stream_id: u32, priority: Priority) -> Self {
        let quantum = Self::calculate_quantum(priority.weight);
        Self {
            stream_id,
            state: StreamScheduleState::Idle,
            priority,
            pending_bytes: 0,
            quantum,
            deficit: 0,
        }
    }

    fn calculate_quantum(weight: u8) -> usize {
        let base = 16384;
        ((base * weight as usize) / 256).max(64)
    }

    fn update_quantum(&mut self) {
        self.quantum = Self::calculate_quantum(self.priority.weight);
    }
}

#[derive(Debug, Clone)]
struct DependencyNode {
    stream_id: u32,
    parent_id: u32,
    children: Vec<u32>,
    exclusive: bool,
}

impl DependencyNode {
    fn new(stream_id: u32, parent_id: u32, exclusive: bool) -> Self {
        Self {
            stream_id,
            parent_id,
            children: Vec::new(),
            exclusive,
        }
    }
}

pub struct PriorityScheduler {
    streams: HashMap<u32, ScheduleStream>, 
    dependencies: HashMap<u32, DependencyNode>,
    root_stream_id: u32,
    active_queue: VecDeque<u32>,
    blocked_streams: Vec<u32>,
    total_pending: usize,
}

impl PriorityScheduler {
    pub fn new() -> Self {
        let root_stream_id = 0;
        let mut dependencies = HashMap::new();
        dependencies.insert(
            root_stream_id,
            DependencyNode::new(root_stream_id, root_stream_id, false),
        );

        Self {
            streams: HashMap::new(),
            dependencies,
            root_stream_id,
            active_queue: VecDeque::new(),
            blocked_streams: Vec::new(),
            total_pending: 0,
        }
    }

    pub fn add_stream(&mut self, stream_id: u32, priority: Priority) {
        let parent_id = priority.stream_dependency;
        let exclusive = priority.exclusive;
        let stream = ScheduleStream::new(stream_id, priority);
        self.streams.insert(stream_id, stream);

        self.add_dependency(stream_id, parent_id, exclusive);
    }

    fn add_dependency(&mut self, stream_id: u32, parent_id: u32, exclusive: bool) {
        if parent_id != self.root_stream_id && !self.dependencies.contains_key(&parent_id) {
            self.add_dependency(stream_id, self.root_stream_id, false);
            return;
        }

        if exclusive {
            if let Some(parent_node) = self.dependencies.get_mut(&parent_id) {
                let old_children = parent_node.children.clone();
                parent_node.children.clear();
                parent_node.children.push(stream_id);
                
                let mut new_node = DependencyNode::new(stream_id, parent_id, true);
                new_node.children = old_children.clone();
                self.dependencies.insert(stream_id, new_node);
                
                for child_id in &old_children {
                    if let Some(child_node) = self.dependencies.get_mut(child_id) {
                        child_node.parent_id = stream_id;
                    }
                }
            }
        } else {
            if let Some(parent_node) = self.dependencies.get_mut(&parent_id) {
                parent_node.children.push(stream_id);
            }
            
            let new_node = DependencyNode::new(stream_id, parent_id, false);
            self.dependencies.insert(stream_id, new_node);
        }
    }

    pub fn remove_stream(&mut self, stream_id: u32) {
        if let Some(stream) = self.streams.remove(&stream_id) {
            self.total_pending = self.total_pending.saturating_sub(stream.pending_bytes);
        }
        
        self.remove_dependency(stream_id);
        
        self.active_queue.retain(|&id| id != stream_id);
        self.blocked_streams.retain(|&id| id != stream_id);
    }

    pub fn update_priority(&mut self, stream_id: u32, priority: Priority) {
        if let Some(stream) = self.streams.get_mut(&stream_id) {
            let old_parent = stream.priority.stream_dependency;
            let new_parent = priority.stream_dependency;
            let exclusive = priority.exclusive;
            
            stream.priority = priority;
            stream.update_quantum();
            if old_parent != new_parent {
                self.remove_dependency(stream_id);
                self.add_dependency(stream_id, new_parent, exclusive);
            }
        }
    }

    pub fn mark_ready(&mut self, stream_id: u32, pending_bytes: usize) {
        let should_insert = if let Some(stream) = self.streams.get_mut(&stream_id) {
            let needs_insert = stream.state != StreamScheduleState::Ready;
            if needs_insert {
                stream.state = StreamScheduleState::Ready;
            }
            
            self.total_pending = self.total_pending.saturating_sub(stream.pending_bytes);
            stream.pending_bytes = pending_bytes;
            self.total_pending += pending_bytes;
            needs_insert
        } else {
            false
        };
        
        if should_insert {
            self.blocked_streams.retain(|&id| id != stream_id);
            self.insert_into_active_queue(stream_id);
        }
    }

    pub fn mark_blocked(&mut self, stream_id: u32) {
        if let Some(stream) = self.streams.get_mut(&stream_id) {
            if stream.state == StreamScheduleState::Ready {
                stream.state = StreamScheduleState::Blocked;
                self.active_queue.retain(|&id| id != stream_id);
                self.blocked_streams.push(stream_id);
            }
        }
    }

    pub fn mark_closed(&mut self, stream_id: u32) {
        if let Some(stream) = self.streams.get_mut(&stream_id) {
            stream.state = StreamScheduleState::Closed;
            self.total_pending = self.total_pending.saturating_sub(stream.pending_bytes);
            stream.pending_bytes = 0;
        }
        
        self.active_queue.retain(|&id| id != stream_id);
        self.blocked_streams.retain(|&id| id != stream_id);
    }

    pub fn schedule_next(&mut self) -> Option<u32> {
        if self.active_queue.is_empty() {
            return None;
        }

        self.schedule_from_tree(self.root_stream_id)
    }

    fn schedule_from_tree(&mut self, parent_id: u32) -> Option<u32> {
        let children = if let Some(node) = self.dependencies.get(&parent_id) {
            node.children.clone()
        } else {
            return None;
        };

        if children.is_empty() {
            return None;
        }

        let mut weighted_children: Vec<(u32, usize, i64)> = Vec::new();
        for &child_id in &children {
            if let Some(stream) = self.streams.get(&child_id) {
                if stream.state == StreamScheduleState::Ready && stream.pending_bytes > 0 {
                    weighted_children.push((
                        child_id,
                        stream.quantum,
                        stream.deficit,
                    ));
                }
            }
        }

        if weighted_children.is_empty() {
            for &child_id in &children {
                if let Some(scheduled) = self.schedule_from_tree(child_id) {
                    return Some(scheduled);
                }
            }
            return None;
        }

        weighted_children.sort_by(|a, b| b.2.cmp(&a.2));
        let (selected_id, quantum, _) = weighted_children[0];
        if let Some(stream) = self.streams.get_mut(&selected_id) {
            stream.deficit -= quantum as i64;
        }

        for &child_id in &children {
            if let Some(stream) = self.streams.get_mut(&child_id) {
                if stream.state == StreamScheduleState::Ready {
                    stream.deficit += stream.quantum as i64;
                }
            }
        }

        Some(selected_id)
    }

    pub fn bytes_sent(&mut self, stream_id: u32, bytes: usize) {
        if let Some(stream) = self.streams.get_mut(&stream_id) {
            stream.pending_bytes = stream.pending_bytes.saturating_sub(bytes);
            self.total_pending = self.total_pending.saturating_sub(bytes);
            if stream.pending_bytes == 0 {
                stream.state = StreamScheduleState::Blocked;
                self.active_queue.retain(|&id| id != stream_id);
            }
        }
    }

    pub fn get_state(&self, stream_id: u32) -> Option<StreamScheduleState> {
        self.streams.get(&stream_id).map(|s| s.state)
    }

    pub fn get_priority(&self, stream_id: u32) -> Option<Priority> {
        self.streams.get(&stream_id).map(|s| s.priority.clone())
    }

    pub fn active_count(&self) -> usize {
        self.active_queue.len()
    }

    pub fn total_pending_bytes(&self) -> usize {
        self.total_pending
    }

    pub fn has_ready_streams(&self) -> bool {
        !self.active_queue.is_empty()
    }

    fn remove_dependency(&mut self, stream_id: u32) {
        if let Some(node) = self.dependencies.remove(&stream_id) {
            let parent_id = node.parent_id;
            let children = node.children;
            if let Some(parent_node) = self.dependencies.get_mut(&parent_id) {
                parent_node.children.retain(|&id| id != stream_id);
                parent_node.children.extend(children.iter());
            }
            
            for &child_id in &children {
                if let Some(child_node) = self.dependencies.get_mut(&child_id) {
                    child_node.parent_id = parent_id;
                }
            }
        }
    }

    fn insert_into_active_queue(&mut self, stream_id: u32) {
        if !self.active_queue.contains(&stream_id) {
            self.active_queue.push_back(stream_id);
        }
    }

    pub fn get_tree_stats(&self) -> DependencyTreeStats {
        DependencyTreeStats {
            total_streams: self.streams.len(),
            active_streams: self.active_queue.len(),
            blocked_streams: self.blocked_streams.len(),
            tree_depth: self.calculate_tree_depth(self.root_stream_id, 0),
            total_pending_bytes: self.total_pending,
        }
    }

    fn calculate_tree_depth(&self, node_id: u32, current_depth: usize) -> usize {
        if let Some(node) = self.dependencies.get(&node_id) {
            if node.children.is_empty() {
                return current_depth;
            }
            
            node.children
                .iter()
                .map(|&child_id| self.calculate_tree_depth(child_id, current_depth + 1))
                .max()
                .unwrap_or(current_depth)
        } else {
            current_depth
        }
    }
}

impl Default for PriorityScheduler {
    fn default() -> Self {
        Self::new()
    }
}

#[derive(Debug, Clone, Copy)]
pub struct DependencyTreeStats {
    pub total_streams: usize,
    pub active_streams: usize,
    pub blocked_streams: usize,
    pub tree_depth: usize,
    pub total_pending_bytes: usize,
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_scheduler_creation() {
        let scheduler = PriorityScheduler::new();
        assert_eq!(scheduler.active_count(), 0);
        assert_eq!(scheduler.total_pending_bytes(), 0);
    }

    #[test]
    fn test_add_stream() {
        let mut scheduler = PriorityScheduler::new();
        let priority = Priority::new(0, 16, false);
        
        scheduler.add_stream(1, priority);
        assert!(scheduler.streams.contains_key(&1));
    }

    #[test]
    fn test_mark_ready() {
        let mut scheduler = PriorityScheduler::new();
        let priority = Priority::new(0, 16, false);
        
        scheduler.add_stream(1, priority);
        scheduler.mark_ready(1, 1000);
        
        assert_eq!(scheduler.get_state(1), Some(StreamScheduleState::Ready));
        assert_eq!(scheduler.total_pending_bytes(), 1000);
    }

    #[test]
    fn test_schedule_single_stream() {
        let mut scheduler = PriorityScheduler::new();
        let priority = Priority::new(0, 16, false);
        
        scheduler.add_stream(1, priority);
        scheduler.mark_ready(1, 1000);
        
        let next = scheduler.schedule_next();
        assert_eq!(next, Some(1));
    }

    #[test]
    fn test_schedule_multiple_streams_by_weight() {
        let mut scheduler = PriorityScheduler::new();
        
        scheduler.add_stream(1, Priority::new(0, 255, false));
        scheduler.mark_ready(1, 1000);
        
        scheduler.add_stream(3, Priority::new(0, 1, false));
        scheduler.mark_ready(3, 1000);
        
        let mut stream1_count = 0;
        let mut stream3_count = 0;
        
        for _ in 0..10 {
            if let Some(stream_id) = scheduler.schedule_next() {
                if stream_id == 1 {
                    stream1_count += 1;
                } else if stream_id == 3 {
                    stream3_count += 1;
                }
                
                scheduler.mark_ready(stream_id, 1000);
            }
        }
        
        assert!(stream1_count > stream3_count);
    }

    #[test]
    fn test_dependency_exclusive() {
        let mut scheduler = PriorityScheduler::new();
        
        scheduler.add_stream(1, Priority::new(0, 16, false));
        scheduler.add_stream(3, Priority::new(1, 16, true));
        scheduler.add_stream(5, Priority::new(1, 16, false));
        
        let node3 = scheduler.dependencies.get(&3).unwrap();
        assert_eq!(node3.parent_id, 1);
        assert!(node3.children.contains(&5));
        
        let node5 = scheduler.dependencies.get(&5).unwrap();
        assert_eq!(node5.parent_id, 3);
    }

    #[test]
    fn test_remove_stream_reparents_children() {
        let mut scheduler = PriorityScheduler::new();
        
        scheduler.add_stream(1, Priority::new(0, 16, false));
        scheduler.add_stream(3, Priority::new(1, 16, false));
        scheduler.add_stream(5, Priority::new(3, 16, false));
        
        scheduler.remove_stream(3);
        
        let node5 = scheduler.dependencies.get(&5).unwrap();
        assert_eq!(node5.parent_id, 1);
    }

    #[test]
    fn test_bytes_sent() {
        let mut scheduler = PriorityScheduler::new();
        scheduler.add_stream(1, Priority::new(0, 16, false));
        scheduler.mark_ready(1, 1000);
        
        scheduler.bytes_sent(1, 300);
        
        assert_eq!(scheduler.total_pending_bytes(), 700);
    }

    #[test]
    fn test_tree_stats() {
        let mut scheduler = PriorityScheduler::new();
        
        scheduler.add_stream(1, Priority::new(0, 16, false));
        scheduler.add_stream(3, Priority::new(1, 16, false));
        scheduler.add_stream(5, Priority::new(3, 16, false));
        
        scheduler.mark_ready(1, 1000);
        scheduler.mark_ready(3, 2000);
        
        let stats = scheduler.get_tree_stats();
        assert_eq!(stats.total_streams, 3);
        assert_eq!(stats.active_streams, 2);
        assert_eq!(stats.tree_depth, 3);
        assert_eq!(stats.total_pending_bytes, 3000);
    }
}