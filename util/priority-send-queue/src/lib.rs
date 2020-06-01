// Copyright 2019 Conflux Foundation. All rights reserved.
// Conflux is free software and distributed under GNU General Public License.
// See http://www.gnu.org/licenses/

use std::collections::VecDeque;

#[derive(Debug, Clone, Copy, Ord, PartialOrd, Eq, PartialEq)]
pub enum SendQueuePriority {
    High = 0,
    Normal = 1,
    Low = 2,
}

pub struct PrioritySendQueue<T> {
    queues: Vec<VecDeque<T>>,
}

impl<T> Default for PrioritySendQueue<T> {
    fn default() -> PrioritySendQueue<T> {
        let mut queues = Vec::new();
        queues.push(VecDeque::new()); // High
        queues.push(VecDeque::new()); // Normal
        queues.push(VecDeque::new()); // Low
        PrioritySendQueue { queues }
    }
}

impl<T> PrioritySendQueue<T> {
    fn queue(&self, priority: SendQueuePriority) -> &VecDeque<T> {
        &self.queues[priority as usize]
    }

    fn queue_mut(&mut self, priority: SendQueuePriority) -> &mut VecDeque<T> {
        &mut self.queues[priority as usize]
    }

    pub fn pop_front(&mut self) -> Option<(T, SendQueuePriority)> {
        if let Some(data) = self.queue_mut(SendQueuePriority::High).pop_front()
        {
            return Some((data, SendQueuePriority::High));
        }

        if let Some(data) =
            self.queue_mut(SendQueuePriority::Normal).pop_front()
        {
            return Some((data, SendQueuePriority::Normal));
        }

        if let Some(data) = self.queue_mut(SendQueuePriority::Low).pop_front() {
            return Some((data, SendQueuePriority::Low));
        }

        None
    }

    pub fn is_empty(&self) -> bool {
        self.queue(SendQueuePriority::High).is_empty()
            && self.queue(SendQueuePriority::Normal).is_empty()
            && self.queue(SendQueuePriority::Low).is_empty()
    }

    pub fn is_send_queue_empty(&self, priority: SendQueuePriority) -> bool {
        self.queue(priority).is_empty()
    }

    pub fn push_back(&mut self, value: T, priority: SendQueuePriority) {
        self.queue_mut(priority).push_back(value);
    }

    pub fn len(&self) -> usize {
        self.queue(SendQueuePriority::High).len()
            + self.queue(SendQueuePriority::Normal).len()
            + self.queue(SendQueuePriority::Low).len()
    }

    pub fn len_by_priority(&self, priority: SendQueuePriority) -> usize {
        self.queue(priority).len()
    }
}
