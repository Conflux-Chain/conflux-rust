// Copyright 2019 Conflux Foundation. All rights reserved.
// Conflux is free software and distributed under GNU General Public License.
// See http://www.gnu.org/licenses/

use std::collections::VecDeque;

#[derive(Debug, Clone, Copy, Ord, PartialOrd, Eq, PartialEq)]
pub enum SendQueuePriority {
    High = 0,
    Normal = 1,
}

pub struct PrioritySendQueue<T> {
    queues: Vec<VecDeque<T>>,
}

impl<T> PrioritySendQueue<T> {
    pub fn new() -> PrioritySendQueue<T> {
        let mut queues = Vec::new();
        queues.push(VecDeque::new());
        queues.push(VecDeque::new());
        PrioritySendQueue { queues }
    }

    pub fn pop_front(&mut self) -> Option<T> {
        let res = self.queues[SendQueuePriority::High as usize].pop_front();
        if res.is_some() {
            return res;
        }

        self.queues[SendQueuePriority::Normal as usize].pop_front()
    }

    pub fn front_mut(&mut self) -> Option<&mut T> {
        if self.queues[SendQueuePriority::High as usize].is_empty() {
            let res =
                self.queues[SendQueuePriority::Normal as usize].pop_front();
            if res.is_none() {
                return None;
            }

            let res = res.unwrap();
            self.queues[SendQueuePriority::High as usize].push_back(res);
        }

        self.queues[SendQueuePriority::High as usize].front_mut()
    }

    pub fn is_empty(&self) -> bool {
        self.queues[SendQueuePriority::High as usize].is_empty()
            && self.queues[SendQueuePriority::Normal as usize].is_empty()
    }

    pub fn push_back(&mut self, value: T, priority: SendQueuePriority) {
        self.queues[priority as usize].push_back(value);
    }

    pub fn len(&self) -> usize {
        self.queues[SendQueuePriority::High as usize].len()
            + self.queues[SendQueuePriority::Normal as usize].len()
    }
}
