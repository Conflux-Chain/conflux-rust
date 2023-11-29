#[derive(Default)]
pub struct CheckpointLog<T> {
    data: Vec<T>,
    checkpoints: Vec<usize>,
}

impl<T> CheckpointLog<T> {
    pub fn push(&mut self, item: T) { self.data.push(item); }

    pub fn checkpoint(&mut self) { self.checkpoints.push(self.data.len()); }

    pub fn revert_checkpoint(&mut self) {
        let start = self.checkpoints.pop().unwrap();
        self.data.truncate(start);
    }

    pub fn discard_checkpoint(&mut self) { self.checkpoints.pop().unwrap(); }

    pub fn drain(self) -> Vec<T> { self.data }
}
