use either::Either;
use memmap::MmapMut;
use parking_lot::Mutex;

use super::seed_compute::SeedHashCompute;
use super::shared::{ETHASH_CACHE_ROUNDS, NODE_BYTES, Node, epoch, get_cache_size, to_hex};
use super::compute::Light;
use super::keccak::{H256, keccak_512};

use std::borrow::Cow;
use std::fs;
use std::io::{self, Read, Write};
use std::path::{Path, PathBuf};
use std::slice;
use std::sync::Arc;

type Cache = Either<Vec<Node>, MmapMut>;

fn byte_size(cache: &Cache) -> usize {
	use self::Either::{Left, Right};

	match *cache {
		Left(ref vec) => vec.len() * NODE_BYTES,
		Right(ref mmap) => mmap.len(),
	}
}

fn new_buffer(path: &Path, num_nodes: usize, ident: &H256) -> Cache {
	let memmap = None;

	memmap.map(Either::Right).unwrap_or_else(|| {
		Either::Left(make_memory_cache(num_nodes, ident))
	})
}

#[derive(Clone)]
pub struct NodeCacheBuilder {
	seedhash: Arc<Mutex<SeedHashCompute>>,
}

pub struct NodeCache {
	builder: NodeCacheBuilder,
	cache_dir: Cow<'static, Path>,
	cache_path: PathBuf,
	epoch: u64,
	cache: Cache,
}

impl NodeCacheBuilder {
    pub fn light(&self, cache_dir: &Path, block_height: u64) -> Light {
        Light::new_with_builder(self, cache_dir, block_height)
    }

	pub fn new() -> Self {
		NodeCacheBuilder {
			seedhash: Arc::new(Mutex::new(SeedHashCompute::default())),
		}
	}

	fn block_height_to_ident(&self, block_height: u64) -> H256 {
		self.seedhash.lock().hash_block_height(block_height)
	}

	fn epoch_to_ident(&self, epoch: u64) -> H256 {
		self.seedhash.lock().hash_epoch(epoch)
	}

	pub fn from_file<P: Into<Cow<'static, Path>>>(
		&self,
		cache_dir: P,
		block_height: u64,
	) -> io::Result<NodeCache> {
		let cache_dir = cache_dir.into();
		let ident = self.block_height_to_ident(block_height);

		let path = cache_path(cache_dir.as_ref(), &ident);

		let cache = cache_from_path(&path)?;
		let expected_cache_size = get_cache_size(block_height);

		if byte_size(&cache) == expected_cache_size {
			Ok(NodeCache {
				builder: self.clone(),
				epoch: epoch(block_height),
				cache_dir: cache_dir,
				cache_path: path,
				cache: cache,
			})
		} else {
			Err(io::Error::new(
				io::ErrorKind::InvalidData,
				"Node cache is of incorrect size",
			))
		}
	}

	pub fn new_cache<P: Into<Cow<'static, Path>>>(
		&self,
		cache_dir: P,
		block_height: u64,
	) -> NodeCache {
		let cache_dir = cache_dir.into();
		let ident = self.block_height_to_ident(block_height);

		let cache_size = get_cache_size(block_height);

		// We use `debug_assert` since it is impossible for `get_cache_size` to return an unaligned
		// value with the current implementation. If the implementation changes, CI will catch it.
		debug_assert!(cache_size % NODE_BYTES == 0, "Unaligned cache size");
		let num_nodes = cache_size / NODE_BYTES;

		let path = cache_path(cache_dir.as_ref(), &ident);
		let nodes = new_buffer(&path, num_nodes, &ident);

		NodeCache {
			builder: self.clone(),
			epoch: epoch(block_height),
			cache_dir: cache_dir.into(),
			cache_path: path,
			cache: nodes,
		}
	}
}

impl NodeCache {
	pub fn cache_path(&self) -> &Path {
		&self.cache_path
	}

	pub fn flush(&mut self) -> io::Result<()> {
		if let Some(last) = self.epoch.checked_sub(2).map(|ep| {
			cache_path(self.cache_dir.as_ref(), &self.builder.epoch_to_ident(ep))
		})
		{
			fs::remove_file(last).unwrap_or_else(|error| match error.kind() {
				io::ErrorKind::NotFound => (),
				_ => warn!("Error removing stale DAG cache: {:?}", error),
			});
		}

		consume_cache(&mut self.cache, &self.cache_path)
	}
}

fn make_memmapped_cache(path: &Path, num_nodes: usize, ident: &H256) -> io::Result<MmapMut> {
	use std::fs::OpenOptions;

	let file = OpenOptions::new()
		.read(true)
		.write(true)
		.create(true)
		.open(&path)?;
	file.set_len((num_nodes * NODE_BYTES) as _)?;

	let mut memmap = unsafe { MmapMut::map_mut(&file)? };

	unsafe { initialize_memory(memmap.as_mut_ptr() as *mut Node, num_nodes, ident) };

	Ok(memmap)
}

fn make_memory_cache(num_nodes: usize, ident: &H256) -> Vec<Node> {
	let mut nodes: Vec<Node> = Vec::with_capacity(num_nodes);
	// Use uninit instead of unnecessarily writing `size_of::<Node>() * num_nodes` 0s
	unsafe {
		initialize_memory(nodes.as_mut_ptr(), num_nodes, ident);
		nodes.set_len(num_nodes);
	}

	nodes
}

fn cache_path<'a, P: Into<Cow<'a, Path>>>(path: P, ident: &H256) -> PathBuf {
	let mut buf = path.into().into_owned();
	buf.push(to_hex(ident));
	buf
}

fn consume_cache(cache: &mut Cache, path: &Path) -> io::Result<()> {
	use std::fs::OpenOptions;

	match *cache {
		Either::Left(ref mut vec) => {
			let mut file = OpenOptions::new()
				.read(true)
				.write(true)
				.create(true)
				.open(&path)?;

			let buf = unsafe {
				slice::from_raw_parts_mut(vec.as_mut_ptr() as *mut u8, vec.len() * NODE_BYTES)
			};

			file.write_all(buf).map(|_| ())
		}
		Either::Right(ref mmap) => {
			mmap.flush()
		}
	}
}

fn cache_from_path(path: &Path) -> io::Result<Cache> {
	let memmap = None;

	memmap.map(Either::Right).ok_or(()).or_else(|_| {
		read_from_path(path).map(Either::Left)
	})
}

fn read_from_path(path: &Path) -> io::Result<Vec<Node>> {
	use std::fs::File;
	use std::mem;

	let mut file = File::open(path)?;

	let mut nodes: Vec<u8> = Vec::with_capacity(file.metadata().map(|m| m.len() as _).unwrap_or(
		NODE_BYTES * 1_000_000,
	));
	file.read_to_end(&mut nodes)?;

	nodes.shrink_to_fit();

	if nodes.len() % NODE_BYTES != 0 || nodes.capacity() % NODE_BYTES != 0 {
		return Err(io::Error::new(
			io::ErrorKind::Other,
			"Node cache is not a multiple of node size",
		));
	}

	let out: Vec<Node> = unsafe {
		Vec::from_raw_parts(
			nodes.as_mut_ptr() as *mut _,
			nodes.len() / NODE_BYTES,
			nodes.capacity() / NODE_BYTES,
		)
	};

	mem::forget(nodes);

	Ok(out)
}

impl AsRef<[Node]> for NodeCache {
	fn as_ref(&self) -> &[Node] {
		match self.cache {
			Either::Left(ref vec) => vec,
			Either::Right(ref mmap) => unsafe {
				let bytes = mmap.as_ptr();
				// This isn't a safety issue, so we can keep this a debug lint. We don't care about
				// people manually messing with the files unless it can cause unsafety, but if we're
				// generating incorrect files then we want to catch that in CI.
				debug_assert_eq!(mmap.len() % NODE_BYTES, 0);
				slice::from_raw_parts(bytes as _, mmap.len() / NODE_BYTES)
			},
		}
	}
}

// This takes a raw pointer and a counter because `memory` may be uninitialized. `memory` _must_ be
// a pointer to the beginning of an allocated but possibly-uninitialized block of
// `num_nodes * NODE_BYTES` bytes
//
// We have to use raw pointers to read/write uninit, using "normal" indexing causes LLVM to freak
// out. It counts as a read and causes all writes afterwards to be elided. Yes, really. I know, I
// want to refactor this to use less `unsafe` as much as the next rustacean.
unsafe fn initialize_memory(memory: *mut Node, num_nodes: usize, ident: &H256) {
	// We use raw pointers here, see above
	let dst = slice::from_raw_parts_mut(memory as *mut u8, NODE_BYTES);

	debug_assert_eq!(ident.len(), 32);
	keccak_512::write(&ident[..], dst);

	for i in 1..num_nodes {
		// We use raw pointers here, see above
		let dst = slice::from_raw_parts_mut(
			memory.offset(i as _) as *mut u8,
			NODE_BYTES,
		);
		let src = slice::from_raw_parts(
			memory.offset(i as isize - 1) as *mut u8,
			NODE_BYTES,
		);
		keccak_512::write(src, dst);
	}

	// Now this is initialized, we can treat it as a slice.
	let nodes: &mut [Node] = slice::from_raw_parts_mut(memory, num_nodes);

	for _ in 0..ETHASH_CACHE_ROUNDS {
		for i in 0..num_nodes {
			let data_idx = (num_nodes - 1 + i) % num_nodes;
			let idx = nodes.get_unchecked_mut(i).as_words()[0] as usize % num_nodes;

			let data = {
				let mut data: Node = nodes.get_unchecked(data_idx).clone();
				let rhs: &Node = nodes.get_unchecked(idx);

				for (a, b) in data.as_dwords_mut().iter_mut().zip(rhs.as_dwords()) {
					*a ^= *b;
				}

				data
			};

			keccak_512::write(&data.bytes, &mut nodes.get_unchecked_mut(i).bytes);
		}
	}
}
