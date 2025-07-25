mod config;
mod execution;

pub use config::*;
pub use execution::*;

use std::path::{Path, PathBuf};
use walkdir::{DirEntry, WalkDir};

#[macro_export]
macro_rules! bail {
    ($e:expr) => {
        return Err($e.into())
    };
}

pub(crate) fn find_all_json_tests(path: &Path) -> Vec<PathBuf> {
    if path.is_file() {
        vec![path.to_path_buf()]
    } else {
        WalkDir::new(path)
            .follow_links(true)
            .into_iter()
            .filter_map(Result::ok)
            .filter(|e| e.path().extension() == Some("json".as_ref()))
            .map(DirEntry::into_path)
            .collect()
    }
}

/// Check if the path matches `.meta/**`.
pub fn contains_meta_dir(path: &Path) -> bool {
    path.iter()
        .any(|c| c.to_str().map_or(false, |s| s == ".meta"))
}

#[allow(unused)]
pub(crate) fn allowed_test(path: &Path, matches: Option<&str>) -> bool {
    if matches.is_none() {
        return true;
    }

    let name = path.file_name().unwrap().to_str().unwrap();

    if name == matches.unwrap() {
        return true;
    }

    false
}
