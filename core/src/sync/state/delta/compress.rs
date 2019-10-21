// Copyright 2019 Conflux Foundation. All rights reserved.
// Conflux is free software and distributed under GNU General Public License.
// See http://www.gnu.org/licenses/

use std::{
    fs::File,
    io::{Error as IoError, Read, Write},
    path::Path,
};
use zip::{write::FileOptions, ZipArchive, ZipWriter};

pub fn write_single_zip_file(
    path: &Path, content: &[u8],
) -> Result<(), IoError> {
    let file = File::create(path)?;
    let mut zip = ZipWriter::new(file);
    zip.start_file("0", FileOptions::default())?;
    zip.write_all(content)?;
    zip.finish()?;
    Ok(())
}

pub fn read_single_zip_file(path: &Path) -> Result<Vec<u8>, IoError> {
    let file = File::open(path)?;
    let mut zip = ZipArchive::new(file)?;
    let mut zip_file = zip.by_index(0)?;
    let mut content = Vec::new();
    zip_file.read_to_end(&mut content)?;
    Ok(content)
}
