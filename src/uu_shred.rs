// Adapted from `src/uu/shred/src/shred.rs` in uutils/coreutils.
// Upstream: https://github.com/uutils/coreutils/blob/7d73dd5bd2f01b7499aeeb16e3bc683e3beaab50/src/uu/shred/src/shred.rs
// Upstream package: uu_shred 0.13.0; source revision: 7d73dd5bd2f01b7499aeeb16e3bc683e3beaab50.
// Copyright (c) uutils developers. Licensed under the MIT License; see
// LICENSES/MIT-uutils-coreutils.txt. Adaptations remove the uutils CLI and
// uucore integration, expose a regular-file operation, and retain the
// overwrite, rename, truncate, and unlink sequence used by git-veil.

use rand::rngs::StdRng;
use rand::seq::SliceRandom;
use rand::{RngCore, SeedableRng};
use std::fs::{self, File, OpenOptions};
use std::io::{self, Seek, SeekFrom, Write};
use std::path::{Path, PathBuf};

// Keep these values aligned with uutils/coreutils' shred implementation.
const BLOCK_SIZE: usize = 1 << 16;
const NAME_CHARSET: &[u8] = b"0123456789abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ_.";
const PATTERN_LENGTH: usize = 3;
const PATTERN_BUFFER_SIZE: usize = BLOCK_SIZE + PATTERN_LENGTH - 1;
const OPTIMAL_IO_BLOCK_SIZE: usize = 1 << 12;

const PATTERNS: [Pattern; 22] = [
    Pattern::Single(b'\x00'),
    Pattern::Single(b'\xFF'),
    Pattern::Single(b'\x55'),
    Pattern::Single(b'\xAA'),
    Pattern::Multi(*b"\x24\x92\x49"),
    Pattern::Multi(*b"\x49\x24\x92"),
    Pattern::Multi(*b"\x6D\xB6\xDB"),
    Pattern::Multi(*b"\x92\x49\x24"),
    Pattern::Multi(*b"\xB6\xDB\x6D"),
    Pattern::Multi(*b"\xDB\x6D\xB6"),
    Pattern::Single(b'\x11'),
    Pattern::Single(b'\x22'),
    Pattern::Single(b'\x33'),
    Pattern::Single(b'\x44'),
    Pattern::Single(b'\x66'),
    Pattern::Single(b'\x77'),
    Pattern::Single(b'\x88'),
    Pattern::Single(b'\x99'),
    Pattern::Single(b'\xBB'),
    Pattern::Single(b'\xCC'),
    Pattern::Single(b'\xDD'),
    Pattern::Single(b'\xEE'),
];

#[derive(Clone, Copy)]
enum Pattern {
    Single(u8),
    Multi([u8; 3]),
}

#[derive(Clone)]
enum PassType {
    Pattern(Pattern),
    Random,
}

struct FilenameIter {
    indices: Vec<usize>,
    exhausted: bool,
}

impl FilenameIter {
    fn new(length: usize) -> Self {
        Self {
            indices: vec![0; length],
            exhausted: false,
        }
    }
}

impl Iterator for FilenameIter {
    type Item = String;

    fn next(&mut self) -> Option<Self::Item> {
        if self.exhausted {
            return None;
        }
        let name = self
            .indices
            .iter()
            .map(|index| char::from(NAME_CHARSET[*index]))
            .collect();
        for index in self.indices.iter_mut().rev() {
            if *index == NAME_CHARSET.len() - 1 {
                *index = 0;
            } else {
                *index += 1;
                return Some(name);
            }
        }
        self.exhausted = true;
        Some(name)
    }
}

#[allow(clippy::large_enum_variant)]
enum BytesWriter {
    Random {
        rng: StdRng,
        buffer: [u8; BLOCK_SIZE],
    },
    Pattern {
        offset: usize,
        buffer: [u8; PATTERN_BUFFER_SIZE],
    },
}

impl BytesWriter {
    fn from_pass_type(pass: &PassType) -> Self {
        match pass {
            PassType::Random => Self::Random {
                rng: StdRng::from_entropy(),
                buffer: [0; BLOCK_SIZE],
            },
            PassType::Pattern(pattern) => {
                let mut buffer = [0; PATTERN_BUFFER_SIZE];
                match pattern {
                    Pattern::Single(byte) => buffer.fill(*byte),
                    Pattern::Multi(bytes) => {
                        for (index, byte) in buffer.iter_mut().enumerate() {
                            *byte = bytes[index % PATTERN_LENGTH];
                        }
                    }
                }
                Self::Pattern { offset: 0, buffer }
            }
        }
    }

    fn bytes_for_pass(&mut self, size: usize) -> &[u8] {
        match self {
            Self::Random { rng, buffer } => {
                rng.fill_bytes(&mut buffer[..size]);
                &buffer[..size]
            }
            Self::Pattern { offset, buffer } => {
                let bytes = &buffer[*offset..size + *offset];
                *offset = (*offset + size) % PATTERN_LENGTH;
                bytes
            }
        }
    }
}

/// Best-effort overwrite and removal for a regular file.
///
/// As with the upstream implementation, this makes repeated writes to the
/// filesystem and then truncates, renames, and unlinks the file. It cannot
/// guarantee physical erasure on SSDs, copy-on-write filesystems, snapshots,
/// or storage with wear levelling.
pub(crate) fn shred_file(path: &Path) -> io::Result<()> {
    let path_metadata = fs::symlink_metadata(path)?;
    if !path_metadata.file_type().is_file() {
        return Err(io::Error::new(
            io::ErrorKind::InvalidInput,
            "refusing to shred a non-regular file",
        ));
    }

    let mut options = OpenOptions::new();
    options.write(true);
    #[cfg(unix)]
    {
        use std::os::unix::fs::OpenOptionsExt;
        options.custom_flags(libc::O_NOFOLLOW);
    }
    let mut file = options.open(path)?;
    let opened_metadata = file.metadata()?;
    if !opened_metadata.is_file() || !same_file(&opened_metadata, &path_metadata) {
        return Err(io::Error::new(
            io::ErrorKind::InvalidInput,
            "file changed while preparing to shred",
        ));
    }

    overwrite_contents(&mut file, opened_metadata.len())?;
    file.set_len(0)?;
    file.sync_all()?;
    drop(file);

    let current_metadata = fs::symlink_metadata(path)?;
    if !current_metadata.file_type().is_file() || !same_file(&current_metadata, &path_metadata) {
        return Err(io::Error::new(
            io::ErrorKind::InvalidInput,
            "file changed before it could be removed after shredding",
        ));
    }

    remove_file(path)
}

#[cfg(unix)]
fn same_file(left: &fs::Metadata, right: &fs::Metadata) -> bool {
    use std::os::unix::fs::MetadataExt;
    left.dev() == right.dev() && left.ino() == right.ino()
}

#[cfg(not(unix))]
fn same_file(left: &fs::Metadata, right: &fs::Metadata) -> bool {
    left.file_type().is_file() && right.file_type().is_file()
}

fn overwrite_contents(file: &mut File, file_size: u64) -> io::Result<()> {
    let passes = create_standard_pass_sequence(3);
    for pass in passes {
        do_pass(file, &pass, file_size)?;
    }
    Ok(())
}

fn create_standard_pass_sequence(num_passes: usize) -> Vec<PassType> {
    if num_passes == 0 {
        return Vec::new();
    }
    if num_passes <= 3 {
        return vec![PassType::Random; num_passes];
    }

    let mut sequence = vec![PassType::Random];
    let n_random = (num_passes / 10).max(3);
    let n_pattern = num_passes - n_random;
    for _ in 0..n_pattern / PATTERNS.len() {
        sequence.extend(PATTERNS.into_iter().map(PassType::Pattern));
    }
    sequence.extend(
        PATTERNS
            .into_iter()
            .take(n_pattern % PATTERNS.len())
            .map(PassType::Pattern),
    );
    sequence.extend((0..n_random - 2).map(|_| PassType::Random));
    let mut rng = StdRng::from_entropy();
    sequence[1..].shuffle(&mut rng);
    sequence.push(PassType::Random);
    sequence
}

fn split_on_blocks(file_size: u64) -> (u64, u64) {
    const _: () = assert!(OPTIMAL_IO_BLOCK_SIZE <= BLOCK_SIZE);
    let aligned_size =
        file_size.div_ceil(OPTIMAL_IO_BLOCK_SIZE as u64) * OPTIMAL_IO_BLOCK_SIZE as u64;
    (
        aligned_size / BLOCK_SIZE as u64,
        aligned_size % BLOCK_SIZE as u64,
    )
}

fn do_pass(file: &mut File, pass_type: &PassType, file_size: u64) -> io::Result<()> {
    file.seek(SeekFrom::Start(0))?;
    let mut writer = BytesWriter::from_pass_type(pass_type);
    let (number_of_blocks, bytes_left) = split_on_blocks(file_size);
    for _ in 0..number_of_blocks {
        file.write_all(writer.bytes_for_pass(BLOCK_SIZE))?;
    }
    file.write_all(writer.bytes_for_pass(bytes_left as usize))?;
    file.sync_data()
}

fn remove_file(path: &Path) -> io::Result<()> {
    let remove_path = wipe_name(path)?;
    fs::remove_file(remove_path)
}

fn wipe_name(orig_path: &Path) -> io::Result<PathBuf> {
    let file_name_len = orig_path.file_name().unwrap_or_default().len();
    let mut last_path = PathBuf::from(orig_path);
    for length in (1..=file_name_len).rev() {
        for name in FilenameIter::new(length) {
            let new_path = orig_path.with_file_name(name);
            if new_path.exists() {
                continue;
            }
            match fs::rename(&last_path, &new_path) {
                Ok(()) => {
                    last_path = new_path;
                    break;
                }
                Err(_) => return Ok(last_path),
            }
        }
    }
    Ok(last_path)
}

#[cfg(test)]
mod tests {
    use super::{overwrite_contents, shred_file};
    use std::fs::{self, File};
    use std::io::{Read, Seek, SeekFrom};

    #[test]
    fn overwrite_changes_plaintext_before_removal() {
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("plain");
        let original = b"this plaintext must be overwritten";
        fs::write(&path, original).unwrap();

        let mut file = File::options().read(true).write(true).open(&path).unwrap();
        overwrite_contents(&mut file, original.len() as u64).unwrap();
        file.seek(SeekFrom::Start(0)).unwrap();
        let mut overwritten = vec![0; original.len()];
        file.read_exact(&mut overwritten).unwrap();
        assert_ne!(overwritten.as_slice(), original);
        drop(file);

        shred_file(&path).unwrap();
        assert!(!path.exists());
    }

    #[cfg(unix)]
    #[test]
    fn failed_unlink_reports_error_and_leaves_the_shredded_path() {
        use std::os::unix::fs::PermissionsExt;

        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("plain");
        fs::write(&path, b"plaintext").unwrap();
        let mut permissions = fs::metadata(dir.path()).unwrap().permissions();
        permissions.set_mode(0o500);
        fs::set_permissions(dir.path(), permissions).unwrap();

        let result = shred_file(&path);
        let mut permissions = fs::metadata(dir.path()).unwrap().permissions();
        permissions.set_mode(0o700);
        fs::set_permissions(dir.path(), permissions).unwrap();

        assert!(result.is_err());
        assert!(path.exists());
        assert_eq!(fs::metadata(path).unwrap().len(), 0);
    }

    #[test]
    fn refuses_non_regular_paths_without_removing_them() {
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("directory");
        fs::create_dir(&path).unwrap();

        assert!(shred_file(&path).is_err());
        assert!(path.is_dir());
    }
}
