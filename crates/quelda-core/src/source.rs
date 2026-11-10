//! Random-access input (plan Step 16 Phase B): the engine reads only the
//! bytes it needs — one sequential pass in blocks, then the regions it
//! must parse or decode — instead of holding the whole file in memory.
//!
//! [`crate::scan`] takes a slice (zero-copy, as before);
//! [`crate::scan_source`] takes any [`Source`]: a file ([`FileSource`],
//! native), a JS `Blob` (WASM binding), or a slice too.

/// A file the engine can read anywhere, any number of times. Must return the
/// same bytes for the same offsets during a scan.
pub trait Source {
    /// Total length in bytes.
    fn len(&self) -> u64;

    /// `true` for an empty source.
    fn is_empty(&self) -> bool {
        self.len() == 0
    }

    /// Fills `buf` with the bytes at `offset..offset + buf.len()` (always
    /// within [`Source::len`]). Anything short of that is an error, which
    /// makes the verdict `ERROR` (`ENGINE.READ`).
    fn read_at(&self, offset: u64, buf: &mut [u8]) -> Result<(), ReadError>;
}

/// Why a [`Source`] could not be read.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct ReadError(pub String);

impl std::fmt::Display for ReadError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.write_str(&self.0)
    }
}

impl Source for [u8] {
    fn len(&self) -> u64 {
        <[u8]>::len(self) as u64
    }

    fn read_at(&self, offset: u64, buf: &mut [u8]) -> Result<(), ReadError> {
        let src = usize::try_from(offset)
            .ok()
            .and_then(|o| self.get(o..o.checked_add(buf.len())?))
            .ok_or_else(|| ReadError("read past the end of the input".to_string()))?;
        buf.copy_from_slice(src);
        Ok(())
    }
}

impl Source for &[u8] {
    fn len(&self) -> u64 {
        Source::len(*self)
    }

    fn read_at(&self, offset: u64, buf: &mut [u8]) -> Result<(), ReadError> {
        (**self).read_at(offset, buf)
    }
}

impl Source for Vec<u8> {
    fn len(&self) -> u64 {
        Source::len(self.as_slice())
    }

    fn read_at(&self, offset: u64, buf: &mut [u8]) -> Result<(), ReadError> {
        self.as_slice().read_at(offset, buf)
    }
}

/// A file read with positioned reads (`pread`): no `mmap` (it needs
/// `unsafe`), nothing loaded up front.
#[cfg(any(unix, windows))]
pub struct FileSource {
    file: std::fs::File,
    len: u64,
}

#[cfg(any(unix, windows))]
impl FileSource {
    pub fn open(path: impl AsRef<std::path::Path>) -> std::io::Result<FileSource> {
        let file = std::fs::File::open(path)?;
        let len = file.metadata()?.len();
        Ok(FileSource { file, len })
    }
}

#[cfg(any(unix, windows))]
impl Source for FileSource {
    fn len(&self) -> u64 {
        self.len
    }

    fn read_at(&self, offset: u64, buf: &mut [u8]) -> Result<(), ReadError> {
        read_exact_at(&self.file, offset, buf).map_err(|e| ReadError(e.to_string()))
    }
}

#[cfg(unix)]
fn read_exact_at(file: &std::fs::File, offset: u64, buf: &mut [u8]) -> std::io::Result<()> {
    std::os::unix::fs::FileExt::read_exact_at(file, buf, offset)
}

#[cfg(windows)]
fn read_exact_at(file: &std::fs::File, mut offset: u64, mut buf: &mut [u8]) -> std::io::Result<()> {
    use std::os::windows::fs::FileExt;
    while !buf.is_empty() {
        match file.seek_read(buf, offset) {
            Ok(0) => return Err(std::io::ErrorKind::UnexpectedEof.into()),
            Ok(n) => {
                buf = &mut buf[n..];
                offset += n as u64;
            }
            Err(e) if e.kind() == std::io::ErrorKind::Interrupted => {}
            Err(e) => return Err(e),
        }
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn slice_source() {
        let s: &[u8] = b"hello";
        assert_eq!(Source::len(s), 5);
        let mut buf = [0u8; 3];
        s.read_at(1, &mut buf).unwrap();
        assert_eq!(&buf, b"ell");
        assert!(s.read_at(3, &mut buf).is_err());
        assert!(s.read_at(u64::MAX, &mut buf).is_err());
        s.read_at(5, &mut []).unwrap();
    }

    #[test]
    fn file_source() {
        let dir = std::env::temp_dir().join(format!("quelda-src-{}", std::process::id()));
        std::fs::create_dir_all(&dir).unwrap();
        let path = dir.join("f.bin");
        std::fs::write(&path, b"0123456789").unwrap();
        let f = FileSource::open(&path).unwrap();
        assert_eq!(f.len(), 10);
        let mut buf = [0u8; 4];
        f.read_at(6, &mut buf).unwrap();
        assert_eq!(&buf, b"6789");
        assert!(f.read_at(8, &mut buf).is_err());
        std::fs::remove_dir_all(&dir).unwrap();
    }
}
