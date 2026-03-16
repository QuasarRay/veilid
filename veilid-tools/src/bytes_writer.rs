use std::{cmp::min, io::Write};

use super::*;

#[must_use]
pub struct BytesWriter {
    bytes_mut: BytesMut,
    start: usize,
    position: usize,
}

impl Default for BytesWriter {
    fn default() -> Self {
        Self::new()
    }
}

impl BytesWriter {
    pub fn new() -> Self {
        Self::with_capacity(0)
    }

    pub fn with_capacity(capacity: usize) -> Self {
        Self {
            bytes_mut: BytesMut::with_capacity(capacity),
            start: 0,
            position: 0,
        }
    }

    pub fn new_append(bytes_mut: BytesMut) -> Self {
        let start = bytes_mut.len();
        Self {
            bytes_mut,
            start,
            position: start,
        }
    }

    pub fn new_offset(mut bytes_mut: BytesMut, offset: usize) -> Self {
        if offset > bytes_mut.len() {
            bytes_mut.resize(offset, 0);
        }
        Self {
            bytes_mut,
            start: offset,
            position: offset,
        }
    }

    #[must_use]
    pub fn bytes_written(&self) -> usize {
        self.position - self.start
    }
    #[must_use]
    pub fn position(&self) -> usize {
        self.position
    }
    #[must_use]
    pub fn start(&self) -> usize {
        self.start
    }
    #[must_use]
    pub fn bytes_mut(&self) -> &BytesMut {
        &self.bytes_mut
    }

    #[must_use]
    pub fn into_inner(self) -> BytesMut {
        self.bytes_mut
    }
}

impl Write for BytesWriter {
    fn write(&mut self, buf: &[u8]) -> std::io::Result<usize> {
        let len = buf.len();

        let len_to_copy = min(len, self.bytes_mut.len() - self.position);
        if len_to_copy > 0 {
            self.bytes_mut[self.position..self.position + len_to_copy]
                .copy_from_slice(&buf[..len_to_copy]);
        }
        if len_to_copy < len {
            self.bytes_mut.extend_from_slice(&buf[len_to_copy..]);
        }
        self.position += len;
        Ok(len)
    }

    fn flush(&mut self) -> std::io::Result<()> {
        Ok(())
    }
}
