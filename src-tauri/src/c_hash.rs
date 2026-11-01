//! Linux adapter to AnnaKav's original C compression function.
extern "C" {
    fn MultiSha(data: *mut u8, state: *mut u32, len: usize, size: u64) -> *mut u32;
}

pub struct Sha256 {
    state: [u32; 8],
    pending: Vec<u8>,
    bytes: u64,
}

impl Sha256 {
    pub fn new() -> Self {
        Self {
            state: [
                0x6a09e667, 0xbb67ae85, 0x3c6ef372, 0xa54ff53a, 0x510e527f, 0x9b05688c, 0x1f83d9ab,
                0x5be0cd19,
            ],
            pending: Vec::with_capacity(64),
            bytes: 0,
        }
    }

    fn block(&mut self, mut block: [u8; 64]) {
        // Full blocks bypass the legacy padding. C retains neither pointer;
        // the state and block are valid, exclusively borrowed fixed arrays.
        unsafe {
            MultiSha(block.as_mut_ptr(), self.state.as_mut_ptr(), 64, 0);
        }
    }

    pub fn update(&mut self, data: &[u8]) {
        self.bytes = self.bytes.wrapping_add(data.len() as u64);
        for chunk in data.chunks(64) {
            self.pending.extend_from_slice(chunk);
            if self.pending.len() >= 64 {
                let block = self.pending[..64].try_into().unwrap();
                self.block(block);
                self.pending.drain(..64);
            }
        }
    }

    pub fn finalize(mut self) -> [u8; 32] {
        let bits = self.bytes.wrapping_mul(8);
        self.pending.push(0x80);
        while self.pending.len() % 64 != 56 {
            self.pending.push(0);
        }
        self.pending.extend_from_slice(&bits.to_be_bytes());
        let tail = std::mem::take(&mut self.pending);
        for block in tail.chunks_exact(64) {
            self.block(block.try_into().unwrap());
        }
        let mut digest = [0; 32];
        for (out, word) in digest.chunks_exact_mut(4).zip(self.state) {
            out.copy_from_slice(&word.to_be_bytes());
        }
        digest
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use sha2::Digest;
    #[test]
    fn original_c_matches_reference_at_padding_and_read_boundaries() {
        for len in [
            0, 1, 3, 54, 55, 56, 63, 64, 65, 119, 120, 127, 128, 65535, 65536, 65537, 200000,
        ] {
            let data: Vec<u8> = (0..len).map(|i| (i % 251) as u8).collect();
            for chunk_size in [1, 63, 64, 65, 65536] {
                let mut c = Sha256::new();
                for chunk in data.chunks(chunk_size) {
                    c.update(chunk);
                }
                let expected: [u8; 32] = sha2::Sha256::digest(&data).into();
                assert_eq!(c.finalize(), expected, "length {len}, chunk {chunk_size}");
            }
        }
    }
}
