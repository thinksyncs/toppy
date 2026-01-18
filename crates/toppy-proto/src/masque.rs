#[derive(Debug, Clone, PartialEq, Eq)]
pub struct HttpDatagram {
    /// QUIC variable-length integer.
    pub context_id: u64,
    pub payload: Vec<u8>,
}

impl HttpDatagram {
    pub fn new(context_id: u64, payload: impl Into<Vec<u8>>) -> Self {
        Self {
            context_id,
            payload: payload.into(),
        }
    }

    /// Encodes as: varint(context_id) || payload
    pub fn encode(&self) -> Result<Vec<u8>, EncodeError> {
        let mut out = Vec::with_capacity(varint_len(self.context_id) + self.payload.len());
        encode_varint(self.context_id, &mut out)?;
        out.extend_from_slice(&self.payload);
        Ok(out)
    }

    pub fn decode(input: &[u8]) -> Result<Self, DecodeError> {
        let (context_id, n) = decode_varint(input)?;
        Ok(Self {
            context_id,
            payload: input[n..].to_vec(),
        })
    }
}

/// CONNECT-UDP uses Context ID 0 for UDP payload datagrams.
pub const CONNECT_UDP_CONTEXT_ID: u64 = 0;

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum DecodeError {
    Truncated,
    Invalid,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum EncodeError {
    OutOfRange,
}

/// Encodes a QUIC variable-length integer.
///
/// Supports values in 0..=2^62-1.
pub fn encode_varint(value: u64, out: &mut Vec<u8>) -> Result<(), EncodeError> {
    match value {
        0..=63 => {
            out.push((value & 0x3f) as u8);
            Ok(())
        }
        64..=16_383 => {
            let v = value | (0b01 << 14);
            out.extend_from_slice(&(v as u16).to_be_bytes());
            Ok(())
        }
        16_384..=1_073_741_823 => {
            let v = value | (0b10u64 << 30);
            out.extend_from_slice(&(v as u32).to_be_bytes());
            Ok(())
        }
        1_073_741_824..=4_611_686_018_427_387_903 => {
            let v = value | (0b11u64 << 62);
            out.extend_from_slice(&v.to_be_bytes());
            Ok(())
        }
        _ => Err(EncodeError::OutOfRange),
    }
}

pub fn decode_varint(input: &[u8]) -> Result<(u64, usize), DecodeError> {
    let first = *input.first().ok_or(DecodeError::Truncated)?;
    let prefix = first >> 6;
    let len = match prefix {
        0b00 => 1,
        0b01 => 2,
        0b10 => 4,
        0b11 => 8,
        _ => return Err(DecodeError::Invalid),
    };

    if input.len() < len {
        return Err(DecodeError::Truncated);
    }

    let value = match len {
        1 => (first & 0x3f) as u64,
        2 => {
            let raw = u16::from_be_bytes([input[0], input[1]]) as u64;
            raw & 0x3fff
        }
        4 => {
            let raw = u32::from_be_bytes([input[0], input[1], input[2], input[3]]) as u64;
            raw & 0x3fff_ffff
        }
        8 => {
            let raw = u64::from_be_bytes([
                input[0], input[1], input[2], input[3], input[4], input[5], input[6], input[7],
            ]);
            raw & 0x3fff_ffff_ffff_ffff
        }
        _ => return Err(DecodeError::Invalid),
    };

    Ok((value, len))
}

pub fn varint_len(value: u64) -> usize {
    match value {
        0..=63 => 1,
        64..=16_383 => 2,
        16_384..=1_073_741_823 => 4,
        1_073_741_824..=4_611_686_018_427_387_903 => 8,
        _ => 0,
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn varint_roundtrip_boundaries() {
        let values = [
            0u64,
            1,
            63,
            64,
            16_383,
            16_384,
            1_073_741_823,
            1_073_741_824,
            4_611_686_018_427_387_903,
        ];

        for v in values {
            let mut buf = Vec::new();
            encode_varint(v, &mut buf).unwrap();
            let (decoded, n) = decode_varint(&buf).unwrap();
            assert_eq!(decoded, v);
            assert_eq!(n, buf.len());
        }
    }

    #[test]
    fn http_datagram_encode_decode_roundtrip() {
        let dg = HttpDatagram::new(CONNECT_UDP_CONTEXT_ID, vec![1, 2, 3, 4]);
        let bytes = dg.encode().unwrap();
        let decoded = HttpDatagram::decode(&bytes).unwrap();
        assert_eq!(decoded, dg);
    }

    #[test]
    fn decode_varint_truncated() {
        assert_eq!(decode_varint(&[]), Err(DecodeError::Truncated));
        // 2-byte encoding but only 1 byte provided.
        assert_eq!(decode_varint(&[0b01 << 6]), Err(DecodeError::Truncated));
    }
}
