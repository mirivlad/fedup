//! Experimental FedUp v1 framing codec.
//!
//! This crate is NOT a VPN and does not provide authentication, encryption,
//! tunneling, routing, or stealth. Frames MUST be carried over an independently
//! authenticated encrypted transport. The v1 wire format is experimental.

use std::fmt;
use std::io::{self, Read, Write};

/// Header: version(1), kind(1), reserved_flags(2), stream_id(4), payload_len(4).
pub const HEADER_LEN: usize = 12;
/// Limit the payload before allocating any payload-sized memory.
pub const MAX_PAYLOAD_LEN: usize = 64 * 1024;
/// The only supported experimental wire version.
pub const WIRE_VERSION: u8 = 1;

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
#[repr(u8)]
pub enum FrameKind {
    Ping = 1,
    Pong = 2,
    Error = 3,
    Open = 4,
    Data = 5,
    Close = 6,
    Datagram = 7,
}

impl TryFrom<u8> for FrameKind {
    type Error = ProtocolError;

    fn try_from(value: u8) -> Result<Self, ProtocolError> {
        match value {
            1 => Ok(Self::Ping),
            2 => Ok(Self::Pong),
            3 => Ok(Self::Error),
            4 => Ok(Self::Open),
            5 => Ok(Self::Data),
            6 => Ok(Self::Close),
            7 => Ok(Self::Datagram),
            _ => Err(ProtocolError::UnknownKind(value)),
        }
    }
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct Frame {
    pub kind: FrameKind,
    /// A zero stream identifier is reserved for control frames.
    pub stream_id: u32,
    pub payload: Vec<u8>,
}

impl Frame {
    pub fn new(kind: FrameKind, stream_id: u32, payload: Vec<u8>) -> Result<Self, ProtocolError> {
        validate(kind, stream_id, payload.len())?;
        Ok(Self {
            kind,
            stream_id,
            payload,
        })
    }
}

#[derive(Debug)]
pub enum ProtocolError {
    Io(io::Error),
    Version(u8),
    UnknownKind(u8),
    NonZeroReservedFlags(u16),
    InvalidStream { kind: FrameKind, stream_id: u32 },
    Oversize { len: usize, max: usize },
}

impl fmt::Display for ProtocolError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::Io(e) => write!(f, "I/O failure: {e}"),
            Self::Version(v) => write!(f, "unsupported frame version {v}"),
            Self::UnknownKind(k) => write!(f, "unknown frame kind {k}"),
            Self::NonZeroReservedFlags(v) => write!(f, "reserved flags not zero: {v:#x}"),
            Self::InvalidStream { kind, stream_id } => {
                write!(f, "invalid stream {stream_id} for frame kind {kind:?}")
            }
            Self::Oversize { len, max } => write!(f, "payload {len} exceeds limit {max}"),
        }
    }
}

impl std::error::Error for ProtocolError {
    fn source(&self) -> Option<&(dyn std::error::Error + 'static)> {
        match self {
            Self::Io(e) => Some(e),
            _ => None,
        }
    }
}

impl From<io::Error> for ProtocolError {
    fn from(value: io::Error) -> Self {
        Self::Io(value)
    }
}

fn validate(kind: FrameKind, stream_id: u32, payload_len: usize) -> Result<(), ProtocolError> {
    if payload_len > MAX_PAYLOAD_LEN {
        return Err(ProtocolError::Oversize {
            len: payload_len,
            max: MAX_PAYLOAD_LEN,
        });
    }
    let control = matches!(kind, FrameKind::Ping | FrameKind::Pong | FrameKind::Error);
    if control != (stream_id == 0) {
        return Err(ProtocolError::InvalidStream { kind, stream_id });
    }
    Ok(())
}

/// Read one frame. Header checks happen before any payload allocation.
/// The caller must set appropriate read and handshake deadlines on network I/O.
pub fn read_frame<R: Read>(reader: &mut R) -> Result<Frame, ProtocolError> {
    let mut header = [0_u8; HEADER_LEN];
    reader.read_exact(&mut header)?;

    if header[0] != WIRE_VERSION {
        return Err(ProtocolError::Version(header[0]));
    }
    let kind = FrameKind::try_from(header[1])?;
    let flags = u16::from_be_bytes([header[2], header[3]]);
    if flags != 0 {
        return Err(ProtocolError::NonZeroReservedFlags(flags));
    }
    let stream_id = u32::from_be_bytes(header[4..8].try_into().expect("fixed header size"));
    let payload_len =
        u32::from_be_bytes(header[8..12].try_into().expect("fixed header size")) as usize;
    validate(kind, stream_id, payload_len)?;

    // Length is bounded. This allocation never depends on unchecked input.
    let mut payload = vec![0; payload_len];
    reader.read_exact(&mut payload)?;
    Ok(Frame {
        kind,
        stream_id,
        payload,
    })
}

/// Encode a single bounded frame without intermediate payload copying.
pub fn write_frame<W: Write>(writer: &mut W, frame: &Frame) -> Result<(), ProtocolError> {
    validate(frame.kind, frame.stream_id, frame.payload.len())?;
    let mut header = [0_u8; HEADER_LEN];
    header[0] = WIRE_VERSION;
    header[1] = frame.kind as u8;
    header[4..8].copy_from_slice(&frame.stream_id.to_be_bytes());
    header[8..12].copy_from_slice(&(frame.payload.len() as u32).to_be_bytes());
    writer.write_all(&header)?;
    writer.write_all(&frame.payload)?;
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::io::Cursor;

    fn raw_header(version: u8, kind: u8, flags: u16, stream: u32, len: u32) -> [u8; 12] {
        let mut h = [0u8; 12];
        h[0] = version;
        h[1] = kind;
        h[2..4].copy_from_slice(&flags.to_be_bytes());
        h[4..8].copy_from_slice(&stream.to_be_bytes());
        h[8..12].copy_from_slice(&len.to_be_bytes());
        h
    }

    #[test]
    fn round_trip_control_and_data() {
        for kind in [
            FrameKind::Ping,
            FrameKind::Pong,
            FrameKind::Error,
            FrameKind::Open,
            FrameKind::Data,
            FrameKind::Close,
            FrameKind::Datagram,
        ] {
            let stream_id = if matches!(kind, FrameKind::Ping | FrameKind::Pong | FrameKind::Error)
            {
                0
            } else {
                1
            };
            let original = Frame::new(kind, stream_id, vec![1, 2, 3, 255]).unwrap();
            let mut encoded = Vec::new();
            write_frame(&mut encoded, &original).unwrap();
            assert_eq!(encoded.len(), HEADER_LEN + 4);
            let parsed = read_frame(&mut Cursor::new(encoded)).unwrap();
            assert_eq!(parsed, original);
        }
    }

    #[test]
    fn zero_length_payload() {
        let f = Frame::new(FrameKind::Ping, 0, vec![]).unwrap();
        let mut bytes = vec![];
        write_frame(&mut bytes, &f).unwrap();
        assert_eq!(read_frame(&mut Cursor::new(bytes)).unwrap(), f);
    }

    #[test]
    fn exactly_maximum_size_accepted() {
        let f = Frame::new(FrameKind::Data, 1, vec![42; MAX_PAYLOAD_LEN]).unwrap();
        let mut bytes = vec![];
        write_frame(&mut bytes, &f).unwrap();
        assert_eq!(read_frame(&mut Cursor::new(bytes)).unwrap(), f);
    }

    #[test]
    fn refuses_declared_oversize_before_read_or_allocation() {
        for len in [MAX_PAYLOAD_LEN as u32 + 1, u32::MAX] {
            let h = raw_header(WIRE_VERSION, FrameKind::Data as u8, 0, 1, len);
            assert!(matches!(
                read_frame(&mut Cursor::new(h)),
                Err(ProtocolError::Oversize { .. })
            ));
        }
    }

    #[test]
    fn rejects_invalid_header_fields() {
        let bad = [
            raw_header(0, 1, 0, 0, 0),
            raw_header(2, 1, 0, 0, 0),
            raw_header(1, 99, 0, 0, 0),
            raw_header(1, 1, 0x10, 0, 0),
            raw_header(1, 1, 0, 1, 0),
            raw_header(1, 5, 0, 0, 0),
        ];
        for h in bad {
            assert!(read_frame(&mut Cursor::new(h)).is_err());
        }
    }

    #[test]
    fn rejects_invalid_frames_before_writing_anything() {
        let cases = [
            Frame {
                kind: FrameKind::Ping,
                stream_id: 1,
                payload: vec![],
            },
            Frame {
                kind: FrameKind::Data,
                stream_id: 0,
                payload: vec![],
            },
            Frame {
                kind: FrameKind::Data,
                stream_id: 1,
                payload: vec![0; MAX_PAYLOAD_LEN + 1],
            },
        ];
        for f in cases {
            let mut output = vec![];
            assert!(write_frame(&mut output, &f).is_err());
            assert!(output.is_empty());
        }
    }

    #[test]
    fn truncated_headers_and_payloads() {
        let h = raw_header(1, 1, 0, 0, 5);
        for end in 0..h.len() {
            assert!(read_frame(&mut Cursor::new(&h[..end])).is_err());
        }
        let mut b = h.to_vec();
        b.extend_from_slice(&[1, 2, 3, 4]);
        assert!(matches!(
            read_frame(&mut Cursor::new(b)),
            Err(ProtocolError::Io(_))
        ));
    }

    #[test]
    fn serialized_data_is_big_endian_and_stable() {
        let f = Frame::new(FrameKind::Data, 0x01020304, vec![0xab]).unwrap();
        let mut bytes = Vec::new();
        write_frame(&mut bytes, &f).unwrap();
        assert_eq!(bytes, [1, 5, 0, 0, 1, 2, 3, 4, 0, 0, 0, 1, 0xab]);
    }

    struct OneByteAtATime<R>(R);
    impl<R: Read> Read for OneByteAtATime<R> {
        fn read(&mut self, buf: &mut [u8]) -> io::Result<usize> {
            let n = buf.len().min(1);
            self.0.read(&mut buf[..n])
        }
    }

    #[test]
    fn fragmented_reads() {
        let f = Frame::new(FrameKind::Ping, 0, b"hello".to_vec()).unwrap();
        let mut encoded = vec![];
        write_frame(&mut encoded, &f).unwrap();
        assert_eq!(
            read_frame(&mut OneByteAtATime(Cursor::new(encoded))).unwrap(),
            f
        );
    }

    #[test]
    fn deterministic_malformed_input_smoke_test() {
        let mut seed = 0xfeed_f00d_1234_abcd_u64;
        for len in 0..2000_usize {
            let mut bytes = vec![0; len % (HEADER_LEN + 100)];
            for b in &mut bytes {
                seed ^= seed << 13;
                seed ^= seed >> 7;
                seed ^= seed << 17;
                *b = seed as u8;
            }
            let _ = read_frame(&mut Cursor::new(bytes));
        }
    }
}
