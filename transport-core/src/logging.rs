use core::fmt;

#[derive(Copy, Clone)]
pub struct HexOption(pub Option<u8>);

impl fmt::Display for HexOption {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self.0 {
            Some(value) => write!(f, "0x{value:02x}"),
            None => write!(f, "n/a"),
        }
    }
}
