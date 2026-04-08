#[derive(Debug, Clone, Copy, PartialEq)]
#[repr(u8)]
pub enum ActionType {
    Default   = 0x00,
    ClipboardSync = 0x01,
}

impl ActionType {
    pub fn from_u8(v: u8) -> Option<Self> {
        match v {
            0x00 => Some(Self::Default),
            0x01 => Some(Self::ClipboardSync),
            _ => None,
        }
    }
}