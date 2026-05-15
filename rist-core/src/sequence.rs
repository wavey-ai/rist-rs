#[derive(Debug, Clone, Default)]
pub struct SequenceExtender {
    last: Option<u32>,
}

impl SequenceExtender {
    pub fn new() -> Self {
        Self::default()
    }

    pub fn extend(&mut self, seq: u16) -> u32 {
        let extended = match self.last {
            None => u32::from(seq),
            Some(last) => extend_near(last, seq),
        };
        self.last = Some(extended);
        extended
    }

    pub fn last(&self) -> Option<u32> {
        self.last
    }
}

pub fn extend_near(reference: u32, seq: u16) -> u32 {
    let reference_low = reference as u16;
    let mut high = reference & 0xffff_0000;
    if seq < reference_low && reference_low.wrapping_sub(seq) > 0x8000 {
        high = high.wrapping_add(0x0001_0000);
    } else if seq > reference_low && seq.wrapping_sub(reference_low) > 0x8000 {
        high = high.wrapping_sub(0x0001_0000);
    }
    high | u32::from(seq)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn extends_forward_across_wrap() {
        let mut extender = SequenceExtender::new();
        assert_eq!(extender.extend(0xfffe), 0xfffe);
        assert_eq!(extender.extend(0xffff), 0xffff);
        assert_eq!(extender.extend(0), 0x1_0000);
        assert_eq!(extender.extend(1), 0x1_0001);
    }

    #[test]
    fn keeps_late_packet_in_previous_cycle() {
        assert_eq!(extend_near(0x1_0002, 0xffff), 0xffff);
    }
}
