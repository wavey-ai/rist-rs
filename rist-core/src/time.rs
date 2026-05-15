use std::time::{Duration, SystemTime, UNIX_EPOCH};

pub const NTP_UNIX_EPOCH_OFFSET_SECS: u64 = 2_208_988_800;
pub const MPEGTS_CLOCK_HZ: u64 = 90_000;
pub const RIST_CLOCK_HZ: u64 = 65_536;

pub fn ntp_from_unix_duration(duration: Duration) -> u64 {
    let seconds = duration.as_secs() + NTP_UNIX_EPOCH_OFFSET_SECS;
    let fraction = ((u64::from(duration.subsec_nanos())) << 32) / 1_000_000_000;
    (seconds << 32) | fraction
}

pub fn ntp_now() -> u64 {
    let duration = SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .unwrap_or_default();
    ntp_from_unix_duration(duration)
}

pub fn mpegts_rtp_timestamp(ntp: u64) -> u32 {
    let seconds = ntp >> 32;
    let fraction = ntp & 0xffff_ffff;
    let fractional_ticks = (fraction * MPEGTS_CLOCK_HZ) >> 32;
    ((seconds * MPEGTS_CLOCK_HZ + fractional_ticks) & 0xffff_ffff) as u32
}

pub fn ntp_delta_micros(later: u64, earlier: u64) -> u64 {
    let ticks = later.saturating_sub(earlier);
    (((u128::from(ticks) * 1_000_000) + (1u128 << 31)) >> 32) as u64
}

pub fn calculate_rtt_micros(request_ntp: u64, response_ntp: u64, delay_micros: u32) -> u64 {
    ntp_delta_micros(response_ntp, request_ntp).saturating_sub(u64::from(delay_micros))
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn ntp_unix_epoch_has_expected_seconds_offset() {
        assert_eq!(ntp_from_unix_duration(Duration::ZERO) >> 32, 2_208_988_800);
    }

    #[test]
    fn mpegts_timestamp_uses_90khz_clock() {
        let start = mpegts_rtp_timestamp(ntp_from_unix_duration(Duration::ZERO));
        let one_second = mpegts_rtp_timestamp(ntp_from_unix_duration(Duration::from_secs(1)));
        assert_eq!(one_second.wrapping_sub(start), 90_000);
    }

    #[test]
    fn ntp_delta_micros_uses_fractional_ntp_units() {
        let start = ntp_from_unix_duration(Duration::ZERO);
        let end = ntp_from_unix_duration(Duration::from_micros(1_500));
        assert_eq!(ntp_delta_micros(end, start), 1_500);
        assert_eq!(calculate_rtt_micros(start, end, 500), 1_000);
    }
}
