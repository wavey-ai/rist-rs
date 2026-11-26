//! Round-trip time estimation shared by receivers and senders.

use std::time::Duration;

/// Smoothed round-trip time, as librist keeps it (`eight_times_rtt`, an EWMA
/// with weight 1/8), plus the last and the smallest sample.
///
/// The two read-outs err in opposite directions on purpose: a receiver
/// waits [`Self::for_renack`] (the larger of the smoothed and the last
/// sample) before asking again, and a sender spaces repairs by
/// [`Self::for_spacing`] (the smaller one). The receiver then errs late and
/// the sender early, so independent estimates on the two sides do not make
/// the sender refuse a re-request that the receiver timed correctly.
#[derive(Debug, Clone, Copy, Default, PartialEq, Eq)]
pub struct RttEstimator {
    srtt_us: Option<u64>,
    last_us: Option<u64>,
    min_us: Option<u64>,
    samples: u64,
}

impl RttEstimator {
    pub fn new() -> Self {
        Self::default()
    }

    /// Folds one sample (microseconds) into the estimate.
    pub fn sample(&mut self, us: u64) {
        self.last_us = Some(us);
        self.srtt_us = Some(match self.srtt_us {
            None => us,
            Some(srtt) => srtt - srtt / 8 + us / 8,
        });
        self.min_us = Some(self.min_us.map_or(us, |min| min.min(us)));
        self.samples += 1;
    }

    pub fn sample_duration(&mut self, rtt: Duration) {
        self.sample(u64::try_from(rtt.as_micros()).unwrap_or(u64::MAX));
    }

    pub fn is_measured(&self) -> bool {
        self.srtt_us.is_some()
    }

    pub fn samples(&self) -> u64 {
        self.samples
    }

    pub fn srtt_micros(&self) -> Option<u64> {
        self.srtt_us
    }

    pub fn last_micros(&self) -> Option<u64> {
        self.last_us
    }

    pub fn min_micros(&self) -> Option<u64> {
        self.min_us
    }

    /// max(smoothed, last): how long a receiver waits before re-requesting.
    pub fn for_renack(&self) -> Option<Duration> {
        let srtt = self.srtt_us?;
        Some(Duration::from_micros(
            srtt.max(self.last_us.unwrap_or(srtt)),
        ))
    }

    /// min(smoothed, last): the basis of a sender's repair spacing.
    pub fn for_spacing(&self) -> Option<Duration> {
        let srtt = self.srtt_us?;
        Some(Duration::from_micros(
            srtt.min(self.last_us.unwrap_or(srtt)),
        ))
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn first_sample_seeds_and_later_samples_move_by_one_eighth() {
        let mut rtt = RttEstimator::new();
        assert!(!rtt.is_measured());
        assert_eq!(rtt.for_renack(), None);
        rtt.sample(30_000);
        assert_eq!(rtt.srtt_micros(), Some(30_000));
        rtt.sample(38_000);
        assert_eq!(rtt.srtt_micros(), Some(31_000));
        assert_eq!(rtt.last_micros(), Some(38_000));
        assert_eq!(rtt.min_micros(), Some(30_000));
        assert_eq!(rtt.for_renack(), Some(Duration::from_micros(38_000)));
        assert_eq!(rtt.for_spacing(), Some(Duration::from_micros(31_000)));
        rtt.sample(10_000);
        assert_eq!(rtt.min_micros(), Some(10_000));
        assert_eq!(rtt.for_spacing(), Some(Duration::from_micros(10_000)));
        assert_eq!(rtt.samples(), 3);
    }
}
