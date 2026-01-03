/// RIST protocol profile.
///
/// Profiles determine which features and complexity levels are available.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Default)]
pub enum Profile {
    /// Simple profile - basic functionality, lowest complexity.
    Simple,
    /// Main profile - standard functionality for most use cases.
    #[default]
    Main,
    /// Advanced profile - full feature set.
    Advanced,
}

impl Profile {
    pub(crate) fn to_raw(self) -> rist_sys::rist_profile {
        match self {
            Profile::Simple => rist_sys::rist_profile_RIST_PROFILE_SIMPLE,
            Profile::Main => rist_sys::rist_profile_RIST_PROFILE_MAIN,
            Profile::Advanced => rist_sys::rist_profile_RIST_PROFILE_ADVANCED,
        }
    }
}
