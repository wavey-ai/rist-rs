#[derive(Debug, Clone, Copy, PartialEq, Eq, Default)]
pub enum Profile {
    Simple,
    #[default]
    Main,
    Advanced,
}
