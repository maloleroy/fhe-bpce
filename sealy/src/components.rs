mod sealed {
    pub trait Sealed {}
    impl Sealed for super::Sym {}
    impl Sealed for super::Asym {}
    impl Sealed for super::SymAsym {}
}

/// Marker traits to signify what types of enryptions are supported
pub mod marker {
    /// Supports symmetric encryptions.
    pub trait Sym: super::sealed::Sealed {}
    /// Supports asymmetric encryptions.
    pub trait Asym: super::sealed::Sealed {}
}

/// Symmetric encryptions marker
#[derive(Debug, PartialEq, Eq, Clone)]
pub struct Sym;
impl marker::Sym for Sym {}

/// Asymmetric encryptions marker
#[derive(Debug, PartialEq, Eq, Clone)]
pub struct Asym;
impl marker::Asym for Asym {}

/// Both symmetric and asymmetric encryptions marker
#[derive(Debug, PartialEq, Eq, Clone)]
pub struct SymAsym;
impl marker::Sym for SymAsym {}
impl marker::Asym for SymAsym {}
