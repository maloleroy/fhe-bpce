use crate::{DegreeType, EncryptionParameters, Error, Modulus, SchemeType};

use super::CoefficientModulusType;

/// Represents a builder that sets up and creates encryption scheme parameters.
///
/// The parameters (most importantly PolyModulus, CoeffModulus)
/// significantly affect the performance, capabilities, and security of the
/// encryption scheme.
#[derive(Debug, PartialEq)]
pub struct CKKSEncryptionParametersBuilder {
    poly_modulus_degree: Option<DegreeType>,
    coefficient_modulus: CoefficientModulusType,
}

impl CKKSEncryptionParametersBuilder {
    /// Creates a new builder.
    #[must_use]
    pub const fn new() -> Self {
        Self {
            poly_modulus_degree: None,
            coefficient_modulus: CoefficientModulusType::NotSet,
        }
    }

    /// Set the degree of the polynomial used in the CKKS scheme. Genrally,
    /// larger values provide more security and noise margin at the expense
    /// of performance.
    #[must_use]
    pub const fn set_poly_modulus_degree(mut self, degree: DegreeType) -> Self {
        self.poly_modulus_degree = Some(degree);
        self
    }

    /// Sets the coefficient modulus parameter. The coefficient modulus consists
    /// of a list of distinct prime numbers, and is represented by a vector of
    /// Modulus objects. The coefficient modulus directly affects the size
    /// of ciphertext elements, the amount of computation that the scheme can
    /// perform (bigger is better), and the security level (bigger is worse). In
    /// Microsoft SEAL each of the prime numbers in the coefficient modulus must
    /// be at most 60 bits, and must be congruent to 1 modulo 2*poly_modulus_degree.
    #[must_use]
    pub fn set_coefficient_modulus(mut self, modulus: Vec<Modulus>) -> Self {
        self.coefficient_modulus = CoefficientModulusType::Modulus(modulus);
        self
    }

    /// Validate the parameter choices and return the encryption parameters.
    pub fn build(self) -> Result<EncryptionParameters, Error> {
        let mut params = EncryptionParameters::new(SchemeType::Ckks)?;

        match self.poly_modulus_degree {
            Some(degree) => params.set_poly_modulus_degree(u64::from(degree))?,
            None => return Err(Error::DegreeNotSet),
        }

        match self.coefficient_modulus {
            CoefficientModulusType::NotSet => return Err(Error::CoefficientModulusNotSet),
            CoefficientModulusType::Modulus(m) => {
                params.set_coefficient_modulus(&m)?;
            }
        }

        Ok(params)
    }
}

impl Default for CKKSEncryptionParametersBuilder {
    fn default() -> Self {
        Self::new()
    }
}

#[cfg(test)]
mod tests {
    use crate::*;

    #[test]
    fn can_build_params() {
        let bit_sizes = [60, 40, 40, 60];
        let modulus_chain =
            CoefficientModulusFactory::build(DegreeType::D1024, bit_sizes.as_slice()).unwrap();

        let params = CKKSEncryptionParametersBuilder::new()
            .set_poly_modulus_degree(DegreeType::D1024)
            .set_coefficient_modulus(modulus_chain)
            .build()
            .unwrap();

        assert_eq!(params.get_poly_modulus_degree(), 1024);
        assert_eq!(params.get_scheme(), SchemeType::Ckks);
        assert_eq!(params.get_coefficient_modulus().len(), 4);

        let params = CKKSEncryptionParametersBuilder::new()
            .set_poly_modulus_degree(DegreeType::D1024)
            .set_coefficient_modulus(
                CoefficientModulusFactory::build(DegreeType::D8192, &[50, 30, 30, 50, 50]).unwrap(),
            )
            .build()
            .unwrap();

        let modulus = params.get_coefficient_modulus();

        assert_eq!(params.get_poly_modulus_degree(), 1024);
        assert_eq!(params.get_scheme(), SchemeType::Ckks);
        assert_eq!(modulus.len(), 5);
        assert_eq!(modulus[0].value(), 1125899905744897);
        assert_eq!(modulus[1].value(), 1073643521);
        assert_eq!(modulus[2].value(), 1073692673);
        assert_eq!(modulus[3].value(), 1125899906629633);
        assert_eq!(modulus[4].value(), 1125899906826241);
    }
}
