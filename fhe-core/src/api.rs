//! This module defines the core API of FHE cryptosystems.

pub mod select;

/// A trait that defines the core API of a FHE cryptosystem.
pub trait CryptoSystem {
    /// The plaintext type for the FHE scheme.
    type Plaintext;
    /// The ciphertext type for the FHE scheme.
    type Ciphertext;

    /// The operations that can be performed on the ciphertexts.
    ///
    /// This should be easily representable by a small enum.
    type Operation;

    /// Encrypts a plaintext into a ciphertext.
    fn cipher(&self, plaintext: &Self::Plaintext) -> Self::Ciphertext;
    /// Decrypts a ciphertext back into a plaintext.
    fn decipher(&self, ciphertext: &Self::Ciphertext) -> Self::Plaintext;

    #[must_use = "This method does not modify the input ciphertext."]
    /// Performs an operation on the ciphertexts.
    ///
    /// Every operation requires at least one operand.
    /// For operations that only require one operand, `rhs` can be `None`.
    /// Otherwise, it is up to you to `unwrap` it and make sure there is one when needed.
    fn operate(
        &self,
        operation: Self::Operation,
        lhs: &Self::Ciphertext,
        rhs: Option<&Self::Ciphertext>,
    ) -> Self::Ciphertext;

    /// Performs an operation on the ciphertexts in place.
    ///
    /// This is a default implementation that calls `operate` and assigns the result to `lhs`.
    /// You can override this method to provide a more detailed implementation.
    fn operate_inplace(
        &self,
        operation: Self::Operation,
        lhs: &mut Self::Ciphertext,
        rhs: Option<&Self::Ciphertext>,
    ) {
        let result: <Self as CryptoSystem>::Ciphertext = self.operate(operation, lhs, rhs);
        *lhs = result;
    }

    fn relinearize(&self, ciphertext: &mut Self::Ciphertext);
}

#[allow(dead_code)]
/// Module to assert that usual usage of the API compiles.
mod private {
    use super::CryptoSystem;

    #[derive(Clone)]
    struct TestPlaintext {}
    struct TestCiphertext {
        // Absolutely not secure system, just for testing purposes.
        data: TestPlaintext,
    }

    struct TestCryptoSystem {}

    #[derive(Clone, Copy, Debug)]
    enum Op {
        Add,
        Mul,
    }

    impl CryptoSystem for TestCryptoSystem {
        type Plaintext = TestPlaintext;
        type Ciphertext = TestCiphertext;
        type Operation = Op;

        fn cipher(&self, plaintext: &Self::Plaintext) -> Self::Ciphertext {
            TestCiphertext {
                data: plaintext.clone(),
            }
        }
        fn decipher(&self, ciphertext: &Self::Ciphertext) -> Self::Plaintext {
            ciphertext.data.clone()
        }

        fn operate(
            &self,
            operation: Self::Operation,
            lhs: &Self::Ciphertext,
            rhs: Option<&Self::Ciphertext>,
        ) -> Self::Ciphertext {
            match operation {
                Op::Add => {
                    assert!(rhs.is_some(), "Addition requires two operands.");
                    let data = rhs.unwrap().data.clone();
                    TestCiphertext { data }
                }
                Op::Mul => {
                    assert!(rhs.is_some(), "Multiplication requires two operands.");
                    let data = lhs.data.clone();
                    TestCiphertext { data }
                }
            }
        }

        fn relinearize(&self, _ciphertext: &mut Self::Ciphertext) {}
    }

    // Assert that CryptoSystem is `dyn` compatible.
    fn any_operation<C, P>(
        _system: &dyn CryptoSystem<Ciphertext = C, Plaintext = P, Operation = ()>,
        other_param: u8,
    ) -> u8 {
        other_param
    }
}
