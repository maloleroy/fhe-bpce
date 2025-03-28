//! This module defines the core API of FHE cryptosystems.

/// A trait that defines the operations that can be performed on the ciphertexts.
pub trait Operation {}
impl Operation for () {}

/// A trait that defines the operations that can be performed on one ciphertext.
pub trait Arity1Operation: Operation {}
impl Arity1Operation for () {}
/// A trait that defines the operations that can be performed on two ciphertexts.
pub trait Arity2Operation: Operation {}
impl Arity2Operation for () {}

/// A trait that defines the core API of a FHE cryptosystem.
pub trait CryptoSystem {
    /// The plaintext type for the FHE scheme.
    type Plaintext;
    /// The ciphertext type for the FHE scheme.
    type Ciphertext;

    /// The arity 1 operations that can be performed on the ciphertexts.
    ///
    /// This should be easily representable by a small enum.
    type Operation1: Arity1Operation;
    /// The arity 2 operations that can be performed on the ciphertexts.
    ///
    /// This should be easily representable by a small enum.
    type Operation2: Arity2Operation;

    /// Encrypts a plaintext into a ciphertext.
    fn cipher(&self, plaintext: &Self::Plaintext) -> Self::Ciphertext;
    /// Decrypts a ciphertext back into a plaintext.
    fn decipher(&self, ciphertext: &Self::Ciphertext) -> Self::Plaintext;

    #[must_use = "This method does not modify the input ciphertext."]
    /// Performs an operation on one ciphertext.
    fn operate1(&self, operation: Self::Operation1, lhs: &Self::Ciphertext) -> Self::Ciphertext;

    #[must_use = "This method does not modify the input ciphertexts."]
    /// Performs an operation on two ciphertexts.
    fn operate2(
        &self,
        operation: Self::Operation2,
        lhs: &Self::Ciphertext,
        rhs: &Self::Ciphertext,
    ) -> Self::Ciphertext;

    /// Performs an operation on one ciphertext in place.
    fn operate1_inplace(&self, operation: Self::Operation1, lhs: &mut Self::Ciphertext) {
        *lhs = self.operate1(operation, lhs);
    }

    /// Performs an operation on two ciphertexts in place.
    fn operate2_inplace(
        &self,
        operation: Self::Operation2,
        lhs: &mut Self::Ciphertext,
        rhs: &Self::Ciphertext,
    ) {
        *lhs = self.operate2(operation, lhs, rhs);
    }

    /// Relinearizes a ciphertext.
    fn relinearize(&self, ciphertext: &mut Self::Ciphertext);
}

#[allow(dead_code)]
/// Module to assert that usual usage of the API compiles.
mod private {
    use super::{Arity2Operation, CryptoSystem, Operation};

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
    impl Operation for Op {}
    impl Arity2Operation for Op {}

    impl CryptoSystem for TestCryptoSystem {
        type Plaintext = TestPlaintext;
        type Ciphertext = TestCiphertext;
        type Operation1 = ();
        type Operation2 = Op;

        fn cipher(&self, plaintext: &Self::Plaintext) -> Self::Ciphertext {
            TestCiphertext {
                data: plaintext.clone(),
            }
        }
        fn decipher(&self, ciphertext: &Self::Ciphertext) -> Self::Plaintext {
            ciphertext.data.clone()
        }

        fn operate1(
            &self,
            _operation: Self::Operation1,
            lhs: &Self::Ciphertext,
        ) -> Self::Ciphertext {
            TestCiphertext {
                data: lhs.data.clone(),
            }
        }

        fn operate2(
            &self,
            operation: Self::Operation2,
            lhs: &Self::Ciphertext,
            rhs: &Self::Ciphertext,
        ) -> Self::Ciphertext {
            match operation {
                Op::Add => {
                    let data = rhs.data.clone();
                    TestCiphertext { data }
                }
                Op::Mul => {
                    let data = lhs.data.clone();
                    TestCiphertext { data }
                }
            }
        }

        fn relinearize(&self, _ciphertext: &mut Self::Ciphertext) {}
    }

    // Assert that CryptoSystem is `dyn` compatible.
    fn any_operation<C, P>(
        _system: &dyn CryptoSystem<Ciphertext = C, Plaintext = P, Operation1 = (), Operation2 = Op>,
        other_param: u8,
    ) -> u8 {
        other_param
    }
}
