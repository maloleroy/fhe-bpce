//! This module defines the core API of FHE cryptosystems.

/// A handle to a value.
///
/// A very good example of this is `Box`, which is a handle to a value on the heap.
/// You can also use other types of smart pointers, or even raw pointers if you're feeling adventurous.
pub trait Handle: core::ops::Deref<Target = Self::Inner> {
    type Inner;
    fn from_raw_inner(inner: Self::Inner) -> Self;
}

#[cfg(feature = "alloc")]
impl<T> Handle for alloc::boxed::Box<T> {
    type Inner = T;
    fn from_raw_inner(inner: T) -> Self {
        Self::new(inner)
    }
}

/// A trait that defines the core API of a FHE cryptosystem.
pub trait CryptoSystem {
    /// A wrapper around a ciphertext that acts as a handle.
    /// This is very similair to a smart pointer.
    ///
    /// This is usually a `Box`.
    type CiphertextHandle: Handle<Inner = Self::Ciphertext>;

    /// A wrapper around a plaintext that acts as a handle.
    /// This is very similair to a smart pointer.
    ///
    /// This is usually a `Box`.
    type PlaintextHandle: Handle<Inner = Self::Plaintext>;

    /// The plaintext type for the FHE scheme.
    type Plaintext;
    /// The ciphertext type for the FHE scheme.
    type Ciphertext;

    /// The operations that can be performed on the ciphertexts.
    ///
    /// This should be easily representable by a small enum.
    type Operation;

    /// Encrypts a plaintext into a ciphertext.
    fn cipher(&self, plaintext: &Self::Plaintext) -> Self::CiphertextHandle;
    /// Decrypts a ciphertext back into a plaintext.
    fn decipher(&self, ciphertext: &Self::Ciphertext) -> Self::PlaintextHandle;

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
    ) -> Self::CiphertextHandle;
}

#[cfg(any(feature = "alloc", test))]
#[allow(dead_code)]
/// Module to assert that usual usage of the API compiles.
mod private {
    use super::*;
    use alloc::boxed::Box;

    #[derive(Clone)]
    struct TestPlaintext {}
    struct TestCiphertext {
        // Absolutely not secure system, just for testing purposes.
        data: TestPlaintext,
    }

    struct TestCryptoSystem {}

    #[derive(Clone, Copy, Debug)]
    #[allow(dead_code)]
    enum Op {
        Add,
        Mul,
    }

    impl CryptoSystem for TestCryptoSystem {
        type CiphertextHandle = Box<Self::Ciphertext>;
        type PlaintextHandle = Box<Self::Plaintext>;
        type Plaintext = TestPlaintext;
        type Ciphertext = TestCiphertext;
        type Operation = Op;

        fn cipher(&self, plaintext: &Self::Plaintext) -> Self::CiphertextHandle {
            Box::new(TestCiphertext {
                data: plaintext.clone(),
            })
        }
        fn decipher(&self, ciphertext: &Self::Ciphertext) -> Self::PlaintextHandle {
            Box::new(ciphertext.data.clone())
        }

        fn operate(
            &self,
            operation: Self::Operation,
            lhs: &Self::Ciphertext,
            rhs: Option<&Self::Ciphertext>,
        ) -> Self::CiphertextHandle {
            match operation {
                Op::Add => {
                    assert!(rhs.is_some(), "Addition requires two operands.");
                    let data = rhs.unwrap().data.clone();
                    Box::new(TestCiphertext { data })
                }
                Op::Mul => {
                    assert!(rhs.is_some(), "Multiplication requires two operands.");
                    let data = lhs.data.clone();
                    Box::new(TestCiphertext { data })
                }
            }
        }
    }

    // Assert that CryptoSystem is `dyn` compatible.
    fn any_operation<C, P>(
        _system: &dyn CryptoSystem<
            Ciphertext = C,
            Plaintext = P,
            CiphertextHandle = Box<C>,
            PlaintextHandle = Box<P>,
            Operation = (),
        >,
        other_param: u8,
    ) -> u8 {
        other_param
    }
}
