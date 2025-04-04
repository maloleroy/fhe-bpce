use std::ffi::c_void;
use std::ptr::null_mut;
use std::sync::atomic::AtomicPtr;
use std::sync::atomic::Ordering;

use crate::bindgen;
use crate::error::Result;
use crate::try_seal;
use crate::{Ciphertext, Context, Plaintext, RelinearizationKey};

pub struct EvaluatorBase {
    handle: AtomicPtr<c_void>,
}

impl EvaluatorBase {
    /// Creates an Evaluator instance initialized with the specified Context.
    /// * `ctx` - The context.
    pub(crate) fn new(ctx: &Context) -> Result<Self> {
        let mut handle = null_mut();

        try_seal!(unsafe { bindgen::Evaluator_Create(ctx.get_handle(), &mut handle) })?;

        Ok(Self {
            handle: AtomicPtr::new(handle),
        })
    }

    /// Gets the handle to the internal SEAL object.
    pub(crate) unsafe fn get_handle(&self) -> *mut c_void {
        self.handle.load(Ordering::SeqCst)
    }

    /// Negates a ciphertext and stores the result inplace.
    pub(crate) fn negate_inplace(&self, a: &Ciphertext) -> Result<()> {
        try_seal!(unsafe {
            bindgen::Evaluator_Negate(self.get_handle(), a.get_handle(), a.get_handle())
        })?;

        Ok(())
    }

    pub(crate) fn negate(&self, a: &Ciphertext) -> Result<Ciphertext> {
        let out = Ciphertext::new()?;

        try_seal!(unsafe {
            bindgen::Evaluator_Negate(self.get_handle(), a.get_handle(), out.get_handle())
        })?;

        Ok(out)
    }

    pub(crate) fn add_inplace(&self, a: &Ciphertext, b: &Ciphertext) -> Result<()> {
        try_seal!(unsafe {
            bindgen::Evaluator_Add(
                self.get_handle(),
                a.get_handle(),
                b.get_handle(),
                a.get_handle(),
            )
        })?;

        Ok(())
    }

    pub(crate) fn add(&self, a: &Ciphertext, b: &Ciphertext) -> Result<Ciphertext> {
        let c = Ciphertext::new()?;

        try_seal!(unsafe {
            bindgen::Evaluator_Add(
                self.get_handle(),
                a.get_handle(),
                b.get_handle(),
                c.get_handle(),
            )
        })?;

        Ok(c)
    }

    pub(crate) fn add_many(&self, a: &[Ciphertext]) -> Result<Ciphertext> {
        let c = Ciphertext::new()?;

        let mut a_ptr = unsafe {
            a.iter()
                .map(|x| x.get_handle())
                .collect::<Vec<*mut c_void>>()
        };

        try_seal!(unsafe {
            bindgen::Evaluator_AddMany(
                self.get_handle(),
                u64::try_from(a_ptr.len()).unwrap(),
                a_ptr.as_mut_ptr(),
                c.get_handle(),
            )
        })?;

        Ok(c)
    }

    pub(crate) fn multiply_many(
        &self,
        a: &[Ciphertext],
        relin_keys: &RelinearizationKey,
    ) -> Result<Ciphertext> {
        let c = Ciphertext::new()?;

        let mut a_ptr = unsafe {
            a.iter()
                .map(|x| x.get_handle())
                .collect::<Vec<*mut c_void>>()
        };

        // let mem = MemoryPool::new()?;

        try_seal!(unsafe {
            bindgen::Evaluator_MultiplyMany(
                self.get_handle(),
                u64::try_from(a_ptr.len()).unwrap(),
                a_ptr.as_mut_ptr(),
                relin_keys.get_handle(),
                c.get_handle(),
                null_mut(),
                // mem.get_handle(),
            )
        })?;

        Ok(c)
    }

    pub(crate) fn sub_inplace(&self, a: &Ciphertext, b: &Ciphertext) -> Result<()> {
        try_seal!(unsafe {
            bindgen::Evaluator_Sub(
                self.get_handle(),
                a.get_handle(),
                b.get_handle(),
                a.get_handle(),
            )
        })?;

        Ok(())
    }

    pub(crate) fn sub(&self, a: &Ciphertext, b: &Ciphertext) -> Result<Ciphertext> {
        let c = Ciphertext::new()?;

        try_seal!(unsafe {
            bindgen::Evaluator_Sub(
                self.get_handle(),
                a.get_handle(),
                b.get_handle(),
                c.get_handle(),
            )
        })?;

        Ok(c)
    }

    pub(crate) fn multiply_inplace(&self, a: &Ciphertext, b: &Ciphertext) -> Result<()> {
        try_seal!(unsafe {
            bindgen::Evaluator_Multiply(
                self.get_handle(),
                a.get_handle(),
                b.get_handle(),
                a.get_handle(),
                null_mut(),
            )
        })?;

        Ok(())
    }

    pub(crate) fn multiply(&self, a: &Ciphertext, b: &Ciphertext) -> Result<Ciphertext> {
        let c = Ciphertext::new()?;

        try_seal!(unsafe {
            bindgen::Evaluator_Multiply(
                self.get_handle(),
                a.get_handle(),
                b.get_handle(),
                c.get_handle(),
                null_mut(),
            )
        })?;

        Ok(c)
    }

    pub(crate) fn square_inplace(&self, a: &Ciphertext) -> Result<()> {
        try_seal!(unsafe {
            bindgen::Evaluator_Square(
                self.get_handle(),
                a.get_handle(),
                a.get_handle(),
                null_mut(),
            )
        })?;

        Ok(())
    }

    pub(crate) fn square(&self, a: &Ciphertext) -> Result<Ciphertext> {
        let c = Ciphertext::new()?;

        try_seal!(unsafe {
            bindgen::Evaluator_Square(
                self.get_handle(),
                a.get_handle(),
                c.get_handle(),
                null_mut(),
            )
        })?;

        Ok(c)
    }

    pub(crate) fn mod_switch_to_next(&self, a: &Ciphertext) -> Result<Ciphertext> {
        let c = Ciphertext::new()?;

        try_seal!(unsafe {
            bindgen::Evaluator_ModSwitchToNext1(
                self.get_handle(),
                a.get_handle(),
                c.get_handle(),
                null_mut(),
            )
        })?;

        Ok(c)
    }

    pub(crate) fn mod_switch_to_next_inplace(&self, a: &Ciphertext) -> Result<()> {
        try_seal!(unsafe {
            bindgen::Evaluator_ModSwitchToNext1(
                self.get_handle(),
                a.get_handle(),
                a.get_handle(),
                null_mut(),
            )
        })?;

        Ok(())
    }

    pub(crate) fn mod_switch_to_next_plaintext(&self, a: &Plaintext) -> Result<Plaintext> {
        let p = Plaintext::new()?;

        try_seal!(unsafe {
            bindgen::Evaluator_ModSwitchToNext2(self.get_handle(), a.get_handle(), p.get_handle())
        })?;

        Ok(p)
    }

    pub(crate) fn mod_switch_to_next_inplace_plaintext(&self, a: &Plaintext) -> Result<()> {
        try_seal!(unsafe {
            bindgen::Evaluator_ModSwitchToNext2(self.get_handle(), a.get_handle(), a.get_handle())
        })?;

        Ok(())
    }

    pub(crate) fn exponentiate(
        &self,
        a: &Ciphertext,
        exponent: u64,
        relin_keys: &RelinearizationKey,
    ) -> Result<Ciphertext> {
        let c = Ciphertext::new()?;

        try_seal!(unsafe {
            bindgen::Evaluator_Exponentiate(
                self.get_handle(),
                a.get_handle(),
                exponent,
                relin_keys.get_handle(),
                c.get_handle(),
                null_mut(),
            )
        })?;

        Ok(c)
    }

    pub(crate) fn exponentiate_inplace(
        &self,
        a: &Ciphertext,
        exponent: u64,
        relin_keys: &RelinearizationKey,
    ) -> Result<()> {
        try_seal!(unsafe {
            bindgen::Evaluator_Exponentiate(
                self.get_handle(),
                a.get_handle(),
                exponent,
                relin_keys.get_handle(),
                a.get_handle(),
                null_mut(),
            )
        })?;

        Ok(())
    }

    pub(crate) fn add_plain(&self, a: &Ciphertext, b: &Plaintext) -> Result<Ciphertext> {
        let c = Ciphertext::new()?;

        try_seal!(unsafe {
            bindgen::Evaluator_AddPlain(
                self.get_handle(),
                a.get_handle(),
                b.get_handle(),
                c.get_handle(),
            )
        })?;

        Ok(c)
    }

    pub(crate) fn add_plain_inplace(&self, a: &Ciphertext, b: &Plaintext) -> Result<()> {
        try_seal!(unsafe {
            bindgen::Evaluator_AddPlain(
                self.get_handle(),
                a.get_handle(),
                b.get_handle(),
                a.get_handle(),
            )
        })?;

        Ok(())
    }

    pub(crate) fn sub_plain(&self, a: &Ciphertext, b: &Plaintext) -> Result<Ciphertext> {
        let c = Ciphertext::new()?;

        try_seal!(unsafe {
            bindgen::Evaluator_SubPlain(
                self.get_handle(),
                a.get_handle(),
                b.get_handle(),
                c.get_handle(),
            )
        })?;

        Ok(c)
    }

    pub(crate) fn sub_plain_inplace(&self, a: &Ciphertext, b: &Plaintext) -> Result<()> {
        try_seal!(unsafe {
            bindgen::Evaluator_SubPlain(
                self.get_handle(),
                a.get_handle(),
                b.get_handle(),
                a.get_handle(),
            )
        })?;

        Ok(())
    }

    pub(crate) fn multiply_plain(&self, a: &Ciphertext, b: &Plaintext) -> Result<Ciphertext> {
        let c = Ciphertext::new()?;

        try_seal!(unsafe {
            bindgen::Evaluator_MultiplyPlain(
                self.get_handle(),
                a.get_handle(),
                b.get_handle(),
                c.get_handle(),
                null_mut(),
            )
        })?;

        Ok(c)
    }

    pub(crate) fn multiply_plain_inplace(&self, a: &Ciphertext, b: &Plaintext) -> Result<()> {
        try_seal!(unsafe {
            bindgen::Evaluator_MultiplyPlain(
                self.get_handle(),
                a.get_handle(),
                b.get_handle(),
                a.get_handle(),
                null_mut(),
            )
        })?;

        Ok(())
    }

    // TODO: NTT transform.
}

impl Drop for EvaluatorBase {
    fn drop(&mut self) {
        try_seal!(unsafe { bindgen::Evaluator_Destroy(self.get_handle()) })
            .expect("Internal error in Evaluator::drop()");
    }
}
