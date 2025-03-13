use crate::config::Config;
use fhe_core::{
    f64::round,
    pring::Polynomial,
    rand::distributions::{Distribution, Gaussian, Truncated, Uniform},
};
use zeroize::{Zeroize, ZeroizeOnDrop};

#[derive(Debug, Clone)]
/// Public key
pub struct PublicKey<const P: i64, const N: u32> {
    p0: Polynomial<P, N>,
    p1: Polynomial<P, N>,
}

impl<const P: i64, const N: u32> PublicKey<P, N> {
    #[must_use]
    #[inline]
    pub const fn p0(&self) -> &Polynomial<P, N> {
        &self.p0
    }

    #[must_use]
    #[inline]
    pub const fn p1(&self) -> &Polynomial<P, N> {
        &self.p1
    }
}

#[derive(Debug, Clone, Zeroize, ZeroizeOnDrop)]
/// Secret key
///
/// # Notes
///
/// The key is automatically zeroized when it goes out of scope
pub struct SecretKey<const P: i64, const N: u32> {
    p: Polynomial<P, N>,
}

impl<const P: i64, const N: u32> SecretKey<P, N> {
    #[must_use]
    #[inline]
    pub const fn p(&self) -> &Polynomial<P, N> {
        &self.p
    }
}

#[must_use]
/// Generate a fresh pair of keys
///
/// # Panics
///
/// Panics if randomness fails to be generated, or if any noise value is non-positive
pub fn generate_keys<const P: i64, const N: u32>(
    config: Config<P, N>,
) -> (PublicKey<P, N>, SecretKey<P, N>) {
    let skey = {
        let u = Uniform::<i64>::new(-1..=1);
        SecretKey {
            p: Polynomial::random(&u),
        }
    };

    let pkey = {
        #[allow(clippy::range_minus_one)]
        let u = Uniform::<i64>::new(0..=P - 1);

        let p1 = { Polynomial::random(&u) };

        let p0 = {
            let g = Gaussian::new(config.gdp().mu(), config.gdp().sigma());
            let beta = config.gdp().beta();
            let t = Truncated::new(g, -beta..=beta);

            let coeffs = skey
                .p
                .coeffs()
                .iter()
                .zip(p1.coeffs())
                .map(|(&sk, &r)| {
                    // Gaussian distribution bounded by beta
                    let e = t.sample().unwrap();
                    let r_128 = i128::from(r.as_i64());
                    let sk_128 = i128::from(sk.as_i64());
                    i64::try_from((-r_128 * sk_128).rem_euclid(P.into())).unwrap() + round(e)
                })
                .collect();
            Polynomial::new(coeffs)
        };

        PublicKey { p0, p1 }
    };

    (pkey, skey)
}
