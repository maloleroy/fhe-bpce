//! `std` f64 utilities

#[must_use]
#[inline]
/// Fast exponentiation
pub fn powi(base: f64, exp: u16) -> f64 {
    libm::pow(base, f64::from(exp))
    // let mut result = 1.0;
    // while exp > 0 {
    //     if exp % 2 == 1 {
    //         result *= base;
    //     }
    //     base *= base;
    //     exp /= 2;
    // }
    // result
}

#[must_use]
/// Rounds an `f64` to the specified number of decimal places.
///
/// ## Warning
///
/// On very big numbers (or very high number of decimal places),
/// this function may return incorrect results.
pub fn round_to(x: f64, decimal_places: u16) -> f64 {
    let factor = powi(10.0, decimal_places);
    #[allow(clippy::cast_precision_loss)]
    (round(x * factor) as f64 / factor)
}

#[must_use]
#[inline]
/// Rounds a given value to the nearest integer
///
/// ## Warning
///
/// On very big numbers (> `i64::MAX`), this function may return incorrect results.
pub fn round(x: f64) -> i64 {
    #[allow(clippy::cast_possible_truncation)]
    (libm::round(x) as i64)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_round() {
        assert_eq!(round(1.5), 2);
        assert_eq!(round(1.4), 1);
        assert_eq!(round(-1.5), -2);
        assert_eq!(round(-1.4), -1);
    }

    #[test]
    fn test_round_to() {
        assert_eq!(round_to(1.23456789, 2), 1.23);
        assert_eq!(round_to(1.23456789, 4), 1.2346);
        assert_eq!(round_to(1.23456789, 6), 1.234568);
    }

    #[test]
    fn test_powi() {
        assert_eq!(powi(2.0, 3), 8.0);
        assert_eq!(powi(2.0, 4), 16.0);
        assert_eq!(powi(2.0, 5), 32.0);
    }
}
