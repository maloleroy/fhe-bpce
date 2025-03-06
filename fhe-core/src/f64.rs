#[must_use]
/// Fast exponentiation
pub fn powi(mut base: f64, mut exp: u16) -> f64 {
    let mut result = 1.0;
    while exp > 0 {
        if exp % 2 == 1 {
            result *= base;
        }
        base *= base;
        exp /= 2;
    }
    result
}

#[must_use]
/// Rounds an `f64` to the specified number of decimal places.
pub fn round_to(x: f64, decimal_places: u16) -> f64 {
    let factor = powi(10.0, decimal_places);
    round(x * factor) as f64 / factor
}

#[must_use]
/// Rounds a given value to the nearest integer
pub fn round(x: f64) -> i64 {
    let floor = x as i64;
    #[allow(clippy::cast_precision_loss)]
    let fract = x - floor as f64;

    if fract.abs() >= 0.5 {
        floor + floor.signum()
    } else {
        floor
    }
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
