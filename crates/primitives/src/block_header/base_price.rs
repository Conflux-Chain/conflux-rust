use super::BASE_PRICE_CHANGE_DENOMINATOR as DENOM;
use cfx_types::U256;
use log::warn;

pub fn compute_next_price(
    gas_target: U256, gas_actual: U256, last_base_price: U256,
    min_base_price: U256,
) -> U256 {
    let gas_actual = if gas_actual > gas_target * 2 {
        // This case may happen if block_gas_limit is an odd number.
        if gas_actual > gas_target * 2 + 1 {
            warn!("gas target is larger than expected");
        }
        gas_target * 2
    } else {
        gas_actual
    };

    let next_base_price = if gas_target.is_zero() || gas_target == gas_actual {
        last_base_price
    } else {
        let (gas_delta, delta_sign) = if gas_actual > gas_target {
            (gas_actual - gas_target, true)
        } else {
            (gas_target - gas_actual, false)
        };

        assert!(gas_delta <= gas_target);

        let mut price_delta = gas_delta * last_base_price / gas_target / DENOM;
        if price_delta.is_zero() {
            price_delta = U256::one()
        }

        if delta_sign {
            last_base_price + price_delta
        } else if !last_base_price.is_zero() {
            last_base_price - price_delta
        } else {
            U256::zero()
        }
    };

    next_base_price.max(min_base_price)
}

pub fn estimate_max_possible_gas(
    gas_target: U256, current_base_price: U256, last_base_price: U256,
) -> U256 {
    let (_, upper_boundary) = estimate_gas_used_boundary(
        gas_target,
        current_base_price,
        last_base_price,
    );
    match upper_boundary {
        None => gas_target * 2,
        Some(U256([0, 0, 0, 0])) => U256::zero(),
        Some(x) => x - 1,
    }
}

// Returns the outside boundary gas usage values that define the range
//
// The first item represents the maximum value that the next_price <
// current_base_price.
//
// The second item represents the minimum value that the
// next_price > current_base_price.
pub fn estimate_gas_used_boundary(
    gas_target: U256, current_base_price: U256, last_base_price: U256,
) -> (Option<U256>, Option<U256>) {
    if gas_target.is_zero() {
        return (None, Some(1.into()));
    }

    if last_base_price.is_zero() {
        return if current_base_price == U256::zero() {
            (None, Some(gas_target + 1))
        } else if current_base_price == U256::one() {
            (Some(gas_target), Some(gas_target * 2 + 1))
        } else {
            (Some(gas_target * 2), None)
        };
    }

    let max_price_delta = U256::max(U256::one(), last_base_price / DENOM);
    let upper_base_price = last_base_price + max_price_delta;
    let lower_base_price = last_base_price - max_price_delta;

    if current_base_price > upper_base_price {
        (Some(gas_target * 2), None)
    } else if current_base_price < lower_base_price {
        (None, Some(U256::zero()))
    } else if current_base_price == last_base_price {
        (Some(gas_target - 1), Some(gas_target + 1))
    } else {
        let (price_delta, delta_sign) = if current_base_price > last_base_price
        {
            (current_base_price - last_base_price, true)
        } else {
            (last_base_price - current_base_price, false)
        };

        assert!(!price_delta.is_zero());

        let lower_bound = if price_delta == U256::one() {
            U256::zero()
        } else {
            (price_delta * gas_target * DENOM - 1) / last_base_price
        };

        let upper_bound =
            ((price_delta + 1) * gas_target * DENOM + last_base_price - 1)
                / last_base_price;

        if delta_sign {
            (
                Some(gas_target + lower_bound),
                Some(U256::min(gas_target + upper_bound, gas_target * 2 + 1)),
            )
        } else {
            (
                // Underflow could happen
                gas_target.checked_sub(upper_bound),
                Some(gas_target - lower_bound),
            )
        }
    }
}

/// A helper function for `compute_next_price` which takes a typle as input
pub fn compute_next_price_tuple(x: (U256, U256, U256, U256)) -> U256 {
    compute_next_price(x.0, x.1, x.2, x.3)
}

#[cfg(test)]
mod tests {
    use crate::block_header::compute_next_price;

    use super::{estimate_gas_used_boundary, DENOM, U256};
    use itertools::Itertools;

    fn test_boundary(gas_target: usize, last_base_price: usize) {
        let max_price_delta = usize::max(1, last_base_price / DENOM);

        let start = last_base_price.saturating_sub(max_price_delta);
        let end = last_base_price.saturating_add(max_price_delta);

        let mut next_start = 0usize;

        for price in start..=end {
            let (lo, up) = estimate_gas_used_boundary(
                gas_target.into(),
                price.into(),
                last_base_price.into(),
            );
            let s = lo.map_or(0, |x| x.as_usize() + 1);
            let e = up.unwrap().as_usize();
            assert_eq!(s, next_start);
            next_start = e;
            for gas_used in s..e {
                let next_price = compute_next_price(
                    gas_target.into(),
                    gas_used.into(),
                    last_base_price.into(),
                    U256::zero(),
                )
                .as_usize();
                assert_eq!(next_price, price);
            }
        }
        assert_eq!(next_start, gas_target * 2 + 1);

        if start > 0 {
            let res = estimate_gas_used_boundary(
                gas_target.into(),
                (start - 1).into(),
                last_base_price.into(),
            );
            assert_eq!(res, (None, Some(U256::zero())))
        }

        let res = estimate_gas_used_boundary(
            gas_target.into(),
            (end + 1).into(),
            last_base_price.into(),
        );
        assert_eq!(res, (Some((gas_target * 2).into()), None));
    }

    #[test]
    fn test_gas_used_estimation() {
        let tasks = [1, 2, 3, 4, 5, 8, 10, 991, 1000, 1019, 9949, 10000, 10067]
            .into_iter()
            .cartesian_product([
                0, 1, 2, 3, 4, 5, 8, 10, 991, 1000, 1019, 9949, 10000, 10067,
            ]);

        for (gas_target, last_base_price) in tasks.into_iter() {
            test_boundary(gas_target, last_base_price);
        }
    }
}
