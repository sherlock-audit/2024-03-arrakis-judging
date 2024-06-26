Merry Yellow Osprey

medium

# HOT::setPriceBounds Malicious executor can brick vault withdrawals for at least 2 days

## Summary

The `HOT::setPriceBounds` function in the HOT contract allows an executor to set the AMM position's square-root upper and lower price bounds. A malicious executor can exploit this function to set the bounds very close together, causing an uint128 overflow when calculating liquidity. This results in disabling vault withdrawals, requiring a timelock of 2 days to set a new executor and re-enable vault withdrawals (by setting other price bounds).

## Vulnerability Detail

> Please note that this exploit currently works for all pools with at least one rebasing token.

The `HOT::setPriceBounds` function can be used by the executor to set the AMM position's square-root upper and lower price bounds: [HOT.sol#L520-L574](https://github.com/sherlock-audit/2024-03-arrakis/blob/64a7dc6ccb5de2824870474a9f35fd3386669e89/valantis-hot/src/HOT.sol#L520-L574).

A malicious executor can set `_sqrtPriceLowX96` and `_sqrtPriceHighX96` very close together. The following constraint is checked: `_sqrtPriceLowX96` < `sqrtPriceSpotX96` < `_sqrtPriceHighX96`, so they must be spaced by at least `2`: [HOTParams.sol#L177-L180](https://github.com/sherlock-audit/2024-03-arrakis/blob/64a7dc6ccb5de2824870474a9f35fd3386669e89/valantis-hot/src/libraries/HOTParams.sol#L177-L180).

If the difference is so small, while computing liquidity in `_calculateAMMLiquidity()`, the cast `toUint128` in [LiquidityAmounts.sol#L31](https://github.com/Uniswap/v3-periphery/blob/b325bb0905d922ae61fcc7df85ee802e8df5e96c/contracts/libraries/LiquidityAmounts.sol#L31) would revert even for small amounts.

> While setting price bounds the executor has to compute values close enough to the limit, but not overflowing, so the `_calculateAMMLiquidity()` at the end of `setPriceBounds()` succeeds: [HOT.sol#L571](https://github.com/sherlock-audit/2024-03-arrakis/blob/64a7dc6ccb5de2824870474a9f35fd3386669e89/valantis-hot/src/HOT.sol#L571).

As the call to `setPriceBounds` has succeeded, the executor can donate a small amount of rebasing token directly to the pool. As the reserve of rebasing token is the balance of this token, this makes all subsequent calls to `_calculateAMMLiquidity` revert.

As a result, all functions of HOT.sol become unusable, but most notably the `withdrawals` since this means that user funds are locked during that time. 

The executor has then to donate a small amount of the rebasing token to the pool.
This would result in the returned `uint128 liquidity` to overflow (even for reasonable values of `amount0` and `sqrtRatioAX96`): [LiquidityAmounts.sol#L31](https://github.com/Uniswap/v3-periphery/blob/b325bb0905d922ae61fcc7df85ee802e8df5e96c/contracts/libraries/LiquidityAmounts.sol#L31), [LiquidityAmounts.sol#L48](https://github.com/Uniswap/v3-periphery/blob/b325bb0905d922ae61fcc7df85ee802e8df5e96c/contracts/libraries/LiquidityAmounts.sol#L48), thus bricking vault withdrawals.

### Example:

Given:

- `sqrtRatioAX96` = 1 << 96
- `sqrtRatioBX96` = 1 << 96 + 2

It would overflow for a `amount` equal to 2 ** 33 (which is smaller than 1 ether == 10**18).

To unbrick the vault withdrawals, an owner would have to set a new executor who would set new price bounds, which means a timelock of 2 days has to pass.

## Impact

Vault withdrawals would be bricked for at least 2 days.

## Code Snippet

- [HOT.sol#L1015-L1024](https://github.com/sherlock-audit/2024-03-arrakis/blob/64a7dc6ccb5de2824870474a9f35fd3386669e89/valantis-hot/src/HOT.sol#L1015-L1024)

## Tool used

Manual Review

## Recommendation

Implement additional constraints on the `setPriceBounds` function to ensure that the `_sqrtPriceLowX96` and `_sqrtPriceHighX96` values cannot be set too close together, preventing potential overflow in the liquidity calculation.

> UniswapV3 naturally does not have this issue, since price ranges can only lie on ticks
