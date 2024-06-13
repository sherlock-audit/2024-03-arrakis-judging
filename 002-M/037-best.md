Curly Banana Sardine

medium

# Deposits/Withdrawals to/from Arrakis Vaults can be sandwiched due to no slippage checks in mint/burn functions

## Summary

There are two instances in which deposits/withdrawals can be sandwiched: 
- When depositing funds through the Router, there is slippage protection, but when directly minting through the vault, no slippage protection is present, making all of the deposits prone to being sandwiched.
- Same goes for withdrawing directly by burning the shares on the vault instead of going through the router's `removeLiquidity()`.
- The above, coupled with the fact that depositing and withdrawing in the same block is possible, makes these user paths prone to sandwich attacks.

## Vulnerability Detail

There are two paths that a user can take when depositing or withdrawing liquidity from the vault. The first one is going through the ArrakisPublicVaultRouter, and the second one is directly through the vault's `mint` and `burn` functions.

For the purpose of this example, we're going to examine withdrawals, but the same flow is present for deposits as well.

When withdrawing / removing liquidity via the router, `removeLiquidity()` subsequently calls `_removeLIquidity()` in which the slippage control logic is located:

```solidity
function _removeLiquidity(RemoveLiquidityData memory params_)
        internal
        returns (uint256 amount0, uint256 amount1)
    {
        (amount0, amount1) = IArrakisMetaVaultPublic(params_.vault)
            .burn(params_.burnAmount, params_.receiver);

        if (
            amount0 < params_.amount0Min
                || amount1 < params_.amount1Min
        ) {
            revert ReceivedBelowMinimum();
        }
    }
```
The problem is, that a user can call `burn()` directly on the public vault, without having to go through the router:

```solidity
function burn(
        uint256 shares_,
        address receiver_
    ) external returns (uint256 amount0, uint256 amount1) {
        if (shares_ == 0) revert BurnZero();
        uint256 supply = totalSupply();
        if (shares_ > supply) revert BurnOverflow();

        uint256 proportion = FullMath.mulDiv(shares_, BASE, supply);

        if (receiver_ == address(0)) revert AddressZero("Receiver");

        _burn(msg.sender, shares_);

        (amount0, amount1) = _withdraw(receiver_, proportion);

        emit LogBurn(shares_, receiver_, amount0, amount1);
    }

```
The function above will calculate the proportion based on the shares that we want to burn and the total supply.  The other problem is that the amount of the two tokens that we will receive is based on the supply of the pools:

```solidity

 function withdraw(
        address receiver_,
        uint256 proportion_
    )
        public
        virtual
        onlyMetaVault
        nonReentrant
        returns (uint256 amount0, uint256 amount1)
    {

        if (receiver_ == address(0)) revert AddressZero();
        if (proportion_ == 0) revert ProportionZero();
        if (proportion_ > BASE) revert ProportionGtBASE();

        {
            (uint256 _amt0, uint256 _amt1) = pool.getReserves();

            amount0 = FullMath.mulDiv(proportion_, _amt0, BASE);
            amount1 = FullMath.mulDiv(proportion_, _amt1, BASE);
        }

        if (amount0 == 0 && amount1 == 0) revert AmountsZeros();

        alm.withdrawLiquidity(amount0, amount1, receiver_, 0, 0);

        emit LogWithdraw(receiver_, proportion_, amount0, amount1);
    }

```

Since the amounts are based on the pool reserves, as well as the total supply of the share token, this can be easily manipulated and/or sandwiched in order to maliciously profit on the user's unprotected transactions.

Considering that deposits and withdrawals can be executed in the same block, plus flashloans can be utilized to aid in the sandwich attack.

## Impact
No slippage control allows for malicious bots/users to sandwich users who directly mint/burn tokens without going through the router.

## Code Snippet
https://github.com/sherlock-audit/2024-03-arrakis/blob/64a7dc6ccb5de2824870474a9f35fd3386669e89/arrakis-modular/src/ArrakisMetaVaultPublic.sol#L51-L74
https://github.com/sherlock-audit/2024-03-arrakis/blob/64a7dc6ccb5de2824870474a9f35fd3386669e89/arrakis-modular/src/ArrakisMetaVaultPublic.sol#L81-L98
## Tool used

Manual Review

## Recommendation
Make the mint/burn functions only callable from the router OR include slippage control arguments and checks in them as well.
