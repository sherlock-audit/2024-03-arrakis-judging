Merry Yellow Osprey

high

# ArrakisMetaVaultPrivate::fund No slippage control on private vault deposit can cause unlimited loss to owner

## Summary

An attacker can front-run a deposit transaction for an `ArrakisMetaVaultPrivate`, forcing the depositor to deposit in an unbalanced way. This increases liquidity around an unfavorable price, leading to a loss of one side of the provided liquidity.

## Vulnerability Detail

The owner of a private vault has full ownership of the shares of liquidity, so they are not even calculated explicitly. It is thus not possible to quantify the slippage control as a `minimum amount of shares minted`.  

However, by providing liquidity around an unfavorable price, the owner of the vault exposes one side of his liquidity to be backrun, as we will see in the concrete example below.

## Impact

An attacker can manipulate the price at which liquidity is added, leading to potential losses for the depositor.

### PoC

To simulate the scenario, we use the Python script from the [uniswapv3book](https://uniswapv3book.com/milestone_1/calculating-liquidity.html?highlight=calculate#liquidity-amount-calculation)

### Scenario

> **Initial Pool State**
> - DAI is trading **1 : 1** to USDC.
> - Price bounds set are: **[0.5, 1.5]**.
> - Reserves: 1000 USDC : 1000 DAI
> - Liquidity: 3414
> - Price: 1

**Steps**

1. Bob is a private vault owner and creates a tx to deposit **1000 USDC** : **1000 DAI**.
2. Alice front-runs Bob tx and swaps **1366 USDC** for **975 DAI** to decrease USDC price down to **0.51**.

> **Pool State After Alice Front-runs**
> 
> - Reserves: 2366 USDC : 25 DAI
> - Liquidity: 3553
> - Price: 0.51


3. Bob transaction goes through, he deposits **1000 USDC** : **1000 DAI**.

> **Pool State After Bob's Transaction**
> 
> - Reserves: 3366 USDC : 1025 DAI
> - Liquidity: 5765
> - Price: 0.51
> 

4. Alice back-runs Bob’s tx, and swaps `1647` DAI for `2307` USDC making a profit of **269 USDC**.

## Code Snippet

- [ValantisHOTModulePrivate.sol#L50](https://github.com/sherlock-audit/2024-03-arrakis/blob/64a7dc6ccb5de2824870474a9f35fd3386669e89/arrakis-modular/src/modules/ValantisHOTModulePrivate.sol#L50)

## Tool used

Manual Review

## Recommendation

Enable private vault depositors to control deviation parameters exposed in `HOT::depositLiquidity`:
`_expectedSqrtSpotPriceLowerX96` and
`_expectedSqrtSpotPriceUpperX96`

in [ArrakisMetaVaultPrivate.sol::fund](https://github.com/sherlock-audit/2024-03-arrakis/blob/main/arrakis-modular/src/ArrakisMetaVaultPrivate.sol#L52-L55) interface
