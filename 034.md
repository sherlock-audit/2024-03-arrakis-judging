Curly Banana Sardine

high

# Timelock roles/deployment gives the public vault owner full control over the vault

## Summary

The public vault owner role is restricted according to the documentation, even though it's wrapped in a Timelock, i.e. each action will have a 2 day delay before it's executed, there's no way to cancel the pending action and/or remove/assign roles in the Timelock. This gives a restricted role full control, including being able to whitelist new modules, etc. through which they can take advantage/exploit the vault.

## Vulnerability Detail
Since the Public vault owner is RESTRICTED according to the contest details, when a new public vault is deployed, the public vault owner's role is "wrapped" in a Timelock:

```solidity

  address timeLock;

        {
            address[] memory proposers = new address[](1);
            address[] memory executors = new address[](1);

            proposers[0] = owner_;
            executors[0] = owner_;

            // NOTE let's create3 timelock or remove create3 for public vault.
            timeLock = address(
                new TimeLock(2 days, proposers, executors, owner_)
            );
        }

        // #endregion create timeLock.

        {
            // #region get the creation code for TokenMetaVault.
            bytes memory creationCode = abi.encodePacked(
                ICreationCode(creationCodePublicVault).getCreationCode(
                ),
                _getPublicVaultConstructorPayload(
                    timeLock, token0_, token1_
                )
            );

            bytes32 salt = keccak256(abi.encode(msg.sender, salt_));

            // #endregion get the creation code for TokenMetaVault.
            vault = Create3.create3(salt, creationCode);
        }

```

After the timelock is created, the timelock is assigned as the owner of the public vault, which would mean that each action in the vault restricted to its owner will be subject to a timelock and a 2 day delay.

The problem is that when the Timelock is deployed, all roles within it: PROPOSER, EXECUTOR and ADMIN are given to the public vault owner. 

According to OZ's documentation, by default, the address that deployed the TimelockControler gets administration privileges over the timelock. This role grants the right to assign proposers, executors, and other administrators. But in this case, the address which deploys the timelock is the address of the ArrakisMetaVaultFactory, and there's no contract logic which can be leveraged to make calls to the Timelock functions. 

https://docs.openzeppelin.com/contracts/3.x/access-control#using_timelockcontroler

The Proposer role is in charge of queueing operations: this is the role the Governor instance should be granted, and it should likely be the only proposer in the system.

The Executor role is in charge of executing already available operations: we can assign this role to the special zero address to allow anyone to execute (if operations can be particularly time sensitive, the Governor should be made Executor instead).

Lastly, there is the Admin role, which can grant and revoke the two previous roles: this is a very sensitive role that will be granted automatically to the timelock itself, and optionally to a second account, which can be used for ease of setup but should promptly renounce the role.

To add to the above, the canceller role is also given to the proposer, which is the public vault owner. 

This will allow for the public vault owner to propose and execute any call that they want (with a 2 day delay), but with no option for the proposal to be cancelled within that delay. And they would also have full control over the assignment and revocation of the role rights/access. 

https://docs.openzeppelin.com/defender/v2/guide/timelock-roles

Some of the calls that can be made by the vault owner include:
- Whitelisting of modules
- Setup of new ALM

## Impact
Public vault owner can exploit the protocol in multiple ways due to improper Timelock setup

## Code Snippet
https://github.com/sherlock-audit/2024-03-arrakis/blob/64a7dc6ccb5de2824870474a9f35fd3386669e89/arrakis-modular/src/ArrakisMetaVaultFactory.sol#L139-L163

## Tool used

Manual Review

## Recommendation
Assign the admin and proposer/canceller role to the Guardian. 
