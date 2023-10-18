![Open Dollar header](https://github.com/code-423n4/2023-10-opendollar/blob/main/open-dollar-header.png)

Open Dollar is a DeFi lending protocol that enables borrowing against liquid staking tokens while earning staking rewards and enabling liquidity via Non-Fungible Vaults (NFVs).

#### [Website](https://opendollar.com/) · [Twitter](https://twitter.com/open_dollar) · [Discord](https://discord.opendollar.com/)

# Open Dollar audit details

- Total Prize Pool: $36,500 USDC
  - HM awards: $24,750 USDC
  - Analysis awards: $1,500 USDC
  - QA awards: $750 USDC
  - Bot Race awards: $2,250 USDC
  - Gas awards: $250 USDC
  - Judge awards: $3,600 USDC
  - Lookout awards: $2,400 USDC
  - Scout awards: $500 USDC
- Join [C4 Discord](https://discord.gg/code4rena) to register
- Submit findings [using the C4 form](https://code4rena.com/contests/2023-10-open-dollar/submit)
- [Read our guidelines for more details](https://docs.code4rena.com/roles/wardens)
- Starts October 18, 2023 20:00 UTC
- Ends October 25, 2023 20:00 UTC

## Automated Findings / Publicly Known Issues

Automated findings output for the audit can be found [here](https://github.com/code-423n4/2023-10-opendollar/blob/main/bot-report.md) within 24 hours of audit opening.

_Note for C4 wardens: Anything included in the automated findings output is considered a publicly known issue and is ineligible for awards._

- Governor role can update the safeManager address in the NFV, which would break the protocol if ever set incorrectly or maliciously.

# Overview

Open Dollar is a floating $1.00 pegged stablecoin backed by Liquid Staking Tokens with NFT controlled vaults. Built specifically for Arbitrum. As the majority of the codebase is built with (the already audited) GEB framework, the focus of this audit is to review the major changes Open Dollar has made to the framework around proxies, vaults, and the safe manager.

Open Dollar contracts are built using the [GEB](https://github.com/reflexer-labs/geb) framework, which uses Collateralized Debt Positions (CDPs) to allow accounts to generate debt against deposited collateral.

### Non Fungible Vaults (NFV)

> NOTE: The terms "CDP", "vault", and "safe" are used interchangeably here. They all refer to a collateralized debt-position in the protocol.

Our modifications to the existing GEB framework include the addition of a Non-Fungible Vault (NFV) feature, which ties CDP ownership to a specific NFT, rather than using the traditional account-based ownership for CDPs. This approach creates a new defi primitive, enabling the development of novel marketplaces, and generating new opportunities for users. Vaults can be sold through existing NFT marketplaces, automations can sell user vaults to arbitrageurs without having to pay liquidation penalties, and existing NFT infrastructure can be used in new ways. With a more capital efficient market for liquidatable vaults there is less risk when creating leveraged positions.

Here's a quick intro video that might help you get started and understand some of the basics:
https://youtu.be/EjuvGs5SdAA

![Open Dollar  audit welcome video](https://github.com/code-423n4/2023-10-opendollar/blob/main/walkthrough-thumbnail.png)

### Docs & Resources

- Live testnet app: https://app.opendollar.com
- Npm packages: SDK [`@opendollar/sdk`](https://www.npmjs.com/package/@opendollar/sdk) and Contract ABIs [`@opendollar/abis`](https://www.npmjs.com/package/@opendollar/abis)
- Docs: https://docs.opendollar.com/
- Contracts docs: https://contracts.opendollar.com
- Lite Paper: https://www.opendollar.com/lite-paper
- Protocol Diagram: https://www.figma.com/file/g7S9iJpEvWALcRN0uC9j08/Open-Dollar-Diagram-v1?type=design&node-id=0%3A1&mode=design&t=tR5NcHdXGTHys5US-1

![Protocol Diagram](https://github.com/code-423n4/2023-10-opendollar/blob/main/figma-chart-preview.png)

# Scope

#### IMPORTANT: The audit scope is based on our [`v.1.5.5-audit release`](https://github.com/open-dollar/od-contracts/releases/tag/v1.5.5)

Our contracts are forked from `hai-on-op/core` at [`v0.1.2-rc.3`](https://github.com/hai-on-op/core/releases/tag/v0.1.2-rc.3). Since that code has already been audited, we suggest that Wardens focus on the changes we've made since then. For convenience, we created a Pull Request showing these changes here: https://github.com/open-dollar/od-contracts/pull/187

| Contract                                                                                                                                                         | SLOC | Purpose                                                                                                                                                                                                                                                                                                        |
| ---------------------------------------------------------------------------------------------------------------------------------------------------------------- | ---- | -------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------- |
| [contracts/AccountingEngine.sol](https://github.com/open-dollar/od-contracts/blob/v1.5.5-audit/src/contracts/AccountingEngine.sol)                               | 185  | The AccountingEngine receives both system surplus and system debt. It covers deficits via debt auctions and disposes of surplus via auctions or transfers (to extraSurplusReceiver)                                                                                                                            |
| [contracts/oracles/CamelotRelayer.sol](https://github.com/open-dollar/od-contracts/blob/v1.5.5-audit/src/contracts/oracles/CamelotRelayer.sol)                   | 62   | Used by Oracle Relayer to fetch the current market price of the system coin (OD) using a [Camelot](https://camelot.exchange) pool on Arbitrum network                                                                                                                                                          |
| [contracts/factories/CamelotRelayerFactory.sol](https://github.com/open-dollar/od-contracts/blob/v1.5.5-audit/src/contracts/factories/CamelotRelayerFactory.sol) | 23   |                                                                                                                                                                                                                                                                                                                |
| [contracts/factories/CamelotRelayerChild.sol](https://github.com/open-dollar/od-contracts/blob/v1.5.5-audit/src/contracts/factories/CamelotRelayerChild.sol)     | 11   |                                                                                                                                                                                                                                                                                                                |
| [contracts/oracles/UniV3Relayer.sol](https://github.com/open-dollar/od-contracts/blob/v1.5.5-audit/src/contracts/oracles/UniV3Relayer.sol)                       | 61   | Potential alternative option to using CamelotRelayer.sol. Used by Oracle Relayer to fetch the current market price of the system coin (OD) using a Uniswap V3 pool on Arbitrum network                                                                                                                         |
| [contracts/gov/ODGovernor.sol](https://github.com/open-dollar/od-contracts/blob/v1.5.5-audit/src/contracts/gov/ODGovernor.sol)                                   | 86   | The DAO-managed contract which can modify protocol parameters, eg. add new collateral types and change PID settings                                                                                                                                                                                            |
| [contracts/proxies/ODProxy.sol](https://github.com/open-dollar/od-contracts/blob/v1.5.5-audit/src/contracts/proxies/ODProxy.sol)                                 | 22   | A more restrictive version of the DSProxy used by Maker Protocol, where the owner cannot be changed. The purpose of this is to ensure that only the Vault721 contract has the ability to transfer a safe.                                                                                                      |
| [contracts/proxies/Vault721.sol](https://github.com/open-dollar/od-contracts/blob/v1.5.5-audit/src/contracts/proxies/Vault721.sol)                               | 106  | Serves as the Proxy Registry, Proxy Factory, and the ERC721 "Non-fungible Vault". Manages all safe ownership, transfers, and approvals via the ERC721 standard. Tracks proxy ownership and deploys new proxies- when called directly, or when a safe is transferred to an account which does not have a proxy. |
| [contracts/proxies/SAFEHandler.sol](https://github.com/open-dollar/od-contracts/blob/v1.5.5-audit/src/contracts/proxies/SAFEHandler.sol)                         | 7    | Grants permission to the ODSafeManager to make modifications to a safe. A new SAFEHandler is deployed for each safe, whose address serves as a unique identifier within the SAFEEngine.                                                                                                                        |
| [contracts/proxies/ODSafeManager.sol](https://github.com/open-dollar/od-contracts/blob/v1.5.5-audit/src/contracts/proxies/ODSafeManager.sol)                     | 167  | A more restrictive Safe Manager, which only allows the Vault721 contract to move a safe. Also calls Vault721 mint when a new safe is created.                                                                                                                                                                  |
| [contracts/proxies/actions/BasicActions.sol](https://github.com/open-dollar/od-contracts/blob/v1.5.5-audit/src/contracts/proxies/actions/BasicActions.sol)       | 268  |

Total: **998 lines**

## Files to focus on

The Following contracts are where we have implemented the new NFV feature, and where we would like auditors to focus their attention:

- [contracts/proxies/Vault721.sol](https://github.com/open-dollar/od-contracts/blob/v1.5.5-audit/src/contracts/proxies/Vault721.sol)
- [contracts/proxies/ODSafeManager.sol](https://github.com/open-dollar/od-contracts/blob/v1.5.5-audit/src/contracts/proxies/ODSafeManager.sol)
- [contracts/proxies/ODProxy.sol](https://github.com/open-dollar/od-contracts/blob/v1.5.5-audit/src/contracts/proxies/ODProxy.sol)
- [contracts/proxies/SAFEHandler.sol](https://github.com/open-dollar/od-contracts/blob/v1.5.5-audit/src/contracts/proxies/SAFEHandler.sol)

## Libraries

All Open Zeppelin imports are from `@openzeppelin/contracts` [v4.8.2](https://github.com/OpenZeppelin/openzeppelin-contracts/tree/release-v4.8)

#### Vault721.sol

- openzeppelin ERC721
- openzeppelin ERC721Enumerable

#### ODSafeManager.sol

- openzeppelin EnumerableSet

#### ODGovernor.sol

- IVotes from @openzeppelin/governance/utils/IVotes
- IERC165 from @openzeppelin/utils/introspection/IERC165
- IGovernor from @openzeppelin/governance/IGovernor
- TimelockController @openzeppelin/governance/TimelockController
- Governor from @openzeppelin/governance/Governor
- GovernorSettings from @openzeppelin/governance/extensions/GovernorSettings
- GovernorCompatibilityBravo from openzeppelin/governance/compatibility/GovernorCompatibilityBravo.sol
- GovernorVotes from @openzeppelin/governance/extensions/GovernorVotes
- GovernorVotesQuorumFraction from '@openzeppelin/governance/extensions/GovernorVotesQuorumFraction
- GovernorTimelockControl from @openzeppelin/governance/extensions/GovernorTimelockControl

#### CamelotRelayer.sol

- openzeppelin IERC20Metadata
- OracleLibrary from @uniswap/v3-periphery: https://github.com/Uniswap/v3-periphery

#### CamelotRelayerFactory.sol

- EnumerableSet from openzeppelin

## Out of scope

- `contracts/proxies/actions/GlobalSettlementActions.sol`
- `contracts/proxies/actions/RewardedActions.sol`
- `contracts/for-test/**/*.sol`
- `contracts/interfaces/**/*.sol`
- `contracts/libraries/**/*.sol`
- Tests, scripts, and anything not in `src/contracts`

# Additional Context

### Token Interactions

- ODGovernor should count ERC-20 delegated votes as expected
- Vault721 should adhere to ERC-721 standard, and token transfers should also transfer the safe ownership as expected

### Blockchain network

Protocol will be deployed to Arbitrum One (ID: 42161)

### Trusted roles

#### ODGovernor

- In Vault721, can call `updateNftRenderer()` to modify the contract used in creating the SVG image for the token URI
- In Vault721, can call `setSafeManager()` to modify the address for the `ODSafeManager`.

### Standard Implementation

- `Vault721`: Should comply with `ERC721`

## Attack ideas (Where to look for bugs)

1. Create a smart contract that is able to receive an NFV without a proxy being deployed for it, eg. by calling transfer in a constructor, or other means.
2. Mint debt against an NFV in the same transaction that it is transferred to someone else, allowing the attacker to mislead an NFV buyer about the value of the NFV being bought.
3. Use reentrancy to trick the SafeManager into allowing your modifications to a safe you don't own.
4. Break access-control by calling SafeManager directly without using the ODproxy.

## Main invariants

1. Only the owner of a particular NFV can ever mint debt against the corresponding safe.
2. If the ERC-721 token from Vault721 is transferred, so too is the ownership and control of the corresponding safe. Meaning only the owner can transfer it or mint debt against it.
3. Users must exclusively use the ODProxy to interact with their safes.
4. When a fresh account, which has never interacted with the protocol, receives an NFV via ERC721 transfer, an ODProxy should always be deployed for them.
5. ODProxy cannot be transferred or change owner.
6. There is 1 safe for each ERC-721 token, and the safe ID always corresponds to the NFT ID.
7. Proper Access Control ensures that transferring safes can only be performed using the Vault721 .
8. A user only ever has a single ODProxy deployed for them.
9. Only the governor role can set an external Renderer contract for the NFV's token URI.

## Scoping Details

```
- If you have a public code repo, please share it here:
- How many contracts are in scope?:   11
- Total SLoC for these contracts?:  998
- How many external imports are there?: 3
- How many separate interfaces and struct definitions are there for the contracts within scope?:  13
- Does most of your code generally use composition or inheritance?:  Composition
- How many external calls?:  0
- What is the overall line coverage percentage provided by your tests?: 95%
- Is this an upgrade of an existing system?: True;
  - 1. Created a custom proxy (ODProxy) for user interactions
  - 2. The Proxy Registry is now an NFT Vault (Vault721.sol)
  - 3. Users can interact with their safe via NFT
  - 4. Safe transfers now also transfer the ownership NFT and vice versa
  - 5. Naming has changed and custom logic around using the NFT has been added
- Check all that apply (e.g. timelock, NFT, AMM, ERC20, rollups, etc.): NFT, Uses L2, ERC-20 Token
- Is there a need to understand a separate part of the codebase / get context in order to audit this part of the protocol?:  False
- Please describe required context:   n/a
- Does it use an oracle?:  No
- Describe any novel or unique curve logic or mathematical models your code uses:
- Is this either a fork of or an alternate implementation of another project?:   True
- Does it use a side-chain?: Yes, Arbitrum
- Describe any specific areas you would like addressed:
```

# Tests

## Setup

Clone [`open-dollar/od-contract`](https://github.com/open-dollar/od-contracts)

```bash
git clone git@github.com:open-dollar/od-contracts.git
```

⚠️ IMPORTANT: Switch to the tag `v1.5.5-audit`. This is the specific release which is in-scope for the audit.

```bash
git checkout v1.5.5-audit
```

Install dependencies and compile

```bash
yarn

yarn build
```

Setup the environment:

```bash
cp .env.example .env
```

The only required variables for running tests are:

```
MAINNET_RPC=https://arbitrum-one.publicnode.com
GOERLI_RPC=https://arbitrum-goerli.publicnode.com
```

## Forge tests

Run tests with foundry:

```bash
yarn test
yarn test:e2e
```

> We expect 22 failing tests:
>
> - 1 failing test in test/nft/anvil/NFT.t.sol:NFTAnvil
> - 1 failing test in test/nft/anvil/TransferOwnership.t.sol:TransferOwnershipAnvil
> - 1 failing test in test/nft/goerli/NFT.t.sol:NFTGoerli
> - 1 failing test in test/nft/goerli/governor/GovActions.t.sol:GovActions
> - 5 failing tests in test/single/AccountingEngine.t.sol:SingleAccountingEngineTest
> - 1 failing test in test/single/SAFEEngine.t.sol:SingleLiquidationTest
> - 8 failing tests in test/unit/AccountingEngine.t.sol:Unit_AccountingEngine_AuctionSurplus
> - 4 failing tests in test/unit/oracles/UniV3RelayerFactory.t.sol::Unit_UniV3RelayerFactory_DeployUniV3Relayer

Deploy to local Anvil environment:

```bash
yarn deploy:anvil
```

## Slither

```bash
slither .
```

> We are aware of errors `ContractSolcParsing`, `SlitherSolcParsing`, etc when running slither. See output here: https://gist.github.com/pi0neerpat/0984343ca5c0f784f3387f1435af4a5e

# Other Tips and Tricks 🍬

Here's some helpful tips for using the od-contracts repo effectively.

1. Understand that the changes we have made are isolated from the rest of the internal accounting and SAFE engine. You do not need a full understanding of the SAFE engine to contribute to this audit. You may find it helpful to think of the SAFE engine as a black box.

2. [Units](https://docs.opendollar.com/contract-translation/naming-transition). GEB uses different units for various levels of precision.

| Unit | Meaning                           |
| :--- | :-------------------------------- |
| WAD  | Number with 18 decimals \(10^18\) |
| RAY  | Number with 27 decimals \(10^27\) |
| RAD  | Number with 45 decimals \(10^45\) |

3. Most of the tests in our repo are for contracts in other parts of the system that are out of scope for this audit. But they might still be helpful in understanding how users are expected to interact with the contracts or coming up with ideas or patterns for potential attacks.

4. The primary entry point for users into the rest of the protocol is through their ODProxy which is used to execute proxy actions. Except when the user does not have a proxy and is making one for the first time.

5. We're on your team! If you have questions, ask the Open Dollar devs for help. Seriously, don't be a stranger.
