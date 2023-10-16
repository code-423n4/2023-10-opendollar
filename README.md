# Open Dollar audit details

- Total Prize Pool: $36,500 USDC (Notion: Total award pool)
  - HM awards: $24,750 USDC (Notion: HM (main) pool)
  - Analysis awards: $1,500 USDC (Notion: Analysis pool)
  - QA awards: $750 USDC (Notion: QA pool)
  - Bot Race awards: $2,250 USDC (Notion: Bot Race pool)
  - Gas awards: $250 USDC (Notion: Gas pool)
  - Judge awards: $3,600 USDC (Notion: Judge Fee)
  - Lookout awards: $2,400 USDC (Notion: Sum of Pre-sort fee + Pre-sort early bonus)
  - Scout awards: $500 USDC (Notion: Scout fee - but usually $500 USDC)
- Join [C4 Discord](https://discord.gg/code4rena) to register
- Submit findings [using the C4 form](https://code4rena.com/contests/2023-10-opendollar/submit)
- [Read our guidelines for more details](https://docs.code4rena.com/roles/wardens)
- Starts October 18, 2023 20:00 UTC
- Ends October 25, 2023 20:00 UTC

## Automated Findings / Publicly Known Issues

Automated findings output for the audit can be found [here](https://github.com/code-423n4/2023-10-opendollar/blob/main/bot-report.md) within 24 hours of audit opening.

_Note for C4 wardens: Anything included in the automated findings output is considered a publicly known issue and is ineligible for awards._

[ ⭐️ SPONSORS: Are there any known issues or risks deemed acceptable that shouldn't lead to a valid finding? If so, list them here. ]

# Overview

## About

Open Dollar is a floating $1.00 pegged stablecoin backed by Liquid Staking Tokens with NFT controlled vaults. Built specifically for Arbitrum. As the majority of the codebase is built with (the already audited) GEB framework, the focus of this one is to review the major changes Open Dollar has made to the framework around proxies, vaults, and the safe manager.

Open Dollar contracts are built using the [GEB](https://github.com/reflexer-labs/geb) framework, which uses Collateralized Debt Positions (CDPs) to allow accounts to generate debt against deposited collateral.

### Links

- **Previous audits:** N/A
- **Documentation:** https://docs.opendollar.com/
- **Website:** https://opendollar.com/
- **Twitter:** https://twitter.com/open_dollar
- **Discord:** https://discord.opendollar.com/

### Non Fungible Vaults (NFV)

> NOTE: The terms "CDP", "vault", and "safe" are used interchangeably here. They all refer to a collateralized debt-position in the protocol.

Our modifications to the existing GEB framework include the addition of a Non-Fungible Vault (NFV) feature, which ties CDP ownership to a specific NFT, rather than using the traditional account-based ownership for CDPs. This approach creates a new primitive to build additional markets on and opportunities for users. Vaults can be sold through existing NFT marketplaces, automations can sell user vaults to arbitrageurs without having to pay liquidation penalties, and existing NFT infrastructure can be used in new ways. With a more capital efficient market for liquidatable vaults there is less risk when creating leveraged positions.

Some things we expect:

- Only the owner of a particular NFV can ever mint debt against the corresponding vault
- If NFVs are transfered, so too is the ownership and control of the vault
- Users must use the ODProxy to interact with their vaults

### Resources

- Docs: https://docs.opendollar.com/
- Forge contract docs: https://contracts.opendollar.com
- Lite Paper: https://www.opendollar.com/lite-paper
- Protocol Diagram: https://www.figma.com/file/g7S9iJpEvWALcRN0uC9j08/Open-Dollar-Diagram-v1?type=design&node-id=0%3A1&mode=design&t=tR5NcHdXGTHys5US-1

### Files to focus on an approximate number of lines

The Following contracts are where we have created th NFV feature, and where we would like auditors to focus:

- [contracts/proxies/Vault721.sol](https://github.com/open-dollar/od-contracts/blob/v1.5.5-audit/src/contracts/proxies/Vault721.sol)
- [contracts/proxies/ODSafeManager.sol](https://github.com/open-dollar/od-contracts/blob/v1.5.5-audit/src/contracts/proxies/ODSafeManager.sol)
- [contracts/proxies/ODProxy.sol](https://github.com/open-dollar/od-contracts/blob/v1.5.5-audit/src/contracts/proxies/ODProxy.sol)
- [contracts/proxies/SAFEHandler.sol](https://github.com/open-dollar/od-contracts/blob/v1.5.5-audit/src/contracts/proxies/SAFEHandler.sol)

# Scope

IMPORTANT: The audit is scoped to the difference between `open-dollar/od-contracts` at [`v.1.5.5-audit`](https://github.com/open-dollar/od-contracts/releases/tag/v1.5.5) and `hai-on-op/core` at [`v0.1.2-rc.3`](https://github.com/hai-on-op/core/releases/tag/v0.1.2-rc.3). For convenience, we created a Pull Request showing these changes: https://github.com/open-dollar/od-contracts/pull/187

| Contract                                                                                                                                                         | SLOC | Purpose                                                                                                                                                                                                                                                                                                       |
| ---------------------------------------------------------------------------------------------------------------------------------------------------------------- | ---- | ------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------- |
| [contracts/AccountingEngine.sol](https://github.com/open-dollar/od-contracts/blob/v1.5.5-audit/src/contracts/AccountingEngine.sol)                               | 24   | The AccountingEngine receives both system surplus and system debt. It covers deficits via debt auctions and disposes off surplus via auctions or transfers (to extraSurplusReceiver)                                                                                                                          |
| [contracts/oracles/CamelotRelayer.sol](https://github.com/open-dollar/od-contracts/blob/v1.5.5-audit/src/contracts/oracles/CamelotRelayer.sol)                   | 47   | Used by Oracle Relayer to fetch the current market price of the system coin (OD) using a [Camelot](https://camelot.exchange) pool on Arbitrum network                                                                                                                                                         |
| [contracts/factories/CamelotRelayerFactory.sol](https://github.com/open-dollar/od-contracts/blob/v1.5.5-audit/src/contracts/factories/CamelotRelayerFactory.sol) | 17   |                                                                                                                                                                                                                                                                                                               |
| [contracts/factories/CamelotRelayerChild.sol](https://github.com/open-dollar/od-contracts/blob/v1.5.5-audit/src/contracts/factories/CamelotRelayerChild.sol)     | 8    |                                                                                                                                                                                                                                                                                                               |
| [contracts/oracles/UniV3Relayer.sol](https://github.com/open-dollar/od-contracts/blob/v1.5.5-audit/src/contracts/oracles/UniV3Relayer.sol)                       | 45   | Potential alternative option to using CamelotRelayer.sol. Used by Oracle Relayer to fetch the current market price of the system coin (OD) using a Uniswap V3 pool on Arbitrum network                                                                                                                        |
| [contracts/gov/ODGovernor.sol](https://github.com/open-dollar/od-contracts/blob/v1.5.5-audit/src/contracts/gov/ODGovernor.sol)                                   | 51   | The DAO-managed contract which can modify protocol parameters, eg. add new collateral types and change PID settings                                                                                                                                                                                           |
| [contracts/proxies/ODProxy.sol](https://github.com/open-dollar/od-contracts/blob/v1.5.5-audit/src/contracts/proxies/ODProxy.sol)                                 | 17   | A more restrictive version of the DSProxy used by Maker Protocol, where the owner cannot be changed. The purpose of this is to ensure that only the Vault721 contract has the ability to transfer a safe.                                                                                                     |
| [contracts/proxies/Vault721.sol](https://github.com/open-dollar/od-contracts/blob/v1.5.5-audit/src/contracts/proxies/Vault721.sol)                               | 84   | Serves as the Proxy Registry, Proxy Factory, and the ERC721 "Non-fungible Vault". Manages all safe ownership, transfers, and approvals via the ERC721 standard. Tracks proxy ownership and deploys new proxies- when called directly, or when a safe is transfered to an account which does not have a proxy. |
| [contracts/proxies/SAFEHandler.sol](https://github.com/open-dollar/od-contracts/blob/v1.5.5-audit/src/contracts/proxies/SAFEHandler.sol)                         | 5    | Grants permission to the ODSafeManager to make modifications to a safe. A new SAFEHandler is deployed for each safe, whose address serves as a unique identifier within the SAFEEngine.                                                                                                                       |
| [contracts/proxies/ODSafeManager.sol](https://github.com/open-dollar/od-contracts/blob/v1.5.5-audit/src/contracts/proxies/ODSafeManager.sol)                     | 138  | A more restrictive Safe Manager, which only allows the Vault721 contract to move a safe. Also calls Vault721 mint when a new safe is created.                                                                                                                                                                 |
| [contracts/proxies/actions/BasicActions.sol](https://github.com/open-dollar/od-contracts/blob/v1.5.5-audit/src/contracts/proxies/actions/BasicActions.sol)       | 144  |

Total: **580 lines**

## Out of scope

- `contracts/proxies/actions/GlobalSettlementActions.sol`
- `contracts/proxies/actions/RewardedActions.sol`
- `contracts/for-test/**/*.sol`
- `contracts/interfaces/**/*.sol`
- `contracts/libraries/**/*.sol`

## Installation and Compilation

Clone the OD [Contract repo](https://github.com/open-dollar/od-contracts/tree/v1.5.5-audit)

⚠️ IMPORTANT: Switch to the tag `v1.5.5-audit`. This is the specific release which is in-scope for the audit.

```bash
git checkout v1.5.5-audit
```

Install dependencies and compile

```bash
yarn

yarn build
```

Run tests with foundry:

```bash
yarn test
yarn test:e2e
```

Deploy using Anvil:

```bash
yarn deploy:anvil
```

# Additional Context

### Token Interactions

ERC-721 transfers, approvals, etc..

- [ ] Please list specific ERC721 that your protocol is anticipated to interact with.
- [ ] Which blockchains will this code be deployed to, and are considered in scope for this audit?
- [ ] Please list all trusted roles (e.g. operators, slashers, pausers, etc.), the privileges they hold, and any conditions under which privilege escalation is expected/allowable
- [ ] In the event of a DOS, could you outline a minimum duration after which you would consider a finding to be valid? This question is asked in the context of most systems' capacity to handle DoS attacks gracefully for a certain period.
- [ ] Is any part of your implementation intended to conform to any EIP's? If yes, please list the contracts in this format:
  - `Contract1`: Should comply with `ERC/EIPX`
  - `Contract2`: Should comply with `ERC/EIPY`

## Attack ideas (Where to look for bugs)

_List specific areas to address - see [this blog post](https://medium.com/code4rena/the-security-council-elections-within-the-arbitrum-dao-a-comprehensive-guide-aa6d001aae60#9adb) for an example_

## Main invariants

_Describe the project's main invariants (properties that should NEVER EVER be broken)._

## Scoping Details

[ ⭐️ SPONSORS: please confirm/edit the information below. ]

```
- If you have a public code repo, please share it here:
- How many contracts are in scope?:   13
- Total SLoC for these contracts?:  616
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

Accounts should not be able to get an NFV without a proxy being deployed for them.

# Tests

_Provide every step required to build the project from a fresh git clone, as well as steps to run the tests with a gas report._

_Note: Many wardens run Slither as a first pass for testing. Please document any known errors with no workaround._
