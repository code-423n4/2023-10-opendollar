# ✨ So you want to run an audit

This `README.md` contains a set of checklists for our audit collaboration.

Your audit will use two repos: 
- **an _audit_ repo** (this one), which is used for scoping your audit and for providing information to wardens
- **a _findings_ repo**, where issues are submitted (shared with you after the audit) 

Ultimately, when we launch the audit, this repo will be made public and will contain the smart contracts to be reviewed and all the information needed for audit participants. The findings repo will be made public after the audit report is published and your team has mitigated the identified issues.

Some of the checklists in this doc are for **C4 (🐺)** and some of them are for **you as the audit sponsor (⭐️)**.

### Installation and Compilation of Open Dollar contracts
Clone the `v1.5.5-audit` release of the OD [Contract repo](https://github.com/open-dollar/od-contracts/tree/v1.5.5-audit).

Install dependencies:
```bash
yarn
```
Compile the repo or run tests with foundry:
```bash
yarn build
```

## How Open Dollar works
Open Dollar is a GEB style stablecoin with CDPs. Our main changes, and what this audit covers, is the addition of new proxies and a Non-Fungible Vault (NFV) system where debt and collateral are owned by NFTs instead of being tied to accounts.

Some things we expect:
- Only the owner of a particular NFV can ever mint debt against the corresponding vault
- If NFVs are transfered, so too is the ownership and control of the vault
- Users must use the ODProxy to interact with their vaults

### Other docs
https://docs.opendollar.com/
https://www.opendollar.com/lite-paper
Diagram: https://www.figma.com/file/g7S9iJpEvWALcRN0uC9j08/Open-Dollar-Diagram-v1?type=design&node-id=0%3A1&mode=design&t=tR5NcHdXGTHys5US-1

### Files to focus on an approximate number of lines
34 AccountingEngine
21 CamelotRelayerChild
37 CamelotRelayerFactory
144 ODGovernor
106 CamelotRelayer
2 UniV3Relayer
36 ODProxy
14 ODSafeManager
1 SAFEHandler
200 Vault721
19 BasiActions
2 GlobalSettlementActions

---
# Repo setup

## ⭐️ Sponsor: Add code to this repo

There are also end to end tests and coverage tests that go through more files than are part of this audit.
Check out the [package.json](https://github.com/open-dollar/od-contracts/blob/v1.5.5-audit/package.json) file for a list of helpful commands.

- [x] Create a PR to this repo with the below changes:
- [x] Provide a self-contained repository with working commands that will build (at least) all in-scope contracts, and commands that will run tests producing gas reports for the relevant contracts.
- [x] Make sure your code is thoroughly commented using the [NatSpec format](https://docs.soliditylang.org/en/v0.5.10/natspec-format.html#natspec-format).
- [ ] Please have final versions of contracts and documentation added/updated in this repo **no less than 48 business hours prior to audit start time.**
- [x] Be prepared for a 🚨code freeze🚨 for the duration of the audit — important because it establishes a level playing field. We want to ensure everyone's looking at the same code, no matter when they look during the audit. (Note: this includes your own repo, since a PR can leak alpha to our wardens!)


---

## ⭐️ Sponsor: Edit this `README.md` file

- [ ] Modify the contents of this `README.md` file. Describe how your code is supposed to work with links to any relevent documentation and any other criteria/details that the C4 Wardens should keep in mind when reviewing. ([Here's a well-constructed example.](https://github.com/code-423n4/2022-08-foundation#readme))
- [ ] Review the Gas award pool amount. This can be adjusted up or down, based on your preference - just flag it for Code4rena staff so we can update the pool totals across all comms channels.
- [ ] Optional / nice to have: pre-record a high-level overview of your protocol (not just specific smart contract functions). This saves wardens a lot of time wading through documentation.
- [ ] [This checklist in Notion](https://code4rena.notion.site/Key-info-for-Code4rena-sponsors-f60764c4c4574bbf8e7a6dbd72cc49b4#0cafa01e6201462e9f78677a39e09746) provides some best practices for Code4rena audits.

## ⭐️ Sponsor: Final touches
- [ ] Review and confirm the details in the section titled "Scoping details" and alert Code4rena staff of any changes.
- [ ] Check that images and other files used in this README have been uploaded to the repo as a file and then linked in the README using absolute path (e.g. `https://github.com/code-423n4/yourrepo-url/filepath.png`)
- [ ] Ensure that *all* links and image/file paths in this README use absolute paths, not relative paths
- [ ] Check that all README information is in markdown format (HTML does not render on Code4rena.com)
- [ ] Remove any part of this template that's not relevant to the final version of the README (e.g. instructions in brackets and italic)
- [ ] Delete this checklist and all text above the line below when you're ready.

---

# Open Dollar audit details
- Total Prize Pool: $36,500 USDC (Notion: Total award pool)
  - HM awards: $24,750 USDC (Notion: HM (main) pool)
  - Analysis awards: $1,500 USDC (Notion: Analysis pool)
  - QA awards: $750 USDC (Notion: QA pool)
  - Bot Race awards: $2,250 USDC (Notion: Bot Race pool)
  - Gas awards: $750 USDC (Notion: Gas pool)
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

*Note for C4 wardens: Anything included in the automated findings output is considered a publicly known issue and is ineligible for awards.*

[ ⭐️ SPONSORS: Are there any known issues or risks deemed acceptable that shouldn't lead to a valid finding? If so, list them here. ]


# Overview

Open Dollar is a floating $1.00 pegged stablecoin backed by Liquid Staking Tokens with NFT controlled vaults. Built for Arbitrum. As the majority of the codebase is built with (the already audited) GEB framework, the focus of this one is to review the major changes Open Dollar has made to the framework around proxies, vaults, the safe manager, and 

### Non Fungible Vaults (NFV)
Unlike traditional Collateralized Debt Positions (CDPs), where ownership is tied to an account, NFVs uniquely associate ownership of the collateralized assets with NFTs. This approach creates a new primitive to build additional markets on and opportunities for users. Vaults can be sold through existing NFT marketplaces, automations can sell user vaults to arbitrageurs without having to pay liquidation penalties, and existing NFT infrastructure can be used in new ways. With a more capital efficient market for liquidatable vaults there is less risk when creating leveraged positions.

## Links

- **Previous audits:** N/A
- **Documentation:** https://docs.opendollar.com/
- **Website:** https://opendollar.com/
- **Twitter:** https://twitter.com/open_dollar
- **Discord:** https://discord.opendollar.com/


# Scope

[ ⭐️ SPONSORS: add scoping and technical details here ]

- [ ] In the table format shown below, provide the name of each contract and:
  - [ ] source lines of code (excluding blank lines and comments) in each *For line of code counts, we recommend running prettier with a 100-character line length, and using [cloc](https://github.com/AlDanial/cloc).* 
  - [ ] external contracts called in each
  - [ ] libraries used in each

*List all files in scope in the table below (along with hyperlinks) -- and feel free to add notes here to emphasize areas of focus.*

| Contract | SLOC | Purpose | Libraries used |  
| ----------- | ----------- | ----------- | ----------- |
| [contracts/folder/sample.sol](https://github.com/code-423n4/repo-name/blob/contracts/folder/sample.sol) | 123 | This contract does XYZ | [`@openzeppelin/*`](https://openzeppelin.com/contracts/) |

## Out of scope

*List any files/contracts that are out of scope for this audit.*

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
*List specific areas to address - see [this blog post](https://medium.com/code4rena/the-security-council-elections-within-the-arbitrum-dao-a-comprehensive-guide-aa6d001aae60#9adb) for an example*

## Main invariants
*Describe the project's main invariants (properties that should NEVER EVER be broken).*

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

*Provide every step required to build the project from a fresh git clone, as well as steps to run the tests with a gas report.* 

*Note: Many wardens run Slither as a first pass for testing.  Please document any known errors with no workaround.* 
