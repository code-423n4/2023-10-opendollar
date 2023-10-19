## Summary

### Low Risk Issues

| |Issue|Instances|
|-|:-|:-:|
| [[L&#x2011;1](#l1-vulnerable-versions-of-packages-are-being-used)] | Vulnerable versions of packages are being used | 2 | 
| [[L&#x2011;2](#l2-missing-checks-for-address-0-when-assigning-values-to-address-state-variables)] | Missing checks for `address(0)` when assigning values to address state variables | 2 | 
| [[L&#x2011;3](#l3-for-loops-in-public-or-external-functions-should-be-avoided-due-to-high-gas-costs-and-possible-dos)] | For loops in public or external functions should be avoided due to high gas costs and possible DOS | 1 | 
| [[L&#x2011;4](#l4-decimals-is-not-a-part-of-the-erc-20-standard)] | `decimals()` is not a part of the ERC-20 standard | 4 | 
| [[L&#x2011;5](#l5-loss-of-precision)] | Loss of precision | 2 | 
| [[L&#x2011;6](#l6-nft-doesn-t-handle-hard-forks)] | NFT doesn't handle hard forks | 1 | 
| [[L&#x2011;7](#l7-operations-such-as-the-changing-of-the-owner-should-be-behind-a-timelock)] | Operations such as the changing of the owner should be behind a timelock | 3 | 
| [[L&#x2011;8](#l8-consider-using-openzeppelin-s-safecast-library-to-prevent-unexpected-overflows-when-casting-from-various-type-int-uint-values)] | Consider using OpenZeppelin’s SafeCast library to prevent unexpected overflows when casting from various type int/uint values | 2 | 
| [[L&#x2011;9](#l9-setters-should-have-initial-value-check)] | Setters should have initial value check | 4 | 
| [[L&#x2011;10](#l10-symbol-is-not-a-part-of-the-erc-20-standard)] | `symbol()` is not a part of the ERC-20 standard | 4 | 
| [[L&#x2011;11](#l11-consider-using-descriptive-constant-s-when-passing-zero-as-a-function-argument)] | Consider using descriptive `constant`s when passing zero as a function argument | 6 | 
| [[L&#x2011;12](#l12-prevent-re-setting-a-state-variable-with-the-same-value)] | prevent re-setting a state variable with the same value | 6 | 

Total: 37 instances over 12 issues

### Non-critical Issues

| |Issue|Instances|
|-|:-|:-:|
| [[NC&#x2011;1](#nc1-public-variable-declarations-should-have-natspec-descriptions)] | Public `variable` declarations should have NatSpec descriptions | 10 | 
| [[NC&#x2011;2](#nc2-large-or-complicated-code-bases-should-implement-invariant-tests)] | Large or complicated code bases should implement invariant tests | 1 | 
| [[NC&#x2011;3](#nc3-contract-declarations-should-have-natspec-author-annotations)] | Contract declarations should have NatSpec `@author` annotations | 11 | 
| [[NC&#x2011;4](#nc4-common-functions-should-be-refactored-to-a-common-base-contract)] | Common functions should be refactored to a common base contract | 1 | 
| [[NC&#x2011;5](#nc5-constants-in-comparisons-should-appear-on-the-left-side)] | Constants in comparisons should appear on the left side | 19 | 
| [[NC&#x2011;6](#nc6-natspec-documentation-for-contract-is-missing)] | NatSpec documentation for `contract` is missing | 4 | 
| [[NC&#x2011;7](#nc7-control-structures-do-not-follow-the-solidity-style-guide)] | Control structures do not follow the Solidity Style Guide | 24 | 
| [[NC&#x2011;8](#nc8-custom-error-has-no-error-details)] | Custom error has no error details | 5 | 
| [[NC&#x2011;9](#nc9-consider-using-delete-rather-than-assigning-zero-to-clear-values)] | Consider using `delete` rather than assigning `zero` to clear values | 3 | 
| [[NC&#x2011;10](#nc10-dependence-on-external-protocols)] | Dependence on external protocols | 8 | 
| [[NC&#x2011;11](#nc11-empty-bytes-check-is-missing)] | Empty bytes check is missing | 14 | 
| [[NC&#x2011;12](#nc12-events-are-missing-sender-information)] | Events are missing sender information | 8 | 
| [[NC&#x2011;13](#nc13-events-may-be-emitted-out-of-order-due-to-reentrancy)] | Events may be emitted out of order due to reentrancy | 15 | 
| [[NC&#x2011;14](#nc14-it-is-standard-for-all-external-and-public-functions-to-be-override-from-an-interface)] | It is standard for all external and public functions to be override from an interface | 55 | 
| [[NC&#x2011;15](#nc15-natspec-documentation-for-function-is-missing)] | NatSpec documentation for `function` is missing | 12 | 
| [[NC&#x2011;16](#nc16-function-ordering-does-not-follow-the-solidity-style-guide)] | Function ordering does not follow the Solidity style guide | 3 | 
| [[NC&#x2011;17](#nc17-duplicated-require-revert-checks-should-be-refactored-to-a-modifier-or-function)] | Duplicated `require()`/`revert()` checks should be refactored to a modifier or function | 2 | 
| [[NC&#x2011;18](#nc18-some-if-statement-can-be-converted-to-a-ternary)] | Some if-statement can be converted to a ternary | 1 | 
| [[NC&#x2011;19](#nc19-contract-implements-interface-without-extending-the-interface)] | Contract implements interface without extending the interface | 8 | 
| [[NC&#x2011;20](#nc20-imports-could-be-organized-more-systematically)] | Imports could be organized more systematically | 3 | 
| [[NC&#x2011;21](#nc21-inconsistent-usage-of-require-error)] | Inconsistent usage of `require`/`error` | 5 | 
| [[NC&#x2011;22](#nc22-long-lines-of-code)] | Long lines of code | 5 | 
| [[NC&#x2011;23](#nc23-missing-event-and-or-timelock-for-critical-parameter-change)] | Missing event and or timelock for critical parameter change | 1 | 
| [[NC&#x2011;24](#nc24-file-is-missing-natspec)] | File is missing NatSpec | 1 | 
| [[NC&#x2011;25](#nc25-some-error-strings-are-not-descriptive)] | Some error strings are not descriptive | 2 | 
| [[NC&#x2011;26](#nc26-public-state-variables-shouldn-t-have-a-preceding-in-their-name)] | Public state variables shouldn't have a preceding _ in their name | 1 | 
| [[NC&#x2011;27](#nc27-override-function-arguments-that-are-unused-should-have-the-variable-name-removed-or-commented-out-to-avoid-compiler-warnings)] | `override` function arguments that are unused should have the variable name removed or commented out to avoid compiler warnings | 1 | 
| [[NC&#x2011;28](#nc28-use-of-override-is-unnecessary)] | Use of `override` is unnecessary | 4 | 
| [[NC&#x2011;29](#nc29-natspec-param-is-missing)] | NatSpec `@param` is missing | 34 | 
| [[NC&#x2011;30](#nc30-public-functions-not-called-by-the-contract-should-be-declared-external-instead)] | `public` functions not called by the contract should be declared `external` instead | 1 | 
| [[NC&#x2011;31](#nc31-redundant-inheritance-specifier)] | Redundant inheritance specifier | 5 | 
| [[NC&#x2011;32](#nc32-require-revert-statements-should-have-descriptive-reason-strings)] | `require()` / `revert()` statements should have descriptive reason strings | 1 | 
| [[NC&#x2011;33](#nc33-natspec-return-argument-is-missing)] | NatSpec `@return` argument is missing | 21 | 
| [[NC&#x2011;34](#nc34-polymorphic-functions-make-security-audits-more-time-consuming-and-error-prone)] | Polymorphic functions make security audits more time-consuming and error-prone | 3 | 
| [[NC&#x2011;35](#nc35-consider-moving-msg-sender-checks-to-a-common-authorization-modifier)] | Consider moving `msg.sender` checks to a common authorization `modifier` | 2 | 
| [[NC&#x2011;36](#nc36-imports-should-use-double-quotes-rather-than-single-quotes)] | Imports should use double quotes rather than single quotes | 65 | 
| [[NC&#x2011;37](#nc37-state-variables-should-include-comments)] | State variables should include comments | 14 | 
| [[NC&#x2011;38](#nc38-strings-should-use-double-quotes-rather-than-single-quotes)] | Strings should use double quotes rather than single quotes | 23 | 
| [[NC&#x2011;39](#nc39-contracts-should-have-full-test-coverage)] | Contracts should have full test coverage | 1 | 
| [[NC&#x2011;40](#nc40-contract-declarations-should-have-natspec-title-annotations)] | Contract declarations should have NatSpec `@title` annotations | 4 | 
| [[NC&#x2011;41](#nc41-top-level-pragma-declarations-should-be-separated-by-two-blank-lines)] | Top level pragma declarations should be separated by two blank lines | 12 | 
| [[NC&#x2011;42](#nc42-critical-functions-should-be-a-two-step-procedure)] | Critical functions should be a two step procedure | 5 | 
| [[NC&#x2011;43](#nc43-event-is-missing-indexed-fields)] | Event is missing `indexed` fields | 1 | 
| [[NC&#x2011;44](#nc44-unused-import)] | Unused Import | 10 | 
| [[NC&#x2011;45](#nc45-unused-parameter)] | Unused parameter | 1 | 
| [[NC&#x2011;46](#nc46-use-bytes-concat-on-bytes-instead-of-abi-encodepacked-for-clearer-semantic-meaning)] | Use `bytes.concat()` on bytes instead of `abi.encodePacked()` for clearer semantic meaning | 2 | 
| [[NC&#x2011;47](#nc47-use-string-concat-on-strings-instead-of-abi-encodepacked-for-clearer-semantic-meaning)] | Use `string.concat()` on strings instead of `abi.encodePacked()` for clearer semantic meaning | 2 | 
| [[NC&#x2011;48](#nc48-constants-should-be-defined-rather-than-using-magic-numbers)] | Constants should be defined rather than using magic numbers | 8 | 
| [[NC&#x2011;49](#nc49-use-the-latest-solidity-prior-to-0-8-20-if-on-l2s-for-deployment)] | Use the latest solidity (prior to 0.8.20 if on L2s) for deployment | 11 | 
| [[NC&#x2011;50](#nc50-use-a-single-file-for-system-wide-constants)] | Use a single file for system wide constants | 3 | 
| [[NC&#x2011;51](#nc51-consider-using-smtchecker)] | Consider using SMTChecker | 11 | 
| [[NC&#x2011;52](#nc52-utility-contracts-can-be-made-into-libraries)] | Utility contracts can be made into libraries | 2 | 
| [[NC&#x2011;53](#nc53-high-cyclomatic-complexity)] | High cyclomatic complexity | 2 | 
| [[NC&#x2011;54](#nc54-a-function-which-defines-named-returns-in-it-s-declaration-doesn-t-need-to-use-return)] | A function which defines named returns in it's declaration doesn't need to use return | 10 | 
| [[NC&#x2011;55](#nc55-error-declarations-should-have-natspec-descriptions)] | `error` declarations should have NatSpec descriptions | 6 | 
| [[NC&#x2011;56](#nc56-contract-declarations-should-have-natspec-dev-annotations)] | Contract declarations should have NatSpec `@dev` annotations | 6 | 
| [[NC&#x2011;57](#nc57-contract-should-expose-an-interface)] | Contract should expose an `interface` | 55 | 
| [[NC&#x2011;58](#nc58-contract-declarations-should-have-natspec-notice-annotations)] | Contract declarations should have NatSpec `@notice` annotations | 4 | 
| [[NC&#x2011;59](#nc59-do-not-use-underscore-in-struct-elements-names)] | Do not use UNDERSCORE in `struct` elements names | 1 | 
| [[NC&#x2011;60](#nc60-event-declarations-should-have-natspec-descriptions)] | `event` declarations should have NatSpec descriptions | 1 | 
| [[NC&#x2011;61](#nc61-function-names-should-use-lowercamelcase)] | `function` names should use lowerCamelCase | 38 | 
| [[NC&#x2011;62](#nc62-expressions-for-constant-values-should-use-immutable-rather-than-constant)] | Expressions for constant values should use `immutable` rather than `constant` | 1 | 
| [[NC&#x2011;63](#nc63-contract-uses-both-require-revert-as-well-as-custom-errors)] | Contract uses both `require()`/`revert()` as well as custom errors | 5 | 

Total: 598 instances over 63 issues

### Gas Optimizations

| |Issue|Instances|Total Gas Saved|
|-|:-|:-:|:-:|
| [[GAS&#x2011;1](#gas1-use-assembly-to-check-for-address-0)] | Use assembly to check for `address(0)` | 17 | 102 | 
| [[GAS&#x2011;2](#gas2-optimize-address-storage-value-management-with-assembly)] | Optimize Address Storage Value Management with `assembly` | 17 | - | 
| [[GAS&#x2011;3](#gas3-use-assembly-to-emit-events)] | Use assembly to emit events | 22 | 836 | 
| [[GAS&#x2011;4](#gas4-use-byte32-in-place-of-string)] | Use byte32 in place of string | 2 | - | 
| [[GAS&#x2011;5](#gas5-cache-array-length-outside-of-loop)] | Cache array length outside of loop | 1 | 97 | 
| [[GAS&#x2011;6](#gas6-state-variables-should-be-cached-in-stack-variables-rather-than-re-reading-them-from-storage)] | State variables should be cached in stack variables rather than re-reading them from storage | 11 | 1067 | 
| [[GAS&#x2011;7](#gas7-use-calldata-instead-of-memory-for-function-arguments-that-do-not-get-mutated)] | Use calldata instead of memory for function arguments that do not get mutated | 1 | - | 
| [[GAS&#x2011;8](#gas8-add-unchecked-for-subtractions-where-the-operands-cannot-underflow-because-of-a-previous-require-or-if-statement)] | Add `unchecked {}` for subtractions where the operands cannot underflow because of a previous `require()` or `if`-statement | 2 | 170 | 
| [[GAS&#x2011;9](#gas9-x-y-costs-more-gas-than-x-x-y-for-state-variables)] | `x += y` costs more gas than `x = x + y` for state variables | 2 | 226 | 
| [[GAS&#x2011;10](#gas10-use-custom-errors-rather-than-revert-require-strings-to-save-gas)] | Use custom errors rather than `revert()`/`require()` strings to save gas | 4 | - | 
| [[GAS&#x2011;11](#gas11-divisions-which-do-not-divide-by-x-cannot-overflow-or-overflow-so-such-operations-can-be-unchecked-to-save-gas)] | Divisions which do not divide by -X cannot overflow or overflow so such operations can be unchecked to save gas | 3 | - | 
| [[GAS&#x2011;12](#gas12-do-not-calculate-constants)] | Do not calculate constants | 1 | - | 
| [[GAS&#x2011;13](#gas13-stack-variable-cost-less-while-used-in-emiting-event)] | Stack variable cost less while used in emiting event | 10 | 1000 | 
| [[GAS&#x2011;14](#gas14-superfluous-event-fields)] | Superfluous event fields | 1 | - | 
| [[GAS&#x2011;15](#gas15-use-erc721a-instead-erc721)] | Use `ERC721A` instead `ERC721` | 1 | - | 
| [[GAS&#x2011;16](#gas16-the-result-of-function-calls-should-be-cached-rather-than-re-calling-the-function)] | The result of function calls should be cached rather than re-calling the function | 1 | - | 
| [[GAS&#x2011;17](#gas17-internal-functions-only-called-once-can-be-inlined-to-save-gas)] | `internal` functions only called once can be inlined to save gas | 4 | 80 | 
| [[GAS&#x2011;18](#gas18-multiple-address-id-mappings-can-be-combined-into-a-single-mapping-of-an-address-id-to-a-struct-where-appropriate)] | Multiple `address`/ID mappings can be combined into a single `mapping` of an `address`/ID to a `struct`, where appropriate | 6 | - | 
| [[GAS&#x2011;19](#gas19-optimize-names-to-save-gas)] | Optimize names to save gas | 2 | 44 | 
| [[GAS&#x2011;20](#gas20-not-using-the-named-return-variables-anywhere-in-the-function-is-confusing)] | Not using the named return variables anywhere in the function is confusing | 8 | - | 
| [[GAS&#x2011;21](#gas21-constructors-can-be-marked-payable)] | Constructors can be marked `payable` | 10 | 210 | 
| [[GAS&#x2011;22](#gas22-functions-guaranteed-to-revert-when-called-by-normal-users-can-be-marked-payable)] | Functions guaranteed to revert when called by normal users can be marked `payable` | 4 | 84 | 
| [[GAS&#x2011;23](#gas23-avoid-updating-storage-when-the-value-hasn-t-changed-to-save-gas)] | Avoid updating storage when the value hasn't changed to save gas | 6 | 4800 | 
| [[GAS&#x2011;24](#gas24-usage-of-uints-ints-smaller-than-32-bytes-256-bits-incurs-overhead)] | Usage of `uints`/`ints` smaller than 32 bytes (256 bits) incurs overhead | 9 | - | 
| [[GAS&#x2011;25](#gas25-the-use-of-a-logical-and-in-place-of-double-if-is-slightly-less-gas-efficient-in-instances-where-there-isn-t-a-corresponding-else-statement-for-the-given-if-statement)] | The use of a logical AND in place of double if is slightly less gas efficient in instances where there isn't a corresponding else statement for the given if statement | 2 | 30 | 
| [[GAS&#x2011;26](#gas26-state-variables-only-set-in-the-constructor-should-be-declared-immutable)] | State variables only set in the constructor should be declared `immutable` | 11 | 23067 | 
| [[GAS&#x2011;27](#gas27-using-storage-instead-of-memory-for-structs-arrays-saves-gas)] | Using `storage` instead of `memory` for structs/arrays saves gas | 3 | 12600 | 
| [[GAS&#x2011;28](#gas28-costs-less-gas-than)] | `>=`/`<=` costs less gas than `>`/`<` | 19 | 57 | 
| [[GAS&#x2011;29](#gas29-use-assembly-to-validate-msg-sender)] | Use assembly to validate `msg.sender` | 12 | 144 | 
| [[GAS&#x2011;30](#gas30-i-costs-less-gas-than-i-especially-when-it-s-used-in-for-loops-i-i-too)] | `++i` costs less gas than `i++`, especially when it's used in `for`-loops (`--i`/`i--` too) | 1 | - | 
| [[GAS&#x2011;31](#gas31-unnecessary-casting-as-variable-is-already-of-the-same-type)] | Unnecessary casting as variable is already of the same type | 1 | 22 | 
| [[GAS&#x2011;32](#gas32-stat-variables-can-be-packed-into-fewer-storage-slots-by-truncating-timestamp-bytes)] | Stat variables can be packed into fewer storage slots by truncating timestamp bytes | 1 | - | 
| [[GAS&#x2011;33](#gas33-state-variables-can-be-packed-into-fewer-storage-slots)] | State variables can be packed into fewer storage slots | 2 | 4000 | 
| [[GAS&#x2011;34](#gas34-use-do-while-loops-instead-of-for-loops)] | Use `do while` loops instead of `for` loops | 1 | 121 | 
| [[GAS&#x2011;35](#gas35-use-for-mapping-s)] | Use `+=` for `mapping`s | 1 | - | 
| [[GAS&#x2011;36](#gas36-simple-checks-for-zero-uint-can-be-done-using-assembly-to-save-gas)] | Simple checks for zero `uint` can be done using assembly to save gas | 6 | 36 | 
| [[GAS&#x2011;37](#gas37-i-i-should-be-unchecked-i-unchecked-i-when-it-is-not-possible-for-them-to-overflow-as-is-the-case-when-used-in-for-and-while-loops)] | `++i`/`i++` should be `unchecked{++i}`/`unchecked{i++}` when it is not possible for them to overflow, as is the case when used in `for`- and `while`-loops | 1 | - | 

Total: 206 instances over 37 issues with **48793 gas** saved




## Low Risk Issues

### [L&#x2011;1] Vulnerable versions of packages are being used 
This project's specific package versions are vulnerable to the specific CVEs listed below. Consider switching to more recent versions of these packages that don't have these vulnerabilities


*There are 2 instances of this issue:*

File: package.json


<details><summary>Vulnerabilities related to `@openzeppelin/contracts`:</summary>


- [CVE-2023-34459](https://github.com/OpenZeppelin/openzeppelin-contracts/security/advisories/GHSA-wprv-93r4-jj2p) :When the verifyMultiProof, verifyMultiProofCalldata, processMultiProof, or processMultiProofCalldata functions are in use, it is possible to construct merkle trees that allow forging a valid multiproof for an arbitrary set of leaves.
A contract may be vulnerable if it uses multiproofs for verification and the merkle tree that is processed includes a node with value 0 at depth 1(just under the root).This could happen inadvertently for balanced trees with 3 leaves or less, if the leaves are not hashed.This could happen deliberately if a malicious tree builder includes such a node in the tree.
A contract is not vulnerable if it uses single- leaf proving(verify, verifyCalldata, processProof, or processProofCalldata), or if it uses multiproofs with a known tree that has hashed leaves.Standard merkle trees produced or validated with the @openzeppelin/merkle-tree library are safe.


- [CVE-2023-34234](https://github.com/OpenZeppelin/openzeppelin-contracts/security/advisories/GHSA-5h3x-9wvq-w4m2) :By frontrunning the creation of a proposal, an attacker can become the proposer and gain the ability to cancel it. The attacker can do this repeatedly to try to prevent a proposal from being proposed at all.
This impacts the Governor contract in v4.9.0 only, and the GovernorCompatibilityBravo contract since v4.3.0.


- [CVE-2023-30541](https://github.com/OpenZeppelin/openzeppelin-contracts/security/advisories/GHSA-mx2q-35m2-x2rh) :A function in the implementation contract may be inaccessible if its selector clashes with one of the proxy's own selectors. Specifically, if the clashing function has a different signature with incompatible ABI encoding, the proxy could revert while attempting to decode the arguments from calldata.
The probability of an accidental clash is negligible, but one could be caused deliberately.


- [CVE-2023-30542](https://github.com/OpenZeppelin/openzeppelin-contracts/security/advisories/GHSA-93hq-5wgc-jc82) :The proposal creation entrypoint (propose) in GovernorCompatibilityBravo allows the creation of proposals with a signatures array shorter than the calldatas array. This causes the additional elements of the latter to be ignored, and if the proposal succeeds the corresponding actions would eventually execute without any calldata. The ProposalCreated event correctly represents what will eventually execute, but the proposal parameters as queried through getActions appear to respect the original intended calldata.
</details>

1: 


[link](https://github.com/open-dollar/od-contracts/blob/v1.5.5-audit//package.json#L1-L1) 


```solidity

File: src/contracts/AccountingEngine.sol

//@audit the project is using an old version of OpenZeppelin libraries
1: // SPDX-License-Identifier: GPL-3.0


```

[link](https://github.com/open-dollar/od-contracts/blob/v1.5.5-audit//src/contracts/AccountingEngine.sol#L1-L1) 


### [L&#x2011;2] Missing checks for `address(0)` when assigning values to address state variables 



*There are 2 instances of this issue:*



<details>
<summary>see instances</summary>


```solidity
File: src/contracts/proxies/ODProxy.sol

15:     OWNER = _owner;


```

[link](https://github.com/open-dollar/od-contracts/blob/v1.5.5-audit//src/contracts/proxies/ODProxy.sol#L15-L15) 


```solidity

File: src/contracts/proxies/Vault721.sol

34:     governor = _governor;


```

[link](https://github.com/open-dollar/od-contracts/blob/v1.5.5-audit//src/contracts/proxies/Vault721.sol#L34-L34) 


</details>


### [L&#x2011;3] For loops in public or external functions should be avoided due to high gas costs and possible DOS 
In Solidity, for loops can potentially cause Denial of Service (DoS) attacks if not handled carefully. DoS attacks can occur when an attacker intentionally exploits the gas cost of a function, causing it to run out of gas or making it too expensive for other users to call. Below are some scenarios where for loops can lead to DoS attacks: Nested for loops can become exceptionally gas expensive and should be used sparingly


*There are 1 instances of this issue:*



<details>
<summary>see instances</summary>


```solidity
File: src/contracts/proxies/ODSafeManager.sol

83:   function getSafesData(address _usr)
84:     external
85:     view
86:     returns (uint256[] memory _safes, address[] memory _safeHandlers, bytes32[] memory _cTypes)
87:   {
88:     _safes = _usrSafes[_usr].values();
89:     _safeHandlers = new address[](_safes.length);
90:     _cTypes = new bytes32[](_safes.length);
91:     for (uint256 _i; _i < _safes.length; _i++) {


```

[link](https://github.com/open-dollar/od-contracts/blob/v1.5.5-audit//src/contracts/proxies/ODSafeManager.sol#L83-L91) 


</details>


### [L&#x2011;4] `decimals()` is not a part of the ERC-20 standard 
The `decimals()` function is not a part of the [ERC-20 standard](https://eips.ethereum.org/EIPS/eip-20), and was added later as an [optional extension](https://github.com/OpenZeppelin/openzeppelin-contracts/blob/master/contracts/token/ERC20/extensions/IERC20Metadata.sol). As such, some valid ERC20 tokens do not support this interface, so it is unsafe to blindly cast all tokens to this interface, and then call this function.


*There are 4 instances of this issue:*



<details>
<summary>see instances</summary>


```solidity
File: src/contracts/oracles/CamelotRelayer.sol

57:     baseAmount = uint128(10 ** IERC20Metadata(_baseToken).decimals());

58:     multiplier = 18 - IERC20Metadata(_quoteToken).decimals();


```

[link](https://github.com/open-dollar/od-contracts/blob/v1.5.5-audit//src/contracts/oracles/CamelotRelayer.sol#L57-L57) , [link](https://github.com/open-dollar/od-contracts/blob/v1.5.5-audit//src/contracts/oracles/CamelotRelayer.sol#L58-L58)


```solidity

File: src/contracts/oracles/UniV3Relayer.sol

63:     baseAmount = uint128(10 ** IERC20Metadata(_baseToken).decimals());

64:     multiplier = 18 - IERC20Metadata(_quoteToken).decimals();


```

[link](https://github.com/open-dollar/od-contracts/blob/v1.5.5-audit//src/contracts/oracles/UniV3Relayer.sol#L63-L63) , [link](https://github.com/open-dollar/od-contracts/blob/v1.5.5-audit//src/contracts/oracles/UniV3Relayer.sol#L64-L64)


</details>


### [L&#x2011;5] Loss of precision 
Division by large numbers may result in the result being zero, due to solidity not supporting fractions. Consider requiring a minimum amount for the numerator to ensure that it is always larger than the denominator


*There are 2 instances of this issue:*



<details>
<summary>see instances</summary>


```solidity
File: src/contracts/proxies/actions/BasicActions.sol

43:       _deltaDebt = ((_deltaWad * RAY - _coinAmount) / _rate).toInt();

63:     _deltaDebt = (_coinAmount / _rate).toInt();


```

[link](https://github.com/open-dollar/od-contracts/blob/v1.5.5-audit//src/contracts/proxies/actions/BasicActions.sol#L43-L43) , [link](https://github.com/open-dollar/od-contracts/blob/v1.5.5-audit//src/contracts/proxies/actions/BasicActions.sol#L63-L63)


</details>


### [L&#x2011;6] NFT doesn't handle hard forks 
When there are hard forks, users often have to go through [many hoops](https://twitter.com/elerium115/status/1558471934924431363) to ensure that they control ownership on every fork. Consider adding `require(1 == chain.chainId)`, or the chain ID of whichever chain you prefer, to the functions below, or at least include the chain ID in the URI, so that there is no confusion about which chain is the owner of the NFT.


*There are 1 instances of this issue:*



<details>
<summary>see instances</summary>


```solidity
File: src/contracts/proxies/Vault721.sol

140:   function tokenURI(uint256 _safeId) public view override returns (string memory uri) {


```

[link](https://github.com/open-dollar/od-contracts/blob/v1.5.5-audit//src/contracts/proxies/Vault721.sol#L140-L140) 


</details>


### [L&#x2011;7] Operations such as the changing of the owner should be behind a timelock 
From the point of view of a user, the changing of the owner of a contract is a high risk operation that may have outcomes ranging from an attacker gaining control over the protocol, to the function no longer functioning due to a typo in the destination address. To give users plenty of warning so that they can validate any ownership changes, changes of ownership should be behind a timelock.


*There are 3 instances of this issue:*



<details>
<summary>see instances</summary>


```solidity
File: src/contracts/proxies/ODSafeManager.sol

136:   function transferSAFEOwnership(uint256 _safe, address _dst) external {
137:     require(msg.sender == address(vault721), 'SafeMngr: Only Vault721');
138: 
139:     if (_dst == address(0)) revert ZeroAddress();
140:     SAFEData memory _sData = _safeData[_safe];
141:     if (_dst == _sData.owner) revert AlreadySafeOwner();
142: 
143:     _usrSafes[_sData.owner].remove(_safe);
144:     _usrSafesPerCollat[_sData.owner][_sData.collateralType].remove(_safe);
145: 
146:     _usrSafes[_dst].add(_safe);
147:     _usrSafesPerCollat[_dst][_sData.collateralType].add(_safe);
148: 
149:     _safeData[_safe].owner = _dst;
150: 
151:     emit TransferSAFEOwnership(msg.sender, _safe, _dst);
152:   }


```

[link](https://github.com/open-dollar/od-contracts/blob/v1.5.5-audit//src/contracts/proxies/ODSafeManager.sol#L136-L152) 


```solidity

File: src/contracts/proxies/Vault721.sol

126:   function setSafeManager(address _safeManager) external onlyGovernor {
127:     _setSafeManager(_safeManager);
128:   }

172:   function _setSafeManager(address _safeManager) internal nonZero(_safeManager) {
173:     safeManager = IODSafeManager(_safeManager);
174:   }


```

[link](https://github.com/open-dollar/od-contracts/blob/v1.5.5-audit//src/contracts/proxies/Vault721.sol#L126-L128) , [link](https://github.com/open-dollar/od-contracts/blob/v1.5.5-audit//src/contracts/proxies/Vault721.sol#L172-L174)


</details>


### [L&#x2011;8] Consider using OpenZeppelin’s SafeCast library to prevent unexpected overflows when casting from various type int/uint values 



*There are 2 instances of this issue:*



<details>
<summary>see instances</summary>


```solidity
File: src/contracts/proxies/actions/BasicActions.sol

//@audit `_deltaDebt` is getting converted from `int256` to `uint256`
45:       _deltaDebt = uint256(_deltaDebt) * _rate < _deltaWad * RAY ? _deltaDebt + 1 : _deltaDebt;

//@audit `_deltaDebt` is getting converted from `int256` to `uint256`
65:     _deltaDebt = uint256(_deltaDebt) <= _generatedDebt ? -_deltaDebt : -_generatedDebt.toInt();


```

[link](https://github.com/open-dollar/od-contracts/blob/v1.5.5-audit//src/contracts/proxies/actions/BasicActions.sol#L45-L45) , [link](https://github.com/open-dollar/od-contracts/blob/v1.5.5-audit//src/contracts/proxies/actions/BasicActions.sol#L65-L65)


</details>


### [L&#x2011;9] Setters should have initial value check 
Setters should have initial value check to prevent assigning wrong value to the variable. Assginment of wrong value can lead to unexpected behavior of the contract.


*There are 4 instances of this issue:*



<details>
<summary>see instances</summary>


```solidity
File: src/contracts/AccountingEngine.sol

139:   function settleDebt(uint256 _rad) external {


```

[link](https://github.com/open-dollar/od-contracts/blob/v1.5.5-audit//src/contracts/AccountingEngine.sol#L139-L139) 


```solidity

File: src/contracts/proxies/Vault721.sol

119:   function updateContractURI(string memory _metaData) external onlyGovernor {

126:   function setSafeManager(address _safeManager) external onlyGovernor {

133:   function setNftRenderer(address _nftRenderer) external onlyGovernor {


```

[link](https://github.com/open-dollar/od-contracts/blob/v1.5.5-audit//src/contracts/proxies/Vault721.sol#L119-L119) , [link](https://github.com/open-dollar/od-contracts/blob/v1.5.5-audit//src/contracts/proxies/Vault721.sol#L126-L126), [link](https://github.com/open-dollar/od-contracts/blob/v1.5.5-audit//src/contracts/proxies/Vault721.sol#L133-L133)


</details>


### [L&#x2011;10] `symbol()` is not a part of the ERC-20 standard 
The `symbol()` function is not a part of the [ERC-20 standard](https://eips.ethereum.org/EIPS/eip-20), and was added later as an [optional extension](https://github.com/OpenZeppelin/openzeppelin-contracts/blob/master/contracts/token/ERC20/extensions/IERC20Metadata.sol). As such, some valid ERC20 tokens do not support this interface, so it is unsafe to blindly cast all tokens to this interface, and then call this function.


*There are 4 instances of this issue:*



<details>
<summary>see instances</summary>


```solidity
File: src/contracts/oracles/CamelotRelayer.sol

61:     symbol = string(abi.encodePacked(IERC20Metadata(_baseToken).symbol(), ' / ', IERC20Metadata(_quoteToken).symbol()));

61:     symbol = string(abi.encodePacked(IERC20Metadata(_baseToken).symbol(), ' / ', IERC20Metadata(_quoteToken).symbol()));


```

[link](https://github.com/open-dollar/od-contracts/blob/v1.5.5-audit//src/contracts/oracles/CamelotRelayer.sol#L61-L61) , [link](https://github.com/open-dollar/od-contracts/blob/v1.5.5-audit//src/contracts/oracles/CamelotRelayer.sol#L61-L61)


```solidity

File: src/contracts/oracles/UniV3Relayer.sol

67:     symbol = string(abi.encodePacked(IERC20Metadata(_baseToken).symbol(), ' / ', IERC20Metadata(_quoteToken).symbol()));

67:     symbol = string(abi.encodePacked(IERC20Metadata(_baseToken).symbol(), ' / ', IERC20Metadata(_quoteToken).symbol()));


```

[link](https://github.com/open-dollar/od-contracts/blob/v1.5.5-audit//src/contracts/oracles/UniV3Relayer.sol#L67-L67) , [link](https://github.com/open-dollar/od-contracts/blob/v1.5.5-audit//src/contracts/oracles/UniV3Relayer.sol#L67-L67)


</details>


### [L&#x2011;11] Consider using descriptive `constant`s when passing zero as a function argument 
Passing zero as a function argument can sometimes result in a security issue (e.g. passing zero as the slippage parameter). Consider using a `constant` variable with a descriptive name, so it's clear that the argument is intentionally being used, and for the right reasons.


*There are 6 instances of this issue:*



<details>
<summary>see instances</summary>


```solidity
File: src/contracts/AccountingEngine.sol

//@audit parameter number 2 starting from left
214:       _id = surplusAuctionHouse.startAuction({
215:         _amountToSell: _params.surplusAmount.wmul(ONE_HUNDRED_WAD - _params.surplusTransferPercentage),
216:         _initialBid: 0
217:       });


```

[link](https://github.com/open-dollar/od-contracts/blob/v1.5.5-audit//src/contracts/AccountingEngine.sol#L214-L217) 


```solidity

File: src/contracts/proxies/actions/BasicActions.sol

//@audit parameter number 3 starting from left
106:     _modifySAFECollateralization(
107:       _manager,
108:       _safeId,
109:       0,
110:       _getGeneratedDeltaDebt(_safeEngine, _safeInfo.collateralType, _safeInfo.safeHandler, _deltaWad)
111:     );

//@audit parameter number 3 starting from left
136:     _modifySAFECollateralization(
137:       _manager, _safeId, 0, _getRepaidDeltaDebt(_safeEngine, _safeInfo.collateralType, _safeInfo.safeHandler)
138:     );

//@audit parameter number 4 starting from left
265:     _modifySAFECollateralization(_manager, _safeId, _deltaWad.toInt(), 0);

//@audit parameter number 4 starting from left
276:     _modifySAFECollateralization(_manager, _safeId, -_deltaWad.toInt(), 0);

//@audit parameter number 5 starting from left
302:     ISAFEEngine(_safeEngine).modifySAFECollateralization({
303:       _cType: _safeInfo.collateralType,
304:       _safe: _safeInfo.safeHandler,
305:       _collateralSource: address(this),
306:       _debtDestination: address(this),
307:       _deltaCollateral: 0,
308:       _deltaDebt: -int256(_safeData.generatedDebt)
309:     });


```

[link](https://github.com/open-dollar/od-contracts/blob/v1.5.5-audit//src/contracts/proxies/actions/BasicActions.sol#L106-L111) , [link](https://github.com/open-dollar/od-contracts/blob/v1.5.5-audit//src/contracts/proxies/actions/BasicActions.sol#L136-L138), [link](https://github.com/open-dollar/od-contracts/blob/v1.5.5-audit//src/contracts/proxies/actions/BasicActions.sol#L265-L265), [link](https://github.com/open-dollar/od-contracts/blob/v1.5.5-audit//src/contracts/proxies/actions/BasicActions.sol#L276-L276), [link](https://github.com/open-dollar/od-contracts/blob/v1.5.5-audit//src/contracts/proxies/actions/BasicActions.sol#L302-L309)


</details>


### [L&#x2011;12] prevent re-setting a state variable with the same value 
Not only is wasteful in terms of gas, but this is especially problematic when an event is emitted and the old and new values set are the same, as listeners might not expect this kind of scenario.


*There are 6 instances of this issue:*



<details>
<summary>see instances</summary>


```solidity
File: src/contracts/AccountingEngine.sol

139:   function settleDebt(uint256 _rad) external {


```

[link](https://github.com/open-dollar/od-contracts/blob/v1.5.5-audit//src/contracts/AccountingEngine.sol#L139-L139) 


```solidity

File: src/contracts/proxies/ODSafeManager.sol

155:   function modifySAFECollateralization(


```

[link](https://github.com/open-dollar/od-contracts/blob/v1.5.5-audit//src/contracts/proxies/ODSafeManager.sol#L155-L155) 


```solidity

File: src/contracts/proxies/Vault721.sol

104:   function updateNftRenderer(

119:   function updateContractURI(string memory _metaData) external onlyGovernor {

126:   function setSafeManager(address _safeManager) external onlyGovernor {

133:   function setNftRenderer(address _nftRenderer) external onlyGovernor {


```

[link](https://github.com/open-dollar/od-contracts/blob/v1.5.5-audit//src/contracts/proxies/Vault721.sol#L104-L104) , [link](https://github.com/open-dollar/od-contracts/blob/v1.5.5-audit//src/contracts/proxies/Vault721.sol#L119-L119), [link](https://github.com/open-dollar/od-contracts/blob/v1.5.5-audit//src/contracts/proxies/Vault721.sol#L126-L126), [link](https://github.com/open-dollar/od-contracts/blob/v1.5.5-audit//src/contracts/proxies/Vault721.sol#L133-L133)


</details>


## Non-critical Issues

### [NC&#x2011;1] Public `variable` declarations should have NatSpec descriptions 



*There are 10 instances of this issue:*



<details>
<summary>see instances</summary>


```solidity
File: src/contracts/AccountingEngine.sol

28:   uint256 internal constant ONE_HUNDRED_WAD = 100 * WAD;


```

[link](https://github.com/open-dollar/od-contracts/blob/v1.5.5-audit//src/contracts/AccountingEngine.sol#L28-L28) 


```solidity

File: src/contracts/oracles/CamelotRelayer.sol

20:   address internal constant _CAMELOT_FACTORY = GOERLI_CAMELOT_V3_FACTORY;


```

[link](https://github.com/open-dollar/od-contracts/blob/v1.5.5-audit//src/contracts/oracles/CamelotRelayer.sol#L20-L20) 


```solidity

File: src/contracts/oracles/UniV3Relayer.sol

18:   address internal constant _UNI_V3_FACTORY = GOERLI_UNISWAP_V3_FACTORY;


```

[link](https://github.com/open-dollar/od-contracts/blob/v1.5.5-audit//src/contracts/oracles/UniV3Relayer.sol#L18-L18) 


```solidity

File: src/contracts/proxies/ODProxy.sol

12:   address public immutable OWNER;


```

[link](https://github.com/open-dollar/od-contracts/blob/v1.5.5-audit//src/contracts/proxies/ODProxy.sol#L12-L12) 


```solidity

File: src/contracts/proxies/Vault721.sol

19:   IODSafeManager public safeManager;

20:   NFTRenderer public nftRenderer;

25:   mapping(address proxy => address user) internal _proxyRegistry;

26:   mapping(address user => address proxy) internal _userRegistry;


```

[link](https://github.com/open-dollar/od-contracts/blob/v1.5.5-audit//src/contracts/proxies/Vault721.sol#L19-L19) , [link](https://github.com/open-dollar/od-contracts/blob/v1.5.5-audit//src/contracts/proxies/Vault721.sol#L20-L20), [link](https://github.com/open-dollar/od-contracts/blob/v1.5.5-audit//src/contracts/proxies/Vault721.sol#L25-L25), [link](https://github.com/open-dollar/od-contracts/blob/v1.5.5-audit//src/contracts/proxies/Vault721.sol#L26-L26)


```solidity

File: src/contracts/proxies/ODSafeManager.sol

29:   IVault721 public vault721;

32:   mapping(address _safeOwner => EnumerableSet.UintSet) private _usrSafes;


```

[link](https://github.com/open-dollar/od-contracts/blob/v1.5.5-audit//src/contracts/proxies/ODSafeManager.sol#L29-L29) , [link](https://github.com/open-dollar/od-contracts/blob/v1.5.5-audit//src/contracts/proxies/ODSafeManager.sol#L32-L32)


</details>


### [NC&#x2011;2] Large or complicated code bases should implement invariant tests 
Large code bases, or code with lots of inline-assembly, complicated math, or complicated interactions between multiple contracts, should implement [invariant fuzzing tests](https://medium.com/coinmonks/smart-contract-fuzzing-d9b88e0b0a05). Invariant fuzzers such as Echidna require the test writer to come up with invariants which should not be violated under any circumstances, and the fuzzer tests various inputs and function calls to ensure that the invariants always hold. Even code with 100% code coverage can still have bugs due to the order of the operations a user performs, and invariant fuzzers, with properly and extensively-written invariants, can close this testing gap significantly.


*There are 1 instances of this issue:*



<details>
<summary>see instances</summary>


```solidity
File: src/contracts/AccountingEngine.sol

@audit Should implement invariant tests
1: 


```

[link](https://github.com/open-dollar/od-contracts/blob/v1.5.5-audit//src/contracts/AccountingEngine.sol#L1-L1) 


</details>


### [NC&#x2011;3] Contract declarations should have NatSpec `@author` annotations 



*There are 11 instances of this issue:*



<details>
<summary>see instances</summary>


```solidity
File: src/contracts/AccountingEngine.sol

17: /**
18:  * @title  AccountingEngine
19:  * @notice This contract is responsible for handling protocol surplus and debt
20:  * @notice It allows the system to auction surplus and debt, as well as transfer surplus
21:  * @dev    This is a system contract, therefore it is not meant to be used by users directly
22:  */


```

[link](https://github.com/open-dollar/od-contracts/blob/v1.5.5-audit//src/contracts/AccountingEngine.sol#L17-L22) 


```solidity

File: src/contracts/oracles/CamelotRelayer.sol

13: /**
14:  * @title  CamelotRelayer
15:  * @notice This contracts consults a CamelotRelayer TWAP and transforms the result into a standard IBaseOracle feed
16:  * @dev    The quote obtained from the pool query is transformed into an 18 decimals format
17:  */


```

[link](https://github.com/open-dollar/od-contracts/blob/v1.5.5-audit//src/contracts/oracles/CamelotRelayer.sol#L13-L17) 


```solidity

File: src/contracts/factories/CamelotRelayerFactory.sol

13: contract CamelotRelayerFactory is Authorizable, ICamelotRelayerFactory {


```

[link](https://github.com/open-dollar/od-contracts/blob/v1.5.5-audit//src/contracts/factories/CamelotRelayerFactory.sol#L13-L13) 


```solidity

File: src/contracts/factories/CamelotRelayerChild.sol

10: /**
11:  * @title  CamelotRelayerChild
12:  * @notice This contract inherits all the functionality of `CamelotRelayer.sol` to be factory deployed
13:  */


```

[link](https://github.com/open-dollar/od-contracts/blob/v1.5.5-audit//src/contracts/factories/CamelotRelayerChild.sol#L10-L13) 


```solidity

File: src/contracts/oracles/UniV3Relayer.sol

11: /**
12:  * @title  UniV3Relayer
13:  * @notice This contracts consults a UniswapV3Pool TWAP and transforms the result into a standard IBaseOracle feed
14:  * @dev    The quote obtained from the pool query is transformed into an 18 decimals format
15:  */


```

[link](https://github.com/open-dollar/od-contracts/blob/v1.5.5-audit//src/contracts/oracles/UniV3Relayer.sol#L11-L15) 


```solidity

File: src/contracts/gov/ODGovernor.sol

17: contract ODGovernor is


```

[link](https://github.com/open-dollar/od-contracts/blob/v1.5.5-audit//src/contracts/gov/ODGovernor.sol#L17-L17) 


```solidity

File: src/contracts/proxies/ODProxy.sol

7: contract ODProxy {


```

[link](https://github.com/open-dollar/od-contracts/blob/v1.5.5-audit//src/contracts/proxies/ODProxy.sol#L7-L7) 


```solidity

File: src/contracts/proxies/Vault721.sol

13: contract Vault721 is ERC721Enumerable {


```

[link](https://github.com/open-dollar/od-contracts/blob/v1.5.5-audit//src/contracts/proxies/Vault721.sol#L13-L13) 


```solidity

File: src/contracts/proxies/SAFEHandler.sol

06: /**
07:  * @title  SAFEHandler
08:  * @notice This contract is spawned to provide a unique safe handler address for each user's SAFE
09:  * @dev    When a new SAFE is created inside ODSafeManager this contract is deployed and calls the SAFEEngine to add permissions to the SAFE manager
10:  */


```

[link](https://github.com/open-dollar/od-contracts/blob/v1.5.5-audit//src/contracts/proxies/SAFEHandler.sol#L6-L10) 


```solidity

File: src/contracts/proxies/ODSafeManager.sol

15: /**
16:  * @title  ODSafeManager
17:  * @notice This contract acts as interface to the SAFEEngine, facilitating the management of SAFEs
18:  * @dev    This contract is meant to be used by users that interact with the protocol through a proxy contract
19:  */


```

[link](https://github.com/open-dollar/od-contracts/blob/v1.5.5-audit//src/contracts/proxies/ODSafeManager.sol#L15-L19) 


```solidity

File: src/contracts/proxies/actions/BasicActions.sol

18: /**
19:  * @title  BasicActions
20:  * @notice This contract defines the actions that can be executed to manage a SAFE
21:  */


```

[link](https://github.com/open-dollar/od-contracts/blob/v1.5.5-audit//src/contracts/proxies/actions/BasicActions.sol#L18-L21) 


</details>


### [NC&#x2011;4] Common functions should be refactored to a common base contract 
The functions below have the same implementation as is seen in other files. The functions should be refactored into functions of a common base contract


*There are 1 instances of this issue:*



<details>
<summary>see instances</summary>


```solidity
File: src/contracts/oracles/UniV3Relayer.sol

//@audit this function is already seen in `src/contracts/oracles/UniV3Relayer.sol`
110:   function _parseResult(uint256 _quoteResult) internal view returns (uint256 _result) {
111:     return _quoteResult * 10 ** multiplier;
112:   }


```

[link](https://github.com/open-dollar/od-contracts/blob/v1.5.5-audit//src/contracts/oracles/UniV3Relayer.sol#L110-L112) 


</details>


### [NC&#x2011;5] Constants in comparisons should appear on the left side 



*There are 19 instances of this issue:*



<details>
<summary>see instances</summary>


```solidity
File: src/contracts/AccountingEngine.sol

//@audit `0`
128:     if (_debtBlock == 0) revert AccEng_NullAmount();

//@audit `0`
176:     if (_params.debtAuctionBidSize == 0) revert AccEng_DebtAuctionDisabled();

//@audit `0`
200:     if (_params.surplusAmount == 0) revert AccEng_NullAmount();

//@audit `ONE_HUNDRED_WAD`
213:     if (_params.surplusTransferPercentage < ONE_HUNDRED_WAD) {

//@audit `0`
224:     if (_params.surplusTransferPercentage > 0) {

//@audit `0`
269:     if (_coinBalance > 0) {

//@audit `surplusTransferPercentage`
288:     if (_param == 'surplusTransferPercentage') _params.surplusTransferPercentage = _uint256;

//@audit `surplusDelay`
289:     else if (_param == 'surplusDelay') _params.surplusDelay = _uint256;

//@audit `popDebtDelay`
290:     else if (_param == 'popDebtDelay') _params.popDebtDelay = _uint256;

//@audit `disableCooldown`
291:     else if (_param == 'disableCooldown') _params.disableCooldown = _uint256;

//@audit `surplusAmount`
292:     else if (_param == 'surplusAmount') _params.surplusAmount = _uint256;

//@audit `debtAuctionBidSize`
293:     else if (_param == 'debtAuctionBidSize') _params.debtAuctionBidSize = _uint256;

//@audit `debtAuctionMintedTokens`
294:     else if (_param == 'debtAuctionMintedTokens') _params.debtAuctionMintedTokens = _uint256;

//@audit `surplusBuffer`
295:     else if (_param == 'surplusBuffer') _params.surplusBuffer = _uint256;

//@audit `surplusAuctionHouse`
297:     else if (_param == 'surplusAuctionHouse') _setSurplusAuctionHouse(_address);

//@audit `debtAuctionHouse`
298:     else if (_param == 'debtAuctionHouse') debtAuctionHouse = IDebtAuctionHouse(_address);

//@audit `postSettlementSurplusDrain`
299:     else if (_param == 'postSettlementSurplusDrain') postSettlementSurplusDrain = _address;

//@audit `extraSurplusReceiver`
300:     else if (_param == 'extraSurplusReceiver') extraSurplusReceiver = _address;


```

[link](https://github.com/open-dollar/od-contracts/blob/v1.5.5-audit//src/contracts/AccountingEngine.sol#L128-L128) , [link](https://github.com/open-dollar/od-contracts/blob/v1.5.5-audit//src/contracts/AccountingEngine.sol#L176-L176), [link](https://github.com/open-dollar/od-contracts/blob/v1.5.5-audit//src/contracts/AccountingEngine.sol#L200-L200), [link](https://github.com/open-dollar/od-contracts/blob/v1.5.5-audit//src/contracts/AccountingEngine.sol#L213-L213), [link](https://github.com/open-dollar/od-contracts/blob/v1.5.5-audit//src/contracts/AccountingEngine.sol#L224-L224), [link](https://github.com/open-dollar/od-contracts/blob/v1.5.5-audit//src/contracts/AccountingEngine.sol#L269-L269), [link](https://github.com/open-dollar/od-contracts/blob/v1.5.5-audit//src/contracts/AccountingEngine.sol#L288-L288), [link](https://github.com/open-dollar/od-contracts/blob/v1.5.5-audit//src/contracts/AccountingEngine.sol#L289-L289), [link](https://github.com/open-dollar/od-contracts/blob/v1.5.5-audit//src/contracts/AccountingEngine.sol#L290-L290), [link](https://github.com/open-dollar/od-contracts/blob/v1.5.5-audit//src/contracts/AccountingEngine.sol#L291-L291), [link](https://github.com/open-dollar/od-contracts/blob/v1.5.5-audit//src/contracts/AccountingEngine.sol#L292-L292), [link](https://github.com/open-dollar/od-contracts/blob/v1.5.5-audit//src/contracts/AccountingEngine.sol#L293-L293), [link](https://github.com/open-dollar/od-contracts/blob/v1.5.5-audit//src/contracts/AccountingEngine.sol#L294-L294), [link](https://github.com/open-dollar/od-contracts/blob/v1.5.5-audit//src/contracts/AccountingEngine.sol#L295-L295), [link](https://github.com/open-dollar/od-contracts/blob/v1.5.5-audit//src/contracts/AccountingEngine.sol#L297-L297), [link](https://github.com/open-dollar/od-contracts/blob/v1.5.5-audit//src/contracts/AccountingEngine.sol#L298-L298), [link](https://github.com/open-dollar/od-contracts/blob/v1.5.5-audit//src/contracts/AccountingEngine.sol#L299-L299), [link](https://github.com/open-dollar/od-contracts/blob/v1.5.5-audit//src/contracts/AccountingEngine.sol#L300-L300)


```solidity

File: src/contracts/proxies/actions/BasicActions.sol

//@audit `0`
148:     if (_deltaWad == 0) return;


```

[link](https://github.com/open-dollar/od-contracts/blob/v1.5.5-audit//src/contracts/proxies/actions/BasicActions.sol#L148-L148) 


</details>


### [NC&#x2011;6] NatSpec documentation for `contract` is missing 
It is recommended that Solidity contracts are fully annotated using NatSpec for all public interfaces (everything in the ABI). It is clearly stated in the Solidity official documentation. In complex projects such as Defi, the interpretation of all functions and their arguments and returns is important for code readability and auditability.[source](https://docs.soliditylang.org/en/v0.8.15/natspec-format.html)


*There are 4 instances of this issue:*



<details>
<summary>see instances</summary>


```solidity
File: src/contracts/factories/CamelotRelayerFactory.sol

13: contract CamelotRelayerFactory is Authorizable, ICamelotRelayerFactory {


```

[link](https://github.com/open-dollar/od-contracts/blob/v1.5.5-audit//src/contracts/factories/CamelotRelayerFactory.sol#L13-L13) 


```solidity

File: src/contracts/gov/ODGovernor.sol

17: contract ODGovernor is


```

[link](https://github.com/open-dollar/od-contracts/blob/v1.5.5-audit//src/contracts/gov/ODGovernor.sol#L17-L17) 


```solidity

File: src/contracts/proxies/ODProxy.sol

7: contract ODProxy {


```

[link](https://github.com/open-dollar/od-contracts/blob/v1.5.5-audit//src/contracts/proxies/ODProxy.sol#L7-L7) 


```solidity

File: src/contracts/proxies/Vault721.sol

13: contract Vault721 is ERC721Enumerable {


```

[link](https://github.com/open-dollar/od-contracts/blob/v1.5.5-audit//src/contracts/proxies/Vault721.sol#L13-L13) 


</details>


### [NC&#x2011;7] Control structures do not follow the Solidity Style Guide 
See the [control structures](https://docs.soliditylang.org/en/latest/style-guide.html#control-structures) section of the Solidity Style Guide


*There are 24 instances of this issue:*



<details>
<summary>see instances</summary>


```solidity
File: src/contracts/AccountingEngine.sol

143:   function _settleDebt(


```

[link](https://github.com/open-dollar/od-contracts/blob/v1.5.5-audit//src/contracts/AccountingEngine.sol#L143-L143) 


```solidity

File: src/contracts/factories/CamelotRelayerFactory.sol

23:   function deployCamelotRelayer(


```

[link](https://github.com/open-dollar/od-contracts/blob/v1.5.5-audit//src/contracts/factories/CamelotRelayerFactory.sol#L23-L23) 


```solidity

File: src/contracts/gov/ODGovernor.sol

85:   function propose(

104:   function _execute(

117:   function _cancel(


```

[link](https://github.com/open-dollar/od-contracts/blob/v1.5.5-audit//src/contracts/gov/ODGovernor.sol#L85-L85) , [link](https://github.com/open-dollar/od-contracts/blob/v1.5.5-audit//src/contracts/gov/ODGovernor.sol#L104-L104), [link](https://github.com/open-dollar/od-contracts/blob/v1.5.5-audit//src/contracts/gov/ODGovernor.sol#L117-L117)


```solidity

File: src/contracts/proxies/Vault721.sol

104:   function updateNftRenderer(


```

[link](https://github.com/open-dollar/od-contracts/blob/v1.5.5-audit//src/contracts/proxies/Vault721.sol#L104-L104) 


```solidity

File: src/contracts/proxies/ODSafeManager.sol

155:   function modifySAFECollateralization(


```

[link](https://github.com/open-dollar/od-contracts/blob/v1.5.5-audit//src/contracts/proxies/ODSafeManager.sol#L155-L155) 


```solidity

File: src/contracts/proxies/actions/BasicActions.sol

31:   function _getGeneratedDeltaDebt(

53:   function _getRepaidDeltaDebt(

72:   function _getRepaidDebt(

94:   function _generateDebt(

121:   function _repayDebt(

158:   function _modifySAFECollateralization(

170:   function _lockTokenCollateralAndGenerateDebt(

211:   function _collectAndExitCollateral(

231:   function generateDebt(

242:   function repayDebt(

253:   function lockTokenCollateral(

269:   function freeTokenCollateral(

282:   function repayAllDebt(

313:   function lockTokenCollateralAndGenerateDebt(

328:   function openLockTokenCollateralAndGenerateDebt(

345:   function repayDebtAndFreeTokenCollateral(

374:   function repayAllDebtAndFreeTokenCollateral(


```

[link](https://github.com/open-dollar/od-contracts/blob/v1.5.5-audit//src/contracts/proxies/actions/BasicActions.sol#L31-L31) , [link](https://github.com/open-dollar/od-contracts/blob/v1.5.5-audit//src/contracts/proxies/actions/BasicActions.sol#L53-L53), [link](https://github.com/open-dollar/od-contracts/blob/v1.5.5-audit//src/contracts/proxies/actions/BasicActions.sol#L72-L72), [link](https://github.com/open-dollar/od-contracts/blob/v1.5.5-audit//src/contracts/proxies/actions/BasicActions.sol#L94-L94), [link](https://github.com/open-dollar/od-contracts/blob/v1.5.5-audit//src/contracts/proxies/actions/BasicActions.sol#L121-L121), [link](https://github.com/open-dollar/od-contracts/blob/v1.5.5-audit//src/contracts/proxies/actions/BasicActions.sol#L158-L158), [link](https://github.com/open-dollar/od-contracts/blob/v1.5.5-audit//src/contracts/proxies/actions/BasicActions.sol#L170-L170), [link](https://github.com/open-dollar/od-contracts/blob/v1.5.5-audit//src/contracts/proxies/actions/BasicActions.sol#L211-L211), [link](https://github.com/open-dollar/od-contracts/blob/v1.5.5-audit//src/contracts/proxies/actions/BasicActions.sol#L231-L231), [link](https://github.com/open-dollar/od-contracts/blob/v1.5.5-audit//src/contracts/proxies/actions/BasicActions.sol#L242-L242), [link](https://github.com/open-dollar/od-contracts/blob/v1.5.5-audit//src/contracts/proxies/actions/BasicActions.sol#L253-L253), [link](https://github.com/open-dollar/od-contracts/blob/v1.5.5-audit//src/contracts/proxies/actions/BasicActions.sol#L269-L269), [link](https://github.com/open-dollar/od-contracts/blob/v1.5.5-audit//src/contracts/proxies/actions/BasicActions.sol#L282-L282), [link](https://github.com/open-dollar/od-contracts/blob/v1.5.5-audit//src/contracts/proxies/actions/BasicActions.sol#L313-L313), [link](https://github.com/open-dollar/od-contracts/blob/v1.5.5-audit//src/contracts/proxies/actions/BasicActions.sol#L328-L328), [link](https://github.com/open-dollar/od-contracts/blob/v1.5.5-audit//src/contracts/proxies/actions/BasicActions.sol#L345-L345), [link](https://github.com/open-dollar/od-contracts/blob/v1.5.5-audit//src/contracts/proxies/actions/BasicActions.sol#L374-L374)


</details>


### [NC&#x2011;8] Custom error has no error details 
Consider adding parameters to the error to indicate which user or values caused the failure


*There are 5 instances of this issue:*



<details>
<summary>see instances</summary>


```solidity
File: src/contracts/proxies/ODProxy.sol

8:   error TargetAddressRequired();

10:   error OnlyOwner();


```

[link](https://github.com/open-dollar/od-contracts/blob/v1.5.5-audit//src/contracts/proxies/ODProxy.sol#L8-L8) , [link](https://github.com/open-dollar/od-contracts/blob/v1.5.5-audit//src/contracts/proxies/ODProxy.sol#L10-L10)


```solidity

File: src/contracts/proxies/Vault721.sol

14:   error NotGovernor();

15:   error ProxyAlreadyExist();

16:   error ZeroAddress();


```

[link](https://github.com/open-dollar/od-contracts/blob/v1.5.5-audit//src/contracts/proxies/Vault721.sol#L14-L14) , [link](https://github.com/open-dollar/od-contracts/blob/v1.5.5-audit//src/contracts/proxies/Vault721.sol#L15-L15), [link](https://github.com/open-dollar/od-contracts/blob/v1.5.5-audit//src/contracts/proxies/Vault721.sol#L16-L16)


</details>


### [NC&#x2011;9] Consider using `delete` rather than assigning `zero` to clear values 
The `delete` keyword more closely matches the semantics of what is being done, and draws more attention to the changing of state, which may lead to a more thorough audit of its associated logic


*There are 3 instances of this issue:*



<details>
<summary>see instances</summary>


```solidity
File: src/contracts/AccountingEngine.sol

131:     debtQueue[_debtBlockTimestamp] = 0;

248:     totalQueuedDebt = 0;

249:     totalOnAuctionDebt = 0;


```

[link](https://github.com/open-dollar/od-contracts/blob/v1.5.5-audit//src/contracts/AccountingEngine.sol#L131-L131) , [link](https://github.com/open-dollar/od-contracts/blob/v1.5.5-audit//src/contracts/AccountingEngine.sol#L248-L248), [link](https://github.com/open-dollar/od-contracts/blob/v1.5.5-audit//src/contracts/AccountingEngine.sol#L249-L249)


</details>


### [NC&#x2011;10] Dependence on external protocols 
External protocols should be monitored as such dependencies may introduce vulnerabilities if a vulnerability is found /introduced in the external protocol


*There are 8 instances of this issue:*



<details>
<summary>see instances</summary>


```solidity
File: src/contracts/oracles/CamelotRelayer.sol

10: import {OracleLibrary} from '@uniswap/v3-periphery/contracts/libraries/OracleLibrary.sol';


```

[link](https://github.com/open-dollar/od-contracts/blob/v1.5.5-audit//src/contracts/oracles/CamelotRelayer.sol#L10-L10) 


```solidity

File: src/contracts/oracles/UniV3Relayer.sol

7: import {IUniswapV3Factory} from '@uniswap/v3-core/contracts/interfaces/IUniswapV3Factory.sol';

8: import {OracleLibrary, IUniswapV3Pool} from '@uniswap/v3-periphery/contracts/libraries/OracleLibrary.sol';

9: import {UNISWAP_V3_FACTORY, GOERLI_UNISWAP_V3_FACTORY} from '@script/Registry.s.sol';

18:   address internal constant _UNI_V3_FACTORY = GOERLI_UNISWAP_V3_FACTORY;

48:     uniV3Pool = IUniswapV3Factory(_UNI_V3_FACTORY).getPool(_baseToken, _quoteToken, _feeTier);

51:     address _token0 = IUniswapV3Pool(uniV3Pool).token0();

52:     address _token1 = IUniswapV3Pool(uniV3Pool).token1();


```

[link](https://github.com/open-dollar/od-contracts/blob/v1.5.5-audit//src/contracts/oracles/UniV3Relayer.sol#L7-L7) , [link](https://github.com/open-dollar/od-contracts/blob/v1.5.5-audit//src/contracts/oracles/UniV3Relayer.sol#L8-L8), [link](https://github.com/open-dollar/od-contracts/blob/v1.5.5-audit//src/contracts/oracles/UniV3Relayer.sol#L9-L9), [link](https://github.com/open-dollar/od-contracts/blob/v1.5.5-audit//src/contracts/oracles/UniV3Relayer.sol#L18-L18), [link](https://github.com/open-dollar/od-contracts/blob/v1.5.5-audit//src/contracts/oracles/UniV3Relayer.sol#L48-L48), [link](https://github.com/open-dollar/od-contracts/blob/v1.5.5-audit//src/contracts/oracles/UniV3Relayer.sol#L51-L51), [link](https://github.com/open-dollar/od-contracts/blob/v1.5.5-audit//src/contracts/oracles/UniV3Relayer.sol#L52-L52)


</details>


### [NC&#x2011;11] Empty bytes check is missing 
When developing smart contracts in Solidity, it's crucial to validate the inputs of your functions. This includes ensuring that the bytes parameters are not empty, especially when they represent crucial data such as addresses, identifiers, or raw data that the contract needs to process.
Missing empty bytes checks can lead to unexpected behaviour in your contract.For instance, certain operations might fail, produce incorrect results, or consume unnecessary gas when performed with empty bytes.Moreover, missing input validation can potentially expose your contract to malicious activity, including exploitation of unhandled edge cases.
To mitigate these issues, always validate that bytes parameters are not empty when the logic of your contract requires it.


*There are 14 instances of this issue:*



<details>
<summary>see instances</summary>


```solidity
File: src/contracts/AccountingEngine.sol

//@audit  ,_data are not checked
283:   function _modifyParameters(bytes32 _param, bytes memory _data) internal override {
284:     uint256 _uint256 = _data.toUint256();


```

[link](https://github.com/open-dollar/od-contracts/blob/v1.5.5-audit//src/contracts/AccountingEngine.sol#L283-L284) 


```solidity

File: src/contracts/gov/ODGovernor.sol

//@audit  ,descriptionHash are not checked
104:   function _execute(
105:     uint256 proposalId,
106:     address[] memory targets,
107:     uint256[] memory values,
108:     bytes[] memory calldatas,
109:     bytes32 descriptionHash
110:   ) internal override(Governor, GovernorTimelockControl) {

//@audit  ,descriptionHash are not checked
117:   function _cancel(
118:     address[] memory targets,
119:     uint256[] memory values,
120:     bytes[] memory calldatas,
121:     bytes32 descriptionHash
122:   ) internal override(Governor, GovernorTimelockControl) returns (uint256) {

//@audit  ,interfaceId are not checked
136:   function supportsInterface(bytes4 interfaceId)
137:     public
138:     view
139:     override(Governor, IERC165, GovernorTimelockControl)
140:     returns (bool)
141:   {


```

[link](https://github.com/open-dollar/od-contracts/blob/v1.5.5-audit//src/contracts/gov/ODGovernor.sol#L104-L110) , [link](https://github.com/open-dollar/od-contracts/blob/v1.5.5-audit//src/contracts/gov/ODGovernor.sol#L117-L122), [link](https://github.com/open-dollar/od-contracts/blob/v1.5.5-audit//src/contracts/gov/ODGovernor.sol#L136-L141)


```solidity

File: src/contracts/proxies/ODProxy.sol

//@audit  ,_data are not checked
26:   function execute(address _target, bytes memory _data) external payable onlyOwner returns (bytes memory _response) {
27:     if (_target == address(0)) revert TargetAddressRequired();


```

[link](https://github.com/open-dollar/od-contracts/blob/v1.5.5-audit//src/contracts/proxies/ODProxy.sol#L26-L27) 


```solidity

File: src/contracts/proxies/ODSafeManager.sol

//@audit  ,_cType are not checked
78:   function getSafes(address _usr, bytes32 _cType) external view returns (uint256[] memory _safes) {
79:     _safes = _usrSafesPerCollat[_usr][_cType].values();

//@audit  ,_cType are not checked
118:   function openSAFE(bytes32 _cType, address _usr) external returns (uint256 _id) {
119:     if (_usr == address(0)) revert ZeroAddress();

//@audit  ,_cType are not checked
175:   function transferCollateral(bytes32 _cType, uint256 _safe, address _dst, uint256 _wad) external safeAllowed(_safe) {
176:     SAFEData memory _sData = _safeData[_safe];


```

[link](https://github.com/open-dollar/od-contracts/blob/v1.5.5-audit//src/contracts/proxies/ODSafeManager.sol#L78-L79) , [link](https://github.com/open-dollar/od-contracts/blob/v1.5.5-audit//src/contracts/proxies/ODSafeManager.sol#L118-L119), [link](https://github.com/open-dollar/od-contracts/blob/v1.5.5-audit//src/contracts/proxies/ODSafeManager.sol#L175-L176)


```solidity

File: src/contracts/proxies/actions/BasicActions.sol

//@audit  ,_cType are not checked
31:   function _getGeneratedDeltaDebt(
32:     address _safeEngine,
33:     bytes32 _cType,
34:     address _safeHandler,
35:     uint256 _deltaWad
36:   ) internal view returns (int256 _deltaDebt) {

//@audit  ,_cType are not checked
53:   function _getRepaidDeltaDebt(
54:     address _safeEngine,
55:     bytes32 _cType,
56:     address _safeHandler
57:   ) internal view returns (int256 _deltaDebt) {

//@audit  ,_cType are not checked
72:   function _getRepaidDebt(
73:     address _safeEngine,
74:     address _usr,
75:     bytes32 _cType,
76:     address _safeHandler
77:   ) internal view returns (uint256 _deltaWad) {

//@audit  ,_cType are not checked
142:   function _openSAFE(address _manager, bytes32 _cType, address _usr) internal returns (uint256 _safeId) {
143:     _safeId = ODSafeManager(_manager).openSAFE(_cType, _usr);

//@audit  ,_cType are not checked
226:   function openSAFE(address _manager, bytes32 _cType, address _usr) external delegateCall returns (uint256 _safeId) {
227:     return _openSAFE(_manager, _cType, _usr);

//@audit  ,_cType are not checked
328:   function openLockTokenCollateralAndGenerateDebt(
329:     address _manager,
330:     address _taxCollector,
331:     address _collateralJoin,
332:     address _coinJoin,
333:     bytes32 _cType,
334:     uint256 _collateralAmount,
335:     uint256 _deltaWad
336:   ) external delegateCall returns (uint256 _safe) {


```

[link](https://github.com/open-dollar/od-contracts/blob/v1.5.5-audit//src/contracts/proxies/actions/BasicActions.sol#L31-L36) , [link](https://github.com/open-dollar/od-contracts/blob/v1.5.5-audit//src/contracts/proxies/actions/BasicActions.sol#L53-L57), [link](https://github.com/open-dollar/od-contracts/blob/v1.5.5-audit//src/contracts/proxies/actions/BasicActions.sol#L72-L77), [link](https://github.com/open-dollar/od-contracts/blob/v1.5.5-audit//src/contracts/proxies/actions/BasicActions.sol#L142-L143), [link](https://github.com/open-dollar/od-contracts/blob/v1.5.5-audit//src/contracts/proxies/actions/BasicActions.sol#L226-L227), [link](https://github.com/open-dollar/od-contracts/blob/v1.5.5-audit//src/contracts/proxies/actions/BasicActions.sol#L328-L336)


</details>


### [NC&#x2011;12] Events are missing sender information 
When an action is triggered based on a user's action, not being able to filter based on who triggered the action makes event processing a lot more cumbersome. Including the `msg.sender` the events of these types of action will make events much more useful to end users, especially when `msg.sender` is not `tx.origin`.


*There are 8 instances of this issue:*



<details>
<summary>see instances</summary>


```solidity
File: src/contracts/AccountingEngine.sol

119:     emit PushDebtToQueue(block.timestamp, _debtBlock);

133:     emit PopDebtFromQueue(_debtBlockTimestamp, _debtBlock);

169:     emit CancelDebt(_rad, _coinBalance - _rad, safeEngine.debtBalance(address(this)));

192:     emit AuctionDebt(_id, _params.debtAuctionMintedTokens, _params.debtAuctionBidSize);

220:       emit AuctionSurplus(_id, 0, _params.surplusAmount.wmul(ONE_HUNDRED_WAD - _params.surplusTransferPercentage));

234:       emit TransferSurplus(extraSurplusReceiver, _params.surplusAmount.wmul(_params.surplusTransferPercentage));

276:       emit TransferSurplus(postSettlementSurplusDrain, _coinBalance);


```

[link](https://github.com/open-dollar/od-contracts/blob/v1.5.5-audit//src/contracts/AccountingEngine.sol#L119-L119) , [link](https://github.com/open-dollar/od-contracts/blob/v1.5.5-audit//src/contracts/AccountingEngine.sol#L133-L133), [link](https://github.com/open-dollar/od-contracts/blob/v1.5.5-audit//src/contracts/AccountingEngine.sol#L169-L169), [link](https://github.com/open-dollar/od-contracts/blob/v1.5.5-audit//src/contracts/AccountingEngine.sol#L192-L192), [link](https://github.com/open-dollar/od-contracts/blob/v1.5.5-audit//src/contracts/AccountingEngine.sol#L220-L220), [link](https://github.com/open-dollar/od-contracts/blob/v1.5.5-audit//src/contracts/AccountingEngine.sol#L234-L234), [link](https://github.com/open-dollar/od-contracts/blob/v1.5.5-audit//src/contracts/AccountingEngine.sol#L276-L276)


```solidity

File: src/contracts/factories/CamelotRelayerFactory.sol

30:     emit NewCamelotRelayer(address(_camelotRelayer), _baseToken, _quoteToken, _quotePeriod);


```

[link](https://github.com/open-dollar/od-contracts/blob/v1.5.5-audit//src/contracts/factories/CamelotRelayerFactory.sol#L30-L30) 


</details>


### [NC&#x2011;13] Events may be emitted out of order due to reentrancy 
Ensure that events follow the best practice of check-effects-interaction, and are emitted before external calls


*There are 15 instances of this issue:*



<details>
<summary>see instances</summary>


```solidity
File: src/contracts/AccountingEngine.sol

155:     emit SettleDebt(_rad, _newCoinBalance, _newDebtBalance);

169:     emit CancelDebt(_rad, _coinBalance - _rad, safeEngine.debtBalance(address(this)));

234:       emit TransferSurplus(extraSurplusReceiver, _params.surplusAmount.wmul(_params.surplusTransferPercentage));

276:       emit TransferSurplus(postSettlementSurplusDrain, _coinBalance);


```

[link](https://github.com/open-dollar/od-contracts/blob/v1.5.5-audit//src/contracts/AccountingEngine.sol#L155-L155) , [link](https://github.com/open-dollar/od-contracts/blob/v1.5.5-audit//src/contracts/AccountingEngine.sol#L169-L169), [link](https://github.com/open-dollar/od-contracts/blob/v1.5.5-audit//src/contracts/AccountingEngine.sol#L234-L234), [link](https://github.com/open-dollar/od-contracts/blob/v1.5.5-audit//src/contracts/AccountingEngine.sol#L276-L276)


```solidity

File: src/contracts/factories/CamelotRelayerFactory.sol

30:     emit NewCamelotRelayer(address(_camelotRelayer), _baseToken, _quoteToken, _quotePeriod);


```

[link](https://github.com/open-dollar/od-contracts/blob/v1.5.5-audit//src/contracts/factories/CamelotRelayerFactory.sol#L30-L30) 


```solidity

File: src/contracts/proxies/ODSafeManager.sol

131:     emit OpenSAFE(msg.sender, _usr, _safeId);

151:     emit TransferSAFEOwnership(msg.sender, _safe, _dst);

164:     emit ModifySAFECollateralization(msg.sender, _safe, _deltaCollateral, _deltaDebt);

171:     emit TransferCollateral(msg.sender, _safe, _dst, _wad);

178:     emit TransferCollateral(msg.sender, _cType, _safe, _dst, _wad);

185:     emit TransferInternalCoins(msg.sender, _safe, _dst, _rad);

201:     emit QuitSystem(msg.sender, _safe, _dst);

213:     emit EnterSystem(msg.sender, _src, _safe);

231:     emit MoveSAFE(msg.sender, _safeSrc, _safeDst);

252:     emit ProtectSAFE(msg.sender, _safe, _liquidationEngine, _saviour);


```

[link](https://github.com/open-dollar/od-contracts/blob/v1.5.5-audit//src/contracts/proxies/ODSafeManager.sol#L131-L131) , [link](https://github.com/open-dollar/od-contracts/blob/v1.5.5-audit//src/contracts/proxies/ODSafeManager.sol#L151-L151), [link](https://github.com/open-dollar/od-contracts/blob/v1.5.5-audit//src/contracts/proxies/ODSafeManager.sol#L164-L164), [link](https://github.com/open-dollar/od-contracts/blob/v1.5.5-audit//src/contracts/proxies/ODSafeManager.sol#L171-L171), [link](https://github.com/open-dollar/od-contracts/blob/v1.5.5-audit//src/contracts/proxies/ODSafeManager.sol#L178-L178), [link](https://github.com/open-dollar/od-contracts/blob/v1.5.5-audit//src/contracts/proxies/ODSafeManager.sol#L185-L185), [link](https://github.com/open-dollar/od-contracts/blob/v1.5.5-audit//src/contracts/proxies/ODSafeManager.sol#L201-L201), [link](https://github.com/open-dollar/od-contracts/blob/v1.5.5-audit//src/contracts/proxies/ODSafeManager.sol#L213-L213), [link](https://github.com/open-dollar/od-contracts/blob/v1.5.5-audit//src/contracts/proxies/ODSafeManager.sol#L231-L231), [link](https://github.com/open-dollar/od-contracts/blob/v1.5.5-audit//src/contracts/proxies/ODSafeManager.sol#L252-L252)


</details>


### [NC&#x2011;14] It is standard for all external and public functions to be override from an interface 
This is to ensure the whole API is extracted in a interface


*There are 55 instances of this issue:*



<details>
<summary>see instances</summary>


```solidity
File: src/contracts/AccountingEngine.sol

61:   function params() external view returns (AccountingEngineParams memory _accEngineParams) {
62:     return _params;

104:   function unqueuedUnauctionedDebt() external view returns (uint256 __unqueuedUnauctionedDebt) {
105:     return _unqueuedUnauctionedDebt(safeEngine.debtBalance(address(this)));

115:   function pushDebtToQueue(uint256 _debtBlock) external isAuthorized {
116:     debtQueue[block.timestamp] = debtQueue[block.timestamp] + _debtBlock;

123:   function popDebtFromQueue(uint256 _debtBlockTimestamp) external {
124:     if (block.timestamp < _debtBlockTimestamp + _params.popDebtDelay) revert AccEng_PopDebtCooldown();

139:   function settleDebt(uint256 _rad) external {
140:     _settleDebt(safeEngine.coinBalance(address(this)), safeEngine.debtBalance(address(this)), _rad);

159:   function cancelAuctionedDebtWithSurplus(uint256 _rad) external {
160:     if (_rad > totalOnAuctionDebt) revert AccEng_InsufficientDebt();

175:   function auctionDebt() external returns (uint256 _id) {
176:     if (_params.debtAuctionBidSize == 0) revert AccEng_DebtAuctionDisabled();

198:   function auctionSurplus() external returns (uint256 _id) {
199:     if(_params.surplusTransferPercentage > WAD) revert AccEng_surplusTransferPercentOverLimit();

260:   function transferPostSettlementSurplus() external whenDisabled {
261:     if (address(postSettlementSurplusDrain) == address(0)) revert AccEng_NullSurplusReceiver();


```

[link](https://github.com/open-dollar/od-contracts/blob/v1.5.5-audit//src/contracts/AccountingEngine.sol#L61-L62) , [link](https://github.com/open-dollar/od-contracts/blob/v1.5.5-audit//src/contracts/AccountingEngine.sol#L104-L105), [link](https://github.com/open-dollar/od-contracts/blob/v1.5.5-audit//src/contracts/AccountingEngine.sol#L115-L116), [link](https://github.com/open-dollar/od-contracts/blob/v1.5.5-audit//src/contracts/AccountingEngine.sol#L123-L124), [link](https://github.com/open-dollar/od-contracts/blob/v1.5.5-audit//src/contracts/AccountingEngine.sol#L139-L140), [link](https://github.com/open-dollar/od-contracts/blob/v1.5.5-audit//src/contracts/AccountingEngine.sol#L159-L160), [link](https://github.com/open-dollar/od-contracts/blob/v1.5.5-audit//src/contracts/AccountingEngine.sol#L175-L176), [link](https://github.com/open-dollar/od-contracts/blob/v1.5.5-audit//src/contracts/AccountingEngine.sol#L198-L199), [link](https://github.com/open-dollar/od-contracts/blob/v1.5.5-audit//src/contracts/AccountingEngine.sol#L260-L261)


```solidity

File: src/contracts/oracles/CamelotRelayer.sol

68:   function getResultWithValidity() external view returns (uint256 _result, bool _validity) {
69:     // If the pool doesn't have enough history return false

91:   function read() external view returns (uint256 _result) {
92:     // This call may revert with 'OLD!' if the pool doesn't have enough cardinality or initialized history


```

[link](https://github.com/open-dollar/od-contracts/blob/v1.5.5-audit//src/contracts/oracles/CamelotRelayer.sol#L68-L69) , [link](https://github.com/open-dollar/od-contracts/blob/v1.5.5-audit//src/contracts/oracles/CamelotRelayer.sol#L91-L92)


```solidity

File: src/contracts/factories/CamelotRelayerFactory.sol

23:   function deployCamelotRelayer(
24:     address _baseToken,
25:     address _quoteToken,
26:     uint32 _quotePeriod
27:   ) external isAuthorized returns (IBaseOracle _camelotRelayer) {

34:   function camelotRelayersList() external view returns (address[] memory _camelotRelayersList) {
35:     return _camelotRelayers.values();


```

[link](https://github.com/open-dollar/od-contracts/blob/v1.5.5-audit//src/contracts/factories/CamelotRelayerFactory.sol#L23-L27) , [link](https://github.com/open-dollar/od-contracts/blob/v1.5.5-audit//src/contracts/factories/CamelotRelayerFactory.sol#L34-L35)


```solidity

File: src/contracts/oracles/UniV3Relayer.sol

74:   function getResultWithValidity() external view returns (uint256 _result, bool _validity) {
75:     // If the pool doesn't have enough history return false

97:   function read() external view returns (uint256 _result) {
98:     // This call may revert with 'OLD!' if the pool doesn't have enough cardinality or initialized history


```

[link](https://github.com/open-dollar/od-contracts/blob/v1.5.5-audit//src/contracts/oracles/UniV3Relayer.sol#L74-L75) , [link](https://github.com/open-dollar/od-contracts/blob/v1.5.5-audit//src/contracts/oracles/UniV3Relayer.sol#L97-L98)


```solidity

File: src/contracts/proxies/ODProxy.sol

26:   function execute(address _target, bytes memory _data) external payable onlyOwner returns (bytes memory _response) {
27:     if (_target == address(0)) revert TargetAddressRequired();


```

[link](https://github.com/open-dollar/od-contracts/blob/v1.5.5-audit//src/contracts/proxies/ODProxy.sol#L26-L27) 


```solidity

File: src/contracts/proxies/Vault721.sol

56:   function initializeManager() external {
57:     if (address(safeManager) == address(0)) _setSafeManager(msg.sender);

63:   function initializeRenderer() external {
64:     if (address(nftRenderer) == address(0)) _setNftRenderer(msg.sender);

70:   function getProxy(address _user) external view returns (address _proxy) {
71:     _proxy = _userRegistry[_user];

77:   function build() external returns (address payable _proxy) {
78:     if (!_isNotProxy(msg.sender)) revert ProxyAlreadyExist();

85:   function build(address _user) external returns (address payable _proxy) {
86:     if (!_isNotProxy(_user)) revert ProxyAlreadyExist();

94:   function mint(address _proxy, uint256 _safeId) external {
95:     require(msg.sender == address(safeManager), 'V721: only safeManager');

104:   function updateNftRenderer(
105:     address _nftRenderer,
106:     address _oracleRelayer,
107:     address _taxCollector,
108:     address _collateralJoinFactory
109:   ) external onlyGovernor nonZero(_oracleRelayer) nonZero(_taxCollector) nonZero(_collateralJoinFactory) {

119:   function updateContractURI(string memory _metaData) external onlyGovernor {
120:     contractMetaData = _metaData;

126:   function setSafeManager(address _safeManager) external onlyGovernor {
127:     _setSafeManager(_safeManager);

133:   function setNftRenderer(address _nftRenderer) external onlyGovernor {
134:     _setNftRenderer(_nftRenderer);

147:   function contractURI() public view returns (string memory uri) {
148:     uri = string.concat('data:application/json;utf8,', contractMetaData);


```

[link](https://github.com/open-dollar/od-contracts/blob/v1.5.5-audit//src/contracts/proxies/Vault721.sol#L56-L57) , [link](https://github.com/open-dollar/od-contracts/blob/v1.5.5-audit//src/contracts/proxies/Vault721.sol#L63-L64), [link](https://github.com/open-dollar/od-contracts/blob/v1.5.5-audit//src/contracts/proxies/Vault721.sol#L70-L71), [link](https://github.com/open-dollar/od-contracts/blob/v1.5.5-audit//src/contracts/proxies/Vault721.sol#L77-L78), [link](https://github.com/open-dollar/od-contracts/blob/v1.5.5-audit//src/contracts/proxies/Vault721.sol#L85-L86), [link](https://github.com/open-dollar/od-contracts/blob/v1.5.5-audit//src/contracts/proxies/Vault721.sol#L94-L95), [link](https://github.com/open-dollar/od-contracts/blob/v1.5.5-audit//src/contracts/proxies/Vault721.sol#L104-L109), [link](https://github.com/open-dollar/od-contracts/blob/v1.5.5-audit//src/contracts/proxies/Vault721.sol#L119-L120), [link](https://github.com/open-dollar/od-contracts/blob/v1.5.5-audit//src/contracts/proxies/Vault721.sol#L126-L127), [link](https://github.com/open-dollar/od-contracts/blob/v1.5.5-audit//src/contracts/proxies/Vault721.sol#L133-L134), [link](https://github.com/open-dollar/od-contracts/blob/v1.5.5-audit//src/contracts/proxies/Vault721.sol#L147-L148)


```solidity

File: src/contracts/proxies/ODSafeManager.sol

73:   function getSafes(address _usr) external view returns (uint256[] memory _safes) {
74:     _safes = _usrSafes[_usr].values();

78:   function getSafes(address _usr, bytes32 _cType) external view returns (uint256[] memory _safes) {
79:     _safes = _usrSafesPerCollat[_usr][_cType].values();

83:   function getSafesData(address _usr)
84:     external
85:     view
86:     returns (uint256[] memory _safes, address[] memory _safeHandlers, bytes32[] memory _cTypes)
87:   {

98:   function safeData(uint256 _safe) external view returns (SAFEData memory _sData) {
99:     _sData = _safeData[_safe];

105:   function allowSAFE(uint256 _safe, address _usr, uint256 _ok) external safeAllowed(_safe) {
106:     address _owner = _safeData[_safe].owner;

112:   function allowHandler(address _usr, uint256 _ok) external {
113:     handlerCan[msg.sender][_usr] = _ok;

118:   function openSAFE(bytes32 _cType, address _usr) external returns (uint256 _id) {
119:     if (_usr == address(0)) revert ZeroAddress();

136:   function transferSAFEOwnership(uint256 _safe, address _dst) external {
137:     require(msg.sender == address(vault721), 'SafeMngr: Only Vault721');

155:   function modifySAFECollateralization(
156:     uint256 _safe,
157:     int256 _deltaCollateral,
158:     int256 _deltaDebt
159:   ) external safeAllowed(_safe) {

168:   function transferCollateral(uint256 _safe, address _dst, uint256 _wad) external safeAllowed(_safe) {
169:     SAFEData memory _sData = _safeData[_safe];

175:   function transferCollateral(bytes32 _cType, uint256 _safe, address _dst, uint256 _wad) external safeAllowed(_safe) {
176:     SAFEData memory _sData = _safeData[_safe];

182:   function transferInternalCoins(uint256 _safe, address _dst, uint256 _rad) external safeAllowed(_safe) {
183:     SAFEData memory _sData = _safeData[_safe];

189:   function quitSystem(uint256 _safe, address _dst) external safeAllowed(_safe) handlerAllowed(_dst) {
190:     SAFEData memory _sData = _safeData[_safe];

205:   function enterSystem(address _src, uint256 _safe) external handlerAllowed(_src) safeAllowed(_safe) {
206:     SAFEData memory _sData = _safeData[_safe];

217:   function moveSAFE(uint256 _safeSrc, uint256 _safeDst) external safeAllowed(_safeSrc) safeAllowed(_safeDst) {
218:     SAFEData memory _srcData = _safeData[_safeSrc];

235:   function addSAFE(uint256 _safe) external {
236:     SAFEData memory _sData = _safeData[_safe];

242:   function removeSAFE(uint256 _safe) external safeAllowed(_safe) {
243:     SAFEData memory _sData = _safeData[_safe];

249:   function protectSAFE(uint256 _safe, address _liquidationEngine, address _saviour) external safeAllowed(_safe) {
250:     SAFEData memory _sData = _safeData[_safe];


```

[link](https://github.com/open-dollar/od-contracts/blob/v1.5.5-audit//src/contracts/proxies/ODSafeManager.sol#L73-L74) , [link](https://github.com/open-dollar/od-contracts/blob/v1.5.5-audit//src/contracts/proxies/ODSafeManager.sol#L78-L79), [link](https://github.com/open-dollar/od-contracts/blob/v1.5.5-audit//src/contracts/proxies/ODSafeManager.sol#L83-L87), [link](https://github.com/open-dollar/od-contracts/blob/v1.5.5-audit//src/contracts/proxies/ODSafeManager.sol#L98-L99), [link](https://github.com/open-dollar/od-contracts/blob/v1.5.5-audit//src/contracts/proxies/ODSafeManager.sol#L105-L106), [link](https://github.com/open-dollar/od-contracts/blob/v1.5.5-audit//src/contracts/proxies/ODSafeManager.sol#L112-L113), [link](https://github.com/open-dollar/od-contracts/blob/v1.5.5-audit//src/contracts/proxies/ODSafeManager.sol#L118-L119), [link](https://github.com/open-dollar/od-contracts/blob/v1.5.5-audit//src/contracts/proxies/ODSafeManager.sol#L136-L137), [link](https://github.com/open-dollar/od-contracts/blob/v1.5.5-audit//src/contracts/proxies/ODSafeManager.sol#L155-L159), [link](https://github.com/open-dollar/od-contracts/blob/v1.5.5-audit//src/contracts/proxies/ODSafeManager.sol#L168-L169), [link](https://github.com/open-dollar/od-contracts/blob/v1.5.5-audit//src/contracts/proxies/ODSafeManager.sol#L175-L176), [link](https://github.com/open-dollar/od-contracts/blob/v1.5.5-audit//src/contracts/proxies/ODSafeManager.sol#L182-L183), [link](https://github.com/open-dollar/od-contracts/blob/v1.5.5-audit//src/contracts/proxies/ODSafeManager.sol#L189-L190), [link](https://github.com/open-dollar/od-contracts/blob/v1.5.5-audit//src/contracts/proxies/ODSafeManager.sol#L205-L206), [link](https://github.com/open-dollar/od-contracts/blob/v1.5.5-audit//src/contracts/proxies/ODSafeManager.sol#L217-L218), [link](https://github.com/open-dollar/od-contracts/blob/v1.5.5-audit//src/contracts/proxies/ODSafeManager.sol#L235-L236), [link](https://github.com/open-dollar/od-contracts/blob/v1.5.5-audit//src/contracts/proxies/ODSafeManager.sol#L242-L243), [link](https://github.com/open-dollar/od-contracts/blob/v1.5.5-audit//src/contracts/proxies/ODSafeManager.sol#L249-L250)


```solidity

File: src/contracts/proxies/actions/BasicActions.sol

226:   function openSAFE(address _manager, bytes32 _cType, address _usr) external delegateCall returns (uint256 _safeId) {
227:     return _openSAFE(_manager, _cType, _usr);

231:   function generateDebt(
232:     address _manager,
233:     address _taxCollector,
234:     address _coinJoin,
235:     uint256 _safeId,
236:     uint256 _deltaWad
237:   ) external delegateCall {

242:   function repayDebt(
243:     address _manager,
244:     address _taxCollector,
245:     address _coinJoin,
246:     uint256 _safeId,
247:     uint256 _deltaWad
248:   ) external delegateCall {

253:   function lockTokenCollateral(
254:     address _manager,
255:     address _collateralJoin,
256:     uint256 _safeId,
257:     uint256 _deltaWad
258:   ) external delegateCall {

269:   function freeTokenCollateral(
270:     address _manager,
271:     address _collateralJoin,
272:     uint256 _safeId,
273:     uint256 _deltaWad
274:   ) external delegateCall {

282:   function repayAllDebt(
283:     address _manager,
284:     address _taxCollector,
285:     address _coinJoin,
286:     uint256 _safeId
287:   ) external delegateCall {

313:   function lockTokenCollateralAndGenerateDebt(
314:     address _manager,
315:     address _taxCollector,
316:     address _collateralJoin,
317:     address _coinJoin,
318:     uint256 _safe,
319:     uint256 _collateralAmount,
320:     uint256 _deltaWad
321:   ) external delegateCall {

328:   function openLockTokenCollateralAndGenerateDebt(
329:     address _manager,
330:     address _taxCollector,
331:     address _collateralJoin,
332:     address _coinJoin,
333:     bytes32 _cType,
334:     uint256 _collateralAmount,
335:     uint256 _deltaWad
336:   ) external delegateCall returns (uint256 _safe) {

345:   function repayDebtAndFreeTokenCollateral(
346:     address _manager,
347:     address _taxCollector,
348:     address _collateralJoin,
349:     address _coinJoin,
350:     uint256 _safeId,
351:     uint256 _collateralWad,
352:     uint256 _debtWad
353:   ) external delegateCall {

374:   function repayAllDebtAndFreeTokenCollateral(
375:     address _manager,
376:     address _taxCollector,
377:     address _collateralJoin,
378:     address _coinJoin,
379:     uint256 _safeId,
380:     uint256 _collateralWad
381:   ) external delegateCall {


```

[link](https://github.com/open-dollar/od-contracts/blob/v1.5.5-audit//src/contracts/proxies/actions/BasicActions.sol#L226-L227) , [link](https://github.com/open-dollar/od-contracts/blob/v1.5.5-audit//src/contracts/proxies/actions/BasicActions.sol#L231-L237), [link](https://github.com/open-dollar/od-contracts/blob/v1.5.5-audit//src/contracts/proxies/actions/BasicActions.sol#L242-L248), [link](https://github.com/open-dollar/od-contracts/blob/v1.5.5-audit//src/contracts/proxies/actions/BasicActions.sol#L253-L258), [link](https://github.com/open-dollar/od-contracts/blob/v1.5.5-audit//src/contracts/proxies/actions/BasicActions.sol#L269-L274), [link](https://github.com/open-dollar/od-contracts/blob/v1.5.5-audit//src/contracts/proxies/actions/BasicActions.sol#L282-L287), [link](https://github.com/open-dollar/od-contracts/blob/v1.5.5-audit//src/contracts/proxies/actions/BasicActions.sol#L313-L321), [link](https://github.com/open-dollar/od-contracts/blob/v1.5.5-audit//src/contracts/proxies/actions/BasicActions.sol#L328-L336), [link](https://github.com/open-dollar/od-contracts/blob/v1.5.5-audit//src/contracts/proxies/actions/BasicActions.sol#L345-L353), [link](https://github.com/open-dollar/od-contracts/blob/v1.5.5-audit//src/contracts/proxies/actions/BasicActions.sol#L374-L381)


</details>


### [NC&#x2011;15] NatSpec documentation for `function` is missing 
It is recommended that Solidity contracts are fully annotated using NatSpec for all public interfaces (everything in the ABI). It is clearly stated in the Solidity official documentation. In complex projects such as Defi, the interpretation of all functions and their arguments and returns is important for code readability and auditability.[source](https://docs.soliditylang.org/en/v0.8.15/natspec-format.html)


*There are 12 instances of this issue:*



<details>
<summary>see instances</summary>


```solidity
File: src/contracts/AccountingEngine.sol

108:   function _unqueuedUnauctionedDebt(uint256 _debtBalance) internal view returns (uint256 __unqueuedUnauctionedDebt) {

143:   function _settleDebt(


```

[link](https://github.com/open-dollar/od-contracts/blob/v1.5.5-audit//src/contracts/AccountingEngine.sol#L108-L108) , [link](https://github.com/open-dollar/od-contracts/blob/v1.5.5-audit//src/contracts/AccountingEngine.sol#L143-L143)


```solidity

File: src/contracts/oracles/CamelotRelayer.sol

40:   constructor(address _baseToken, address _quoteToken, uint32 _quotePeriod) {

103:   function _parseResult(uint256 _quoteResult) internal view returns (uint256 _result) {


```

[link](https://github.com/open-dollar/od-contracts/blob/v1.5.5-audit//src/contracts/oracles/CamelotRelayer.sol#L40-L40) , [link](https://github.com/open-dollar/od-contracts/blob/v1.5.5-audit//src/contracts/oracles/CamelotRelayer.sol#L103-L103)


```solidity

File: src/contracts/factories/CamelotRelayerFactory.sol

20:   constructor() Authorizable(msg.sender) {}

23:   function deployCamelotRelayer(

34:   function camelotRelayersList() external view returns (address[] memory _camelotRelayersList) {


```

[link](https://github.com/open-dollar/od-contracts/blob/v1.5.5-audit//src/contracts/factories/CamelotRelayerFactory.sol#L20-L20) , [link](https://github.com/open-dollar/od-contracts/blob/v1.5.5-audit//src/contracts/factories/CamelotRelayerFactory.sol#L23-L23), [link](https://github.com/open-dollar/od-contracts/blob/v1.5.5-audit//src/contracts/factories/CamelotRelayerFactory.sol#L34-L34)


```solidity

File: src/contracts/factories/CamelotRelayerChild.sol

16:   constructor(


```

[link](https://github.com/open-dollar/od-contracts/blob/v1.5.5-audit//src/contracts/factories/CamelotRelayerChild.sol#L16-L16) 


```solidity

File: src/contracts/proxies/ODProxy.sol

14:   constructor(address _owner) {

26:   function execute(address _target, bytes memory _data) external payable onlyOwner returns (bytes memory _response) {


```

[link](https://github.com/open-dollar/od-contracts/blob/v1.5.5-audit//src/contracts/proxies/ODProxy.sol#L14-L14) , [link](https://github.com/open-dollar/od-contracts/blob/v1.5.5-audit//src/contracts/proxies/ODProxy.sol#L26-L26)


```solidity

File: src/contracts/proxies/ODSafeManager.sol

64:   constructor(address _safeEngine, address _vault721) {

136:   function transferSAFEOwnership(uint256 _safe, address _dst) external {


```

[link](https://github.com/open-dollar/od-contracts/blob/v1.5.5-audit//src/contracts/proxies/ODSafeManager.sol#L64-L64) , [link](https://github.com/open-dollar/od-contracts/blob/v1.5.5-audit//src/contracts/proxies/ODSafeManager.sol#L136-L136)


</details>


### [NC&#x2011;16] Function ordering does not follow the Solidity style guide 
According to the [Solidity style guide](https://docs.soliditylang.org/en/v0.8.17/style-guide.html#order-of-functions), functions should be laid out in the following order :`constructor()`, `receive()`, `fallback()`, `external`, `public`, `internal`, `private`, but the cases below do not follow this pattern


*There are 3 instances of this issue:*



<details>
<summary>see instances</summary>


```solidity
File: src/contracts/AccountingEngine.sol

115:   function pushDebtToQueue(uint256 _debtBlock) external isAuthorized {


```

[link](https://github.com/open-dollar/od-contracts/blob/v1.5.5-audit//src/contracts/AccountingEngine.sol#L115-L115) 


```solidity

File: src/contracts/gov/ODGovernor.sol

136:   function supportsInterface(bytes4 interfaceId)


```

[link](https://github.com/open-dollar/od-contracts/blob/v1.5.5-audit//src/contracts/gov/ODGovernor.sol#L136-L136) 


```solidity

File: src/contracts/proxies/actions/BasicActions.sol

226:   function openSAFE(address _manager, bytes32 _cType, address _usr) external delegateCall returns (uint256 _safeId) {


```

[link](https://github.com/open-dollar/od-contracts/blob/v1.5.5-audit//src/contracts/proxies/actions/BasicActions.sol#L226-L226) 


</details>


### [NC&#x2011;17] Duplicated `require()`/`revert()` checks should be refactored to a modifier or function 
The compiler will inline the function, which will avoid `JUMP` instructions usually associated with functions


*There are 2 instances of this issue:*



<details>
<summary>see instances</summary>


```solidity
File: src/contracts/AccountingEngine.sol

148:     if (_rad > _coinBalance) revert AccEng_InsufficientSurplus();

201:     if (extraSurplusReceiver == address(0)) revert AccEng_NullSurplusReceiver();


```

[link](https://github.com/open-dollar/od-contracts/blob/v1.5.5-audit//src/contracts/AccountingEngine.sol#L148-L148) , [link](https://github.com/open-dollar/od-contracts/blob/v1.5.5-audit//src/contracts/AccountingEngine.sol#L201-L201)


</details>


### [NC&#x2011;18] Some if-statement can be converted to a ternary 
Improving code readability and compactness is an integral part of optimal programming practices. The use of ternary operators in place of if-else conditions is one such measure. Ternary operators allow us to write conditional statements in a more concise manner, thereby enhancing readability and simplicity. They follow the syntax `condition ? exprIfTrue : exprIfFalse`, which interprets as "if the condition is true, evaluate to `exprIfTrue`, else evaluate to `exprIfFalse`". By adopting this approach, we make our code more streamlined and intuitive, which could potentially aid in better understanding and maintenance of the codebase.


*There are 1 instances of this issue:*



<details>
<summary>see instances</summary>


```solidity
File: src/contracts/proxies/Vault721.sol

192:       if (_isNotProxy(to)) {
193:         proxy = _build(to);
194:       } else {


```

[link](https://github.com/open-dollar/od-contracts/blob/v1.5.5-audit//src/contracts/proxies/Vault721.sol#L192-L194) 


</details>


### [NC&#x2011;19] Contract implements interface without extending the interface 
Not extending the interface may lead to the wrong function signature being used, leading to unexpected behavior. If the interface is in fact being implemented, use the `override` keyword to indicate that fact


*There are 8 instances of this issue:*



<details>
<summary>see instances</summary>


```solidity
File: src/contracts/AccountingEngine.sol

//@audit IAccountingEngine.transferPostSettlementSurplus(),  
23: contract AccountingEngine is Authorizable, Modifiable, Disableable, IAccountingEngine {


```

[link](https://github.com/open-dollar/od-contracts/blob/v1.5.5-audit//src/contracts/AccountingEngine.sol#L23-L23) 


```solidity

File: src/contracts/oracles/CamelotRelayer.sol

//@audit IBaseOracle.read(),  
18: contract CamelotRelayer is IBaseOracle, ICamelotRelayer {

//@audit ICamelotRelayer.read(),  
18: contract CamelotRelayer is IBaseOracle, ICamelotRelayer {


```

[link](https://github.com/open-dollar/od-contracts/blob/v1.5.5-audit//src/contracts/oracles/CamelotRelayer.sol#L18-L18) , [link](https://github.com/open-dollar/od-contracts/blob/v1.5.5-audit//src/contracts/oracles/CamelotRelayer.sol#L18-L18)


```solidity

File: src/contracts/factories/CamelotRelayerFactory.sol

//@audit ICamelotRelayerFactory.camelotRelayersList(),  
13: contract CamelotRelayerFactory is Authorizable, ICamelotRelayerFactory {


```

[link](https://github.com/open-dollar/od-contracts/blob/v1.5.5-audit//src/contracts/factories/CamelotRelayerFactory.sol#L13-L13) 


```solidity

File: src/contracts/oracles/UniV3Relayer.sol

//@audit IBaseOracle.read(),  
16: contract UniV3Relayer is IBaseOracle, IUniV3Relayer {

//@audit IUniV3Relayer.read(),  
16: contract UniV3Relayer is IBaseOracle, IUniV3Relayer {


```

[link](https://github.com/open-dollar/od-contracts/blob/v1.5.5-audit//src/contracts/oracles/UniV3Relayer.sol#L16-L16) , [link](https://github.com/open-dollar/od-contracts/blob/v1.5.5-audit//src/contracts/oracles/UniV3Relayer.sol#L16-L16)


```solidity

File: src/contracts/proxies/ODSafeManager.sol

//@audit IODSafeManager.protectSAFE(),  
20: contract ODSafeManager is IODSafeManager {


```

[link](https://github.com/open-dollar/od-contracts/blob/v1.5.5-audit//src/contracts/proxies/ODSafeManager.sol#L20-L20) 


```solidity

File: src/contracts/proxies/actions/BasicActions.sol

//@audit IBasicActions.repayAllDebtAndFreeTokenCollateral(),  
22: contract BasicActions is CommonActions, IBasicActions {


```

[link](https://github.com/open-dollar/od-contracts/blob/v1.5.5-audit//src/contracts/proxies/actions/BasicActions.sol#L22-L22) 


</details>


### [NC&#x2011;20] Imports could be organized more systematically 
The contract used interfaces should be imported first, followed by all other files. The examples below do not follow this layout.


*There are 3 instances of this issue:*



<details>
<summary>see instances</summary>


```solidity
File: src/contracts/proxies/Vault721.sol

6: import {IODSafeManager} from '@interfaces/proxies/IODSafeManager.sol';


```

[link](https://github.com/open-dollar/od-contracts/blob/v1.5.5-audit//src/contracts/proxies/Vault721.sol#L6-L6) 


```solidity

File: src/contracts/proxies/ODSafeManager.sol

5: import {ISAFEEngine} from '@interfaces/ISAFEEngine.sol';


```

[link](https://github.com/open-dollar/od-contracts/blob/v1.5.5-audit//src/contracts/proxies/ODSafeManager.sol#L5-L5) 


```solidity

File: src/contracts/proxies/actions/BasicActions.sol

7: import {ISAFEEngine} from '@interfaces/ISAFEEngine.sol';


```

[link](https://github.com/open-dollar/od-contracts/blob/v1.5.5-audit//src/contracts/proxies/actions/BasicActions.sol#L7-L7) 


</details>


### [NC&#x2011;21] Inconsistent usage of `require`/`error` 
Some parts of the codebase use `require` statements, while others use custom `error`s. Consider refactoring the code to use the same approach: the following findings represent the minority of `require` vs `error`, and they show the first occurance in each file, for brevity.


*There are 5 instances of this issue:*



<details>
<summary>see instances</summary>


```solidity
File: src/contracts/proxies/Vault721.sol

95:     require(msg.sender == address(safeManager), 'V721: only safeManager');

96:     require(_proxyRegistry[_proxy] != address(0), 'V721: non-native proxy');

111:     require(_safeManager != address(0));

188:     require(to != address(0), 'V721: no burn');


```

[link](https://github.com/open-dollar/od-contracts/blob/v1.5.5-audit//src/contracts/proxies/Vault721.sol#L95-L95) , [link](https://github.com/open-dollar/od-contracts/blob/v1.5.5-audit//src/contracts/proxies/Vault721.sol#L96-L96), [link](https://github.com/open-dollar/od-contracts/blob/v1.5.5-audit//src/contracts/proxies/Vault721.sol#L111-L111), [link](https://github.com/open-dollar/od-contracts/blob/v1.5.5-audit//src/contracts/proxies/Vault721.sol#L188-L188)


```solidity

File: src/contracts/proxies/ODSafeManager.sol

137:     require(msg.sender == address(vault721), 'SafeMngr: Only Vault721');


```

[link](https://github.com/open-dollar/od-contracts/blob/v1.5.5-audit//src/contracts/proxies/ODSafeManager.sol#L137-L137) 


</details>


### [NC&#x2011;22] Long lines of code 
Usually lines in source code are limited to [80](https://softwareengineering.stackexchange.com/questions/148677/why-is-80-characters-the-standard-limit-for-code-width) characters. Today's screens are much larger so it's reasonable to stretch this in some cases. The solidity style guide recommends a maximumum line length of [120 characters](https://docs.soliditylang.org/en/v0.8.17/style-guide.html#maximum-line-length), so the lines below should be split when they reach that length.


*There are 5 instances of this issue:*



<details>
<summary>see instances</summary>


```solidity
File: src/contracts/proxies/Vault721.sol

23:     '{"name": "Open Dollar Vaults","description": "Tradable Vaults for the Open Dollar stablecoin protocol. Caution! Trading this NFT means trading the ownership of your Vault in the Open Dollar protocol and all of the assets/collateral inside each Vault.","image": "https://app.opendollar.com/collectionImage.png","external_link": "https://opendollar.com"}';


```

[link](https://github.com/open-dollar/od-contracts/blob/v1.5.5-audit//src/contracts/proxies/Vault721.sol#L23-L23) 


```solidity

File: src/contracts/proxies/SAFEHandler.sol

9:  * @dev    When a new SAFE is created inside ODSafeManager this contract is deployed and calls the SAFEEngine to add permissions to the SAFE manager


```

[link](https://github.com/open-dollar/od-contracts/blob/v1.5.5-audit//src/contracts/proxies/SAFEHandler.sol#L9-L9) 


```solidity

File: src/contracts/proxies/actions/BasicActions.sol

42:       // Calculates the needed deltaDebt so together with the existing coins in the safeEngine is enough to exit wad amount of COIN tokens

44:       // This is neeeded due lack of precision. It might need to sum an extra deltaDebt wei (for the given COIN wad amount)

92:    * @dev    Modifies the SAFE collateralization ratio, increasing the debt and sends the COIN amount to the user's address


```

[link](https://github.com/open-dollar/od-contracts/blob/v1.5.5-audit//src/contracts/proxies/actions/BasicActions.sol#L42-L42) , [link](https://github.com/open-dollar/od-contracts/blob/v1.5.5-audit//src/contracts/proxies/actions/BasicActions.sol#L44-L44), [link](https://github.com/open-dollar/od-contracts/blob/v1.5.5-audit//src/contracts/proxies/actions/BasicActions.sol#L92-L92)


</details>


### [NC&#x2011;23] Missing event and or timelock for critical parameter change 
Events help non-contract tools to track changes, and events prevent users from being surprised by changes


*There are 1 instances of this issue:*



<details>
<summary>see instances</summary>


```solidity
File: src/contracts/proxies/Vault721.sol

119:   function updateContractURI(string memory _metaData) external onlyGovernor {


```

[link](https://github.com/open-dollar/od-contracts/blob/v1.5.5-audit//src/contracts/proxies/Vault721.sol#L119-L119) 


</details>


### [NC&#x2011;24] File is missing NatSpec 



*There are 1 instances of this issue:*



<details>
<summary>see instances</summary>


```solidity
File: src/contracts/factories/CamelotRelayerFactory.sol

0: 


```

[link](https://github.com/open-dollar/od-contracts/blob/v1.5.5-audit//src/contracts/factories/CamelotRelayerFactory.sol#L0-L0) 


</details>


### [NC&#x2011;25] Some error strings are not descriptive 
Consider adding more detail to these error strings


*There are 2 instances of this issue:*



<details>
<summary>see instances</summary>


```solidity
File: src/contracts/AccountingEngine.sol

//@audit This message need more details : 0
220:       emit AuctionSurplus(_id, 0, _params.surplusAmount.wmul(ONE_HUNDRED_WAD - _params.surplusTransferPercentage));


```

[link](https://github.com/open-dollar/od-contracts/blob/v1.5.5-audit//src/contracts/AccountingEngine.sol#L220-L220) 


```solidity

File: src/contracts/proxies/Vault721.sol

//@audit This message need more details : V721: no burn
188:     require(to != address(0), 'V721: no burn');


```

[link](https://github.com/open-dollar/od-contracts/blob/v1.5.5-audit//src/contracts/proxies/Vault721.sol#L188-L188) 


</details>


### [NC&#x2011;26] Public state variables shouldn't have a preceding _ in their name 
Remove the _ from the state variable name, ensure you also refactor where these state variables are internally called


*There are 1 instances of this issue:*



<details>
<summary>see instances</summary>


```solidity
File: src/contracts/AccountingEngine.sol

58:   AccountingEngineParams public _params;


```

[link](https://github.com/open-dollar/od-contracts/blob/v1.5.5-audit//src/contracts/AccountingEngine.sol#L58-L58) 


</details>


### [NC&#x2011;27] `override` function arguments that are unused should have the variable name removed or commented out to avoid compiler warnings 



*There are 1 instances of this issue:*



<details>
<summary>see instances</summary>


```solidity
File: src/contracts/proxies/Vault721.sol

//@audit batchSize is not used
187:   function _afterTokenTransfer(address from, address to, uint256 firstTokenId, uint256 batchSize) internal override {


```

[link](https://github.com/open-dollar/od-contracts/blob/v1.5.5-audit//src/contracts/proxies/Vault721.sol#L187-L187) 


</details>


### [NC&#x2011;28] Use of `override` is unnecessary 
Starting with Solidity version [0.8.8](https://docs.soliditylang.org/en/v0.8.20/contracts.html#function-overriding), using the `override` keyword when the function solely overrides an interface function, and the function doesn't exist in multiple base contracts, is unnecessary.


*There are 4 instances of this issue:*



<details>
<summary>see instances</summary>


```solidity
File: src/contracts/AccountingEngine.sol

247:   function _onContractDisable() internal override {

283:   function _modifyParameters(bytes32 _param, bytes memory _data) internal override {

314:   function _validateParameters() internal view override {


```

[link](https://github.com/open-dollar/od-contracts/blob/v1.5.5-audit//src/contracts/AccountingEngine.sol#L247-L247) , [link](https://github.com/open-dollar/od-contracts/blob/v1.5.5-audit//src/contracts/AccountingEngine.sol#L283-L283), [link](https://github.com/open-dollar/od-contracts/blob/v1.5.5-audit//src/contracts/AccountingEngine.sol#L314-L314)


```solidity

File: src/contracts/proxies/Vault721.sol

187:   function _afterTokenTransfer(address from, address to, uint256 firstTokenId, uint256 batchSize) internal override {


```

[link](https://github.com/open-dollar/od-contracts/blob/v1.5.5-audit//src/contracts/proxies/Vault721.sol#L187-L187) 


</details>


### [NC&#x2011;29] NatSpec `@param` is missing 



*There are 34 instances of this issue:*



<details>
<summary>see instances</summary>


```solidity
File: src/contracts/AccountingEngine.sol

// @audit the @param _surplusAuctionHouse is missing

@dev Set the surplus auction house, deny permissions on the old one and approve on the new one


```

[link](https://github.com/open-dollar/od-contracts/blob/v1.5.5-audit//src/contracts/AccountingEngine.sol#L305-L1) 


```solidity

File: src/contracts/oracles/UniV3Relayer.sol

// @audit the @param _quoteResult is missing

@notice Parses the result from the aggregator into 18 decimals format


```

[link](https://github.com/open-dollar/od-contracts/blob/v1.5.5-audit//src/contracts/oracles/UniV3Relayer.sol#L110-L1) 


```solidity

File: src/contracts/gov/ODGovernor.sol

// @audit the @param blockNumber is missing

 inherit: GovernorVotesQuorumFraction

// @audit the @param proposalId is missing

 inherit: Governor, GovernorTimelockControl

// @audit the @param targets is missing
// @audit the @param values is missing
// @audit the @param calldatas is missing
// @audit the @param description is missing

 inherit: Governor, GovernorCompatibilityBravo

// @audit the @param proposalId is missing
// @audit the @param targets is missing
// @audit the @param values is missing
// @audit the @param calldatas is missing
// @audit the @param descriptionHash is missing

 inherit: Governor, GovernorTimelockControl

// @audit the @param targets is missing
// @audit the @param values is missing
// @audit the @param calldatas is missing
// @audit the @param descriptionHash is missing

 inherit: Governor, GovernorTimelockControl

// @audit the @param interfaceId is missing

 inherit: Governor, GovernorTimelockControl


```

[link](https://github.com/open-dollar/od-contracts/blob/v1.5.5-audit//src/contracts/gov/ODGovernor.sol#L66-L1) , [link](https://github.com/open-dollar/od-contracts/blob/v1.5.5-audit//src/contracts/gov/ODGovernor.sol#L73-L1), [link](https://github.com/open-dollar/od-contracts/blob/v1.5.5-audit//src/contracts/gov/ODGovernor.sol#L85-L1), [link](https://github.com/open-dollar/od-contracts/blob/v1.5.5-audit//src/contracts/gov/ODGovernor.sol#L104-L1), [link](https://github.com/open-dollar/od-contracts/blob/v1.5.5-audit//src/contracts/gov/ODGovernor.sol#L117-L1), [link](https://github.com/open-dollar/od-contracts/blob/v1.5.5-audit//src/contracts/gov/ODGovernor.sol#L136-L1)


```solidity

File: src/contracts/proxies/Vault721.sol

// @audit the @param _governor is missing

 @dev initializes DAO governor contract

// @audit the @param _user is missing

 @dev get proxy by user address

// @audit the @param _user is missing

 @dev allows user without an ODProxy to deploy a new ODProxy

// @audit the @param _proxy is missing
// @audit the @param _safeId is missing

 @dev mint can only be called by the SafeManager
 enforces that only ODProxies call `openSafe` function by checking _proxyRegistry

// @audit the @param _nftRenderer is missing
// @audit the @param _oracleRelayer is missing
// @audit the @param _taxCollector is missing
// @audit the @param _collateralJoinFactory is missing

 @dev allows DAO to update protocol implementation on NFTRenderer

// @audit the @param _metaData is missing

 @dev update meta data

// @audit the @param _safeManager is missing

 @dev allows DAO to update protocol implementation of SafeManager

// @audit the @param _nftRenderer is missing

 @dev allows DAO to update protocol implementation of NFTRenderer

// @audit the @param _safeId is missing

 @dev generate URI with updated vault information

// @audit the @param _user is missing

 @dev check that proxy does not exist OR that the user does not own proxy

// @audit the @param _user is missing

 @dev deploys ODProxy for user to interact with protocol
 updates _proxyRegistry and _userRegistry mappings for new ODProxy

// @audit the @param _safeManager is missing

 @dev allows DAO to update protocol implementation of SafeManager

// @audit the @param _nftRenderer is missing

 @dev allows DAO to update protocol implementation of NFTRenderer

// @audit the @param from is missing
// @audit the @param  is missing
// @audit the @param firstTokenId is missing
// @audit the @param batchSize is missing

 @dev _transfer calls `transferSAFEOwnership` on SafeManager
 enforces that ODProxy exists for transfer or it deploys a new ODProxy for receiver of vault/nft


```

[link](https://github.com/open-dollar/od-contracts/blob/v1.5.5-audit//src/contracts/proxies/Vault721.sol#L33-L1) , [link](https://github.com/open-dollar/od-contracts/blob/v1.5.5-audit//src/contracts/proxies/Vault721.sol#L70-L1), [link](https://github.com/open-dollar/od-contracts/blob/v1.5.5-audit//src/contracts/proxies/Vault721.sol#L85-L1), [link](https://github.com/open-dollar/od-contracts/blob/v1.5.5-audit//src/contracts/proxies/Vault721.sol#L94-L1), [link](https://github.com/open-dollar/od-contracts/blob/v1.5.5-audit//src/contracts/proxies/Vault721.sol#L104-L1), [link](https://github.com/open-dollar/od-contracts/blob/v1.5.5-audit//src/contracts/proxies/Vault721.sol#L119-L1), [link](https://github.com/open-dollar/od-contracts/blob/v1.5.5-audit//src/contracts/proxies/Vault721.sol#L126-L1), [link](https://github.com/open-dollar/od-contracts/blob/v1.5.5-audit//src/contracts/proxies/Vault721.sol#L133-L1), [link](https://github.com/open-dollar/od-contracts/blob/v1.5.5-audit//src/contracts/proxies/Vault721.sol#L140-L1), [link](https://github.com/open-dollar/od-contracts/blob/v1.5.5-audit//src/contracts/proxies/Vault721.sol#L154-L1), [link](https://github.com/open-dollar/od-contracts/blob/v1.5.5-audit//src/contracts/proxies/Vault721.sol#L162-L1), [link](https://github.com/open-dollar/od-contracts/blob/v1.5.5-audit//src/contracts/proxies/Vault721.sol#L172-L1), [link](https://github.com/open-dollar/od-contracts/blob/v1.5.5-audit//src/contracts/proxies/Vault721.sol#L179-L1), [link](https://github.com/open-dollar/od-contracts/blob/v1.5.5-audit//src/contracts/proxies/Vault721.sol#L187-L1)


```solidity

File: src/contracts/proxies/actions/BasicActions.sol

// @audit the @param _safeEngine is missing
// @audit the @param _cType is missing
// @audit the @param _safeHandler is missing
// @audit the @param _deltaWad is missing

 @notice Gets delta debt generated for delta wad (always positive)
 @dev    Total SAFE debt minus available safeHandler COIN balance

// @audit the @param _safeEngine is missing
// @audit the @param _cType is missing
// @audit the @param _safeHandler is missing

 @notice Gets repaid delta debt generated
 @dev    The rate adjusted debt of the SAFE

// @audit the @param _safeEngine is missing
// @audit the @param _usr is missing
// @audit the @param _cType is missing
// @audit the @param _safeHandler is missing

 @notice Gets repaid debt
 @dev    The rate adjusted SAFE's debt minus COIN balance available in usr's address

// @audit the @param _manager is missing
// @audit the @param _taxCollector is missing
// @audit the @param _coinJoin is missing
// @audit the @param _safeId is missing
// @audit the @param _deltaWad is missing

 @notice Generates debt
 @dev    Modifies the SAFE collateralization ratio, increasing the debt and sends the COIN amount to the user's address

// @audit the @param _manager is missing
// @audit the @param _taxCollector is missing
// @audit the @param _coinJoin is missing
// @audit the @param _safeId is missing
// @audit the @param _deltaWad is missing

 @notice Repays debt
 @dev    Joins COIN amount into the safeEngine and modifies the SAFE collateralization reducing the debt

// @audit the @param _manager is missing
// @audit the @param _cType is missing
// @audit the @param _usr is missing

@notice Routes the openSAFE call to the ODSafeManager contract

// @audit the @param _manager is missing
// @audit the @param _safeId is missing
// @audit the @param _dst is missing
// @audit the @param _deltaWad is missing

@notice Routes the transferCollateral call to the ODSafeManager contract

// @audit the @param _manager is missing
// @audit the @param _safeId is missing
// @audit the @param _dst is missing
// @audit the @param _rad is missing

@notice Routes the transferInternalCoins call to the ODSafeManager contract

// @audit the @param _manager is missing
// @audit the @param _safeId is missing
// @audit the @param _deltaCollateral is missing
// @audit the @param _deltaDebt is missing

@notice Routes the modifySAFECollateralization call to the ODSafeManager contract

// @audit the @param _manager is missing
// @audit the @param _taxCollector is missing
// @audit the @param _collateralJoin is missing
// @audit the @param _coinJoin is missing
// @audit the @param _safeId is missing
// @audit the @param _collateralAmount is missing
// @audit the @param _deltaWad is missing

 @notice Joins collateral and exits an amount of COIN

// @audit the @param _manager is missing
// @audit the @param _coinJoin is missing
// @audit the @param _safeId is missing
// @audit the @param _deltaWad is missing

 @notice Transfers an amount of COIN to the proxy address and exits to the user's address

// @audit the @param _manager is missing
// @audit the @param _collateralJoin is missing
// @audit the @param _safeId is missing
// @audit the @param _deltaWad is missing

 @notice Transfers an amount of collateral to the proxy address and exits collateral tokens to the user


```

[link](https://github.com/open-dollar/od-contracts/blob/v1.5.5-audit//src/contracts/proxies/actions/BasicActions.sol#L31-L1) , [link](https://github.com/open-dollar/od-contracts/blob/v1.5.5-audit//src/contracts/proxies/actions/BasicActions.sol#L53-L1), [link](https://github.com/open-dollar/od-contracts/blob/v1.5.5-audit//src/contracts/proxies/actions/BasicActions.sol#L72-L1), [link](https://github.com/open-dollar/od-contracts/blob/v1.5.5-audit//src/contracts/proxies/actions/BasicActions.sol#L94-L1), [link](https://github.com/open-dollar/od-contracts/blob/v1.5.5-audit//src/contracts/proxies/actions/BasicActions.sol#L121-L1), [link](https://github.com/open-dollar/od-contracts/blob/v1.5.5-audit//src/contracts/proxies/actions/BasicActions.sol#L142-L1), [link](https://github.com/open-dollar/od-contracts/blob/v1.5.5-audit//src/contracts/proxies/actions/BasicActions.sol#L147-L1), [link](https://github.com/open-dollar/od-contracts/blob/v1.5.5-audit//src/contracts/proxies/actions/BasicActions.sol#L153-L1), [link](https://github.com/open-dollar/od-contracts/blob/v1.5.5-audit//src/contracts/proxies/actions/BasicActions.sol#L158-L1), [link](https://github.com/open-dollar/od-contracts/blob/v1.5.5-audit//src/contracts/proxies/actions/BasicActions.sol#L170-L1), [link](https://github.com/open-dollar/od-contracts/blob/v1.5.5-audit//src/contracts/proxies/actions/BasicActions.sol#L201-L1), [link](https://github.com/open-dollar/od-contracts/blob/v1.5.5-audit//src/contracts/proxies/actions/BasicActions.sol#L211-L1)


</details>


### [NC&#x2011;30] `public` functions not called by the contract should be declared `external` instead 
Contracts [are allowed](https://docs.soliditylang.org/en/latest/contracts.html#function-overriding) to override their parents' functions and change the visibility from `external` to `public`.


*There are 1 instances of this issue:*



<details>
<summary>see instances</summary>


```solidity
File: src/contracts/proxies/Vault721.sol

147:   function contractURI() public view returns (string memory uri) {


```

[link](https://github.com/open-dollar/od-contracts/blob/v1.5.5-audit//src/contracts/proxies/Vault721.sol#L147-L147) 


</details>


### [NC&#x2011;31] Redundant inheritance specifier 
The contracts below already extend the specified contract, so there is no need to list it in the inheritance list again


*There are 5 instances of this issue:*



<details>
<summary>see instances</summary>


```solidity
File: src/contracts/AccountingEngine.sol

//@audit `Authorizable` is already inherited by `Modifiable` 
23: contract AccountingEngine is Authorizable, Modifiable, Disableable, IAccountingEngine {


```

[link](https://github.com/open-dollar/od-contracts/blob/v1.5.5-audit//src/contracts/AccountingEngine.sol#L23-L23) 


```solidity

File: src/contracts/oracles/CamelotRelayer.sol

//@audit `IBaseOracle` is already inherited by `ICamelotRelayer` 
18: contract CamelotRelayer is IBaseOracle, ICamelotRelayer {


```

[link](https://github.com/open-dollar/od-contracts/blob/v1.5.5-audit//src/contracts/oracles/CamelotRelayer.sol#L18-L18) 


```solidity

File: src/contracts/oracles/UniV3Relayer.sol

//@audit `IBaseOracle` is already inherited by `IUniV3Relayer` 
16: contract UniV3Relayer is IBaseOracle, IUniV3Relayer {


```

[link](https://github.com/open-dollar/od-contracts/blob/v1.5.5-audit//src/contracts/oracles/UniV3Relayer.sol#L16-L16) 


```solidity

File: src/contracts/gov/ODGovernor.sol

//@audit `Governor` is already inherited by `GovernorSettings` 
17: contract ODGovernor is
18:   Governor,
19:   GovernorSettings,

//@audit `GovernorVotes` is already inherited by `GovernorVotesQuorumFraction` 
17: contract ODGovernor is
18:   Governor,
19:   GovernorSettings,
20:   GovernorCompatibilityBravo,
21:   GovernorVotes,
22:   GovernorVotesQuorumFraction,


```

[link](https://github.com/open-dollar/od-contracts/blob/v1.5.5-audit//src/contracts/gov/ODGovernor.sol#L17-L19) , [link](https://github.com/open-dollar/od-contracts/blob/v1.5.5-audit//src/contracts/gov/ODGovernor.sol#L17-L22)


</details>


### [NC&#x2011;32] `require()` / `revert()` statements should have descriptive reason strings 



*There are 1 instances of this issue:*



<details>
<summary>see instances</summary>


```solidity
File: src/contracts/proxies/Vault721.sol

111:     require(_safeManager != address(0));


```

[link](https://github.com/open-dollar/od-contracts/blob/v1.5.5-audit//src/contracts/proxies/Vault721.sol#L111-L111) 


</details>


### [NC&#x2011;33] NatSpec `@return` argument is missing 



*There are 21 instances of this issue:*



<details>
<summary>see instances</summary>


```solidity
File: src/contracts/oracles/UniV3Relayer.sol

// @audit the @return is missing
@notice Parses the result from the aggregator into 18 decimals format


```

[link](https://github.com/open-dollar/od-contracts/blob/v1.5.5-audit//src/contracts/oracles/UniV3Relayer.sol#L110-L1) 


```solidity

File: src/contracts/gov/ODGovernor.sol

// @audit the @return is missing
 @dev - below are required override functions -
 inherit: GovernorSettings

// @audit the @return is missing
 inherit: GovernorSettings

// @audit the @return is missing
 inherit: GovernorVotesQuorumFraction

// @audit the @return is missing
 inherit: Governor, GovernorTimelockControl

// @audit the @return is missing
 inherit: Governor, GovernorCompatibilityBravo

// @audit the @return is missing
 inherit: Governor, GovernorSettings

// @audit the @return is missing
 inherit: Governor, GovernorTimelockControl

// @audit the @return is missing
 inherit: Governor, GovernorTimelockControl

// @audit the @return is missing
 inherit: Governor, GovernorTimelockControl


```

[link](https://github.com/open-dollar/od-contracts/blob/v1.5.5-audit//src/contracts/gov/ODGovernor.sol#L52-L1) , [link](https://github.com/open-dollar/od-contracts/blob/v1.5.5-audit//src/contracts/gov/ODGovernor.sol#L59-L1), [link](https://github.com/open-dollar/od-contracts/blob/v1.5.5-audit//src/contracts/gov/ODGovernor.sol#L66-L1), [link](https://github.com/open-dollar/od-contracts/blob/v1.5.5-audit//src/contracts/gov/ODGovernor.sol#L73-L1), [link](https://github.com/open-dollar/od-contracts/blob/v1.5.5-audit//src/contracts/gov/ODGovernor.sol#L85-L1), [link](https://github.com/open-dollar/od-contracts/blob/v1.5.5-audit//src/contracts/gov/ODGovernor.sol#L97-L1), [link](https://github.com/open-dollar/od-contracts/blob/v1.5.5-audit//src/contracts/gov/ODGovernor.sol#L117-L1), [link](https://github.com/open-dollar/od-contracts/blob/v1.5.5-audit//src/contracts/gov/ODGovernor.sol#L129-L1), [link](https://github.com/open-dollar/od-contracts/blob/v1.5.5-audit//src/contracts/gov/ODGovernor.sol#L136-L1)


```solidity

File: src/contracts/proxies/Vault721.sol

// @audit the @return is missing
 @dev get proxy by user address

// @audit the @return is missing
 @dev allows msg.sender without an ODProxy to deploy a new ODProxy

// @audit the @return is missing
 @dev allows user without an ODProxy to deploy a new ODProxy

// @audit the @return is missing
 @dev generate URI with updated vault information

// @audit the @return is missing
 @dev contract level meta data

// @audit the @return is missing
 @dev check that proxy does not exist OR that the user does not own proxy

// @audit the @return is missing
 @dev deploys ODProxy for user to interact with protocol
 updates _proxyRegistry and _userRegistry mappings for new ODProxy


```

[link](https://github.com/open-dollar/od-contracts/blob/v1.5.5-audit//src/contracts/proxies/Vault721.sol#L70-L1) , [link](https://github.com/open-dollar/od-contracts/blob/v1.5.5-audit//src/contracts/proxies/Vault721.sol#L77-L1), [link](https://github.com/open-dollar/od-contracts/blob/v1.5.5-audit//src/contracts/proxies/Vault721.sol#L85-L1), [link](https://github.com/open-dollar/od-contracts/blob/v1.5.5-audit//src/contracts/proxies/Vault721.sol#L140-L1), [link](https://github.com/open-dollar/od-contracts/blob/v1.5.5-audit//src/contracts/proxies/Vault721.sol#L147-L1), [link](https://github.com/open-dollar/od-contracts/blob/v1.5.5-audit//src/contracts/proxies/Vault721.sol#L154-L1), [link](https://github.com/open-dollar/od-contracts/blob/v1.5.5-audit//src/contracts/proxies/Vault721.sol#L162-L1)


```solidity

File: src/contracts/proxies/actions/BasicActions.sol

// @audit the @return is missing
 @notice Gets delta debt generated for delta wad (always positive)
 @dev    Total SAFE debt minus available safeHandler COIN balance

// @audit the @return is missing
 @notice Gets repaid delta debt generated
 @dev    The rate adjusted debt of the SAFE

// @audit the @return is missing
 @notice Gets repaid debt
 @dev    The rate adjusted SAFE's debt minus COIN balance available in usr's address

// @audit the @return is missing
@notice Routes the openSAFE call to the ODSafeManager contract


```

[link](https://github.com/open-dollar/od-contracts/blob/v1.5.5-audit//src/contracts/proxies/actions/BasicActions.sol#L31-L1) , [link](https://github.com/open-dollar/od-contracts/blob/v1.5.5-audit//src/contracts/proxies/actions/BasicActions.sol#L53-L1), [link](https://github.com/open-dollar/od-contracts/blob/v1.5.5-audit//src/contracts/proxies/actions/BasicActions.sol#L72-L1), [link](https://github.com/open-dollar/od-contracts/blob/v1.5.5-audit//src/contracts/proxies/actions/BasicActions.sol#L142-L1)


</details>


### [NC&#x2011;34] Polymorphic functions make security audits more time-consuming and error-prone 
The instances below point to one of two functions with the same name. Consider naming each function differently, in order to make code navigation and analysis easier.


*There are 3 instances of this issue:*



<details>
<summary>see instances</summary>


```solidity
File: src/contracts/proxies/Vault721.sol

85:   function build(address _user) external returns (address payable _proxy) {


```

[link](https://github.com/open-dollar/od-contracts/blob/v1.5.5-audit//src/contracts/proxies/Vault721.sol#L85-L85) 


```solidity

File: src/contracts/proxies/ODSafeManager.sol

78:   function getSafes(address _usr, bytes32 _cType) external view returns (uint256[] memory _safes) {

175:   function transferCollateral(bytes32 _cType, uint256 _safe, address _dst, uint256 _wad) external safeAllowed(_safe) {


```

[link](https://github.com/open-dollar/od-contracts/blob/v1.5.5-audit//src/contracts/proxies/ODSafeManager.sol#L78-L78) , [link](https://github.com/open-dollar/od-contracts/blob/v1.5.5-audit//src/contracts/proxies/ODSafeManager.sol#L175-L175)


</details>


### [NC&#x2011;35] Consider moving `msg.sender` checks to a common authorization `modifier` 



*There are 2 instances of this issue:*



<details>
<summary>see instances</summary>


```solidity
File: src/contracts/proxies/Vault721.sol

95:     require(msg.sender == address(safeManager), 'V721: only safeManager');


```

[link](https://github.com/open-dollar/od-contracts/blob/v1.5.5-audit//src/contracts/proxies/Vault721.sol#L95-L95) 


```solidity

File: src/contracts/proxies/ODSafeManager.sol

137:     require(msg.sender == address(vault721), 'SafeMngr: Only Vault721');


```

[link](https://github.com/open-dollar/od-contracts/blob/v1.5.5-audit//src/contracts/proxies/ODSafeManager.sol#L137-L137) 


</details>


### [NC&#x2011;36] Imports should use double quotes rather than single quotes 
According to the [documentation](https://docs.soliditylang.org/en/latest/style-guide.html#imports) imports should use a double quote instead of a single one.


*There are 65 instances of this issue:*



<details>
<summary>see instances</summary>


```solidity
File: src/contracts/AccountingEngine.sol

4: import {IAccountingEngine} from '@interfaces/IAccountingEngine.sol';

5: import {IDebtAuctionHouse} from '@interfaces/IDebtAuctionHouse.sol';

6: import {ISurplusAuctionHouse} from '@interfaces/ISurplusAuctionHouse.sol';

7: import {ISAFEEngine} from '@interfaces/ISAFEEngine.sol';

9: import {Authorizable, IAuthorizable} from '@contracts/utils/Authorizable.sol';

10: import {Disableable} from '@contracts/utils/Disableable.sol';

11: import {Modifiable} from '@contracts/utils/Modifiable.sol';

13: import {Encoding} from '@libraries/Encoding.sol';

14: import {Math, WAD} from '@libraries/Math.sol';

15: import {Assertions} from '@libraries/Assertions.sol';


```

[link](https://github.com/open-dollar/od-contracts/blob/v1.5.5-audit//src/contracts/AccountingEngine.sol#L4-L4) , [link](https://github.com/open-dollar/od-contracts/blob/v1.5.5-audit//src/contracts/AccountingEngine.sol#L5-L5), [link](https://github.com/open-dollar/od-contracts/blob/v1.5.5-audit//src/contracts/AccountingEngine.sol#L6-L6), [link](https://github.com/open-dollar/od-contracts/blob/v1.5.5-audit//src/contracts/AccountingEngine.sol#L7-L7), [link](https://github.com/open-dollar/od-contracts/blob/v1.5.5-audit//src/contracts/AccountingEngine.sol#L9-L9), [link](https://github.com/open-dollar/od-contracts/blob/v1.5.5-audit//src/contracts/AccountingEngine.sol#L10-L10), [link](https://github.com/open-dollar/od-contracts/blob/v1.5.5-audit//src/contracts/AccountingEngine.sol#L11-L11), [link](https://github.com/open-dollar/od-contracts/blob/v1.5.5-audit//src/contracts/AccountingEngine.sol#L13-L13), [link](https://github.com/open-dollar/od-contracts/blob/v1.5.5-audit//src/contracts/AccountingEngine.sol#L14-L14), [link](https://github.com/open-dollar/od-contracts/blob/v1.5.5-audit//src/contracts/AccountingEngine.sol#L15-L15)


```solidity

File: src/contracts/oracles/CamelotRelayer.sol

4: import {IBaseOracle} from '@interfaces/oracles/IBaseOracle.sol';

5: import {ICamelotRelayer} from '@interfaces/oracles/ICamelotRelayer.sol';

6: import {IERC20Metadata} from '@openzeppelin/token/ERC20/extensions/IERC20Metadata.sol';

8: import {IAlgebraFactory} from '@interfaces/factories/IAlgebraFactory.sol';

9: import {ICamelotPair} from '@camelot/interfaces/ICamelotPair.sol';

10: import {OracleLibrary} from '@uniswap/v3-periphery/contracts/libraries/OracleLibrary.sol';

11: import {CAMELOT_V3_FACTORY, GOERLI_CAMELOT_V3_FACTORY} from '@script/Registry.s.sol';


```

[link](https://github.com/open-dollar/od-contracts/blob/v1.5.5-audit//src/contracts/oracles/CamelotRelayer.sol#L4-L4) , [link](https://github.com/open-dollar/od-contracts/blob/v1.5.5-audit//src/contracts/oracles/CamelotRelayer.sol#L5-L5), [link](https://github.com/open-dollar/od-contracts/blob/v1.5.5-audit//src/contracts/oracles/CamelotRelayer.sol#L6-L6), [link](https://github.com/open-dollar/od-contracts/blob/v1.5.5-audit//src/contracts/oracles/CamelotRelayer.sol#L8-L8), [link](https://github.com/open-dollar/od-contracts/blob/v1.5.5-audit//src/contracts/oracles/CamelotRelayer.sol#L9-L9), [link](https://github.com/open-dollar/od-contracts/blob/v1.5.5-audit//src/contracts/oracles/CamelotRelayer.sol#L10-L10), [link](https://github.com/open-dollar/od-contracts/blob/v1.5.5-audit//src/contracts/oracles/CamelotRelayer.sol#L11-L11)


```solidity

File: src/contracts/factories/CamelotRelayerFactory.sol

4: import {ICamelotRelayerFactory} from '@interfaces/factories/ICamelotRelayerFactory.sol';

5: import {IBaseOracle} from '@interfaces/oracles/IBaseOracle.sol';

7: import {CamelotRelayerChild} from '@contracts/factories/CamelotRelayerChild.sol';

9: import {Authorizable} from '@contracts/utils/Authorizable.sol';

11: import {EnumerableSet} from '@openzeppelin/utils/structs/EnumerableSet.sol';


```

[link](https://github.com/open-dollar/od-contracts/blob/v1.5.5-audit//src/contracts/factories/CamelotRelayerFactory.sol#L4-L4) , [link](https://github.com/open-dollar/od-contracts/blob/v1.5.5-audit//src/contracts/factories/CamelotRelayerFactory.sol#L5-L5), [link](https://github.com/open-dollar/od-contracts/blob/v1.5.5-audit//src/contracts/factories/CamelotRelayerFactory.sol#L7-L7), [link](https://github.com/open-dollar/od-contracts/blob/v1.5.5-audit//src/contracts/factories/CamelotRelayerFactory.sol#L9-L9), [link](https://github.com/open-dollar/od-contracts/blob/v1.5.5-audit//src/contracts/factories/CamelotRelayerFactory.sol#L11-L11)


```solidity

File: src/contracts/factories/CamelotRelayerChild.sol

4: import {ICamelotRelayerChild} from '@interfaces/factories/ICamelotRelayerChild.sol';

6: import {CamelotRelayer} from '@contracts/oracles/CamelotRelayer.sol';

8: import {FactoryChild} from '@contracts/factories/FactoryChild.sol';


```

[link](https://github.com/open-dollar/od-contracts/blob/v1.5.5-audit//src/contracts/factories/CamelotRelayerChild.sol#L4-L4) , [link](https://github.com/open-dollar/od-contracts/blob/v1.5.5-audit//src/contracts/factories/CamelotRelayerChild.sol#L6-L6), [link](https://github.com/open-dollar/od-contracts/blob/v1.5.5-audit//src/contracts/factories/CamelotRelayerChild.sol#L8-L8)


```solidity

File: src/contracts/oracles/UniV3Relayer.sol

4: import {IBaseOracle} from '@interfaces/oracles/IBaseOracle.sol';

5: import {IUniV3Relayer} from '@interfaces/oracles/IUniV3Relayer.sol';

6: import {IERC20Metadata} from '@openzeppelin/token/ERC20/extensions/IERC20Metadata.sol';

7: import {IUniswapV3Factory} from '@uniswap/v3-core/contracts/interfaces/IUniswapV3Factory.sol';

8: import {OracleLibrary, IUniswapV3Pool} from '@uniswap/v3-periphery/contracts/libraries/OracleLibrary.sol';

9: import {UNISWAP_V3_FACTORY, GOERLI_UNISWAP_V3_FACTORY} from '@script/Registry.s.sol';


```

[link](https://github.com/open-dollar/od-contracts/blob/v1.5.5-audit//src/contracts/oracles/UniV3Relayer.sol#L4-L4) , [link](https://github.com/open-dollar/od-contracts/blob/v1.5.5-audit//src/contracts/oracles/UniV3Relayer.sol#L5-L5), [link](https://github.com/open-dollar/od-contracts/blob/v1.5.5-audit//src/contracts/oracles/UniV3Relayer.sol#L6-L6), [link](https://github.com/open-dollar/od-contracts/blob/v1.5.5-audit//src/contracts/oracles/UniV3Relayer.sol#L7-L7), [link](https://github.com/open-dollar/od-contracts/blob/v1.5.5-audit//src/contracts/oracles/UniV3Relayer.sol#L8-L8), [link](https://github.com/open-dollar/od-contracts/blob/v1.5.5-audit//src/contracts/oracles/UniV3Relayer.sol#L9-L9)


```solidity

File: src/contracts/gov/ODGovernor.sol

4: import {IVotes} from '@openzeppelin/governance/utils/IVotes.sol';

5: import {IERC165} from '@openzeppelin/utils/introspection/IERC165.sol';

6: import {IGovernor} from '@openzeppelin/governance/IGovernor.sol';

8: import {TimelockController} from '@openzeppelin/governance/TimelockController.sol';

10: import {Governor} from '@openzeppelin/governance/Governor.sol';

11: import {GovernorSettings} from '@openzeppelin/governance/extensions/GovernorSettings.sol';

12: import {GovernorCompatibilityBravo} from '@openzeppelin/governance/compatibility/GovernorCompatibilityBravo.sol';

13: import {GovernorVotes} from '@openzeppelin/governance/extensions/GovernorVotes.sol';

14: import {GovernorVotesQuorumFraction} from '@openzeppelin/governance/extensions/GovernorVotesQuorumFraction.sol';

15: import {GovernorTimelockControl} from '@openzeppelin/governance/extensions/GovernorTimelockControl.sol';


```

[link](https://github.com/open-dollar/od-contracts/blob/v1.5.5-audit//src/contracts/gov/ODGovernor.sol#L4-L4) , [link](https://github.com/open-dollar/od-contracts/blob/v1.5.5-audit//src/contracts/gov/ODGovernor.sol#L5-L5), [link](https://github.com/open-dollar/od-contracts/blob/v1.5.5-audit//src/contracts/gov/ODGovernor.sol#L6-L6), [link](https://github.com/open-dollar/od-contracts/blob/v1.5.5-audit//src/contracts/gov/ODGovernor.sol#L8-L8), [link](https://github.com/open-dollar/od-contracts/blob/v1.5.5-audit//src/contracts/gov/ODGovernor.sol#L10-L10), [link](https://github.com/open-dollar/od-contracts/blob/v1.5.5-audit//src/contracts/gov/ODGovernor.sol#L11-L11), [link](https://github.com/open-dollar/od-contracts/blob/v1.5.5-audit//src/contracts/gov/ODGovernor.sol#L12-L12), [link](https://github.com/open-dollar/od-contracts/blob/v1.5.5-audit//src/contracts/gov/ODGovernor.sol#L13-L13), [link](https://github.com/open-dollar/od-contracts/blob/v1.5.5-audit//src/contracts/gov/ODGovernor.sol#L14-L14), [link](https://github.com/open-dollar/od-contracts/blob/v1.5.5-audit//src/contracts/gov/ODGovernor.sol#L15-L15)


```solidity

File: src/contracts/proxies/Vault721.sol

4: import {ERC721} from '@openzeppelin/token/ERC721/ERC721.sol';

5: import {ERC721Enumerable} from '@openzeppelin/token/ERC721/extensions/ERC721Enumerable.sol';

6: import {IODSafeManager} from '@interfaces/proxies/IODSafeManager.sol';

7: import {ODProxy} from '@contracts/proxies/ODProxy.sol';

8: import {NFTRenderer} from '@contracts/proxies/NFTRenderer.sol';


```

[link](https://github.com/open-dollar/od-contracts/blob/v1.5.5-audit//src/contracts/proxies/Vault721.sol#L4-L4) , [link](https://github.com/open-dollar/od-contracts/blob/v1.5.5-audit//src/contracts/proxies/Vault721.sol#L5-L5), [link](https://github.com/open-dollar/od-contracts/blob/v1.5.5-audit//src/contracts/proxies/Vault721.sol#L6-L6), [link](https://github.com/open-dollar/od-contracts/blob/v1.5.5-audit//src/contracts/proxies/Vault721.sol#L7-L7), [link](https://github.com/open-dollar/od-contracts/blob/v1.5.5-audit//src/contracts/proxies/Vault721.sol#L8-L8)


```solidity

File: src/contracts/proxies/SAFEHandler.sol

4: import {ISAFEEngine} from '@interfaces/ISAFEEngine.sol';


```

[link](https://github.com/open-dollar/od-contracts/blob/v1.5.5-audit//src/contracts/proxies/SAFEHandler.sol#L4-L4) 


```solidity

File: src/contracts/proxies/ODSafeManager.sol

4: import {SAFEHandler} from '@contracts/proxies/SAFEHandler.sol';

5: import {ISAFEEngine} from '@interfaces/ISAFEEngine.sol';

6: import {ILiquidationEngine} from '@interfaces/ILiquidationEngine.sol';

7: import {IVault721} from '@interfaces/proxies/IVault721.sol';

9: import {Math} from '@libraries/Math.sol';

10: import {EnumerableSet} from '@openzeppelin/utils/structs/EnumerableSet.sol';

11: import {Assertions} from '@libraries/Assertions.sol';

13: import {IODSafeManager} from '@interfaces/proxies/IODSafeManager.sol';


```

[link](https://github.com/open-dollar/od-contracts/blob/v1.5.5-audit//src/contracts/proxies/ODSafeManager.sol#L4-L4) , [link](https://github.com/open-dollar/od-contracts/blob/v1.5.5-audit//src/contracts/proxies/ODSafeManager.sol#L5-L5), [link](https://github.com/open-dollar/od-contracts/blob/v1.5.5-audit//src/contracts/proxies/ODSafeManager.sol#L6-L6), [link](https://github.com/open-dollar/od-contracts/blob/v1.5.5-audit//src/contracts/proxies/ODSafeManager.sol#L7-L7), [link](https://github.com/open-dollar/od-contracts/blob/v1.5.5-audit//src/contracts/proxies/ODSafeManager.sol#L9-L9), [link](https://github.com/open-dollar/od-contracts/blob/v1.5.5-audit//src/contracts/proxies/ODSafeManager.sol#L10-L10), [link](https://github.com/open-dollar/od-contracts/blob/v1.5.5-audit//src/contracts/proxies/ODSafeManager.sol#L11-L11), [link](https://github.com/open-dollar/od-contracts/blob/v1.5.5-audit//src/contracts/proxies/ODSafeManager.sol#L13-L13)


```solidity

File: src/contracts/proxies/actions/BasicActions.sol

4: import {ODSafeManager} from '@contracts/proxies/ODSafeManager.sol';

5: import {ODProxy} from '@contracts/proxies/ODProxy.sol';

7: import {ISAFEEngine} from '@interfaces/ISAFEEngine.sol';

8: import {ICoinJoin} from '@interfaces/utils/ICoinJoin.sol';

9: import {ITaxCollector} from '@interfaces/ITaxCollector.sol';

10: import {ICollateralJoin} from '@interfaces/utils/ICollateralJoin.sol';

11: import {IERC20Metadata} from '@openzeppelin/token/ERC20/extensions/IERC20Metadata.sol';

12: import {IBasicActions} from '@interfaces/proxies/actions/IBasicActions.sol';

14: import {Math, WAD, RAY, RAD} from '@libraries/Math.sol';

16: import {CommonActions} from '@contracts/proxies/actions/CommonActions.sol';


```

[link](https://github.com/open-dollar/od-contracts/blob/v1.5.5-audit//src/contracts/proxies/actions/BasicActions.sol#L4-L4) , [link](https://github.com/open-dollar/od-contracts/blob/v1.5.5-audit//src/contracts/proxies/actions/BasicActions.sol#L5-L5), [link](https://github.com/open-dollar/od-contracts/blob/v1.5.5-audit//src/contracts/proxies/actions/BasicActions.sol#L7-L7), [link](https://github.com/open-dollar/od-contracts/blob/v1.5.5-audit//src/contracts/proxies/actions/BasicActions.sol#L8-L8), [link](https://github.com/open-dollar/od-contracts/blob/v1.5.5-audit//src/contracts/proxies/actions/BasicActions.sol#L9-L9), [link](https://github.com/open-dollar/od-contracts/blob/v1.5.5-audit//src/contracts/proxies/actions/BasicActions.sol#L10-L10), [link](https://github.com/open-dollar/od-contracts/blob/v1.5.5-audit//src/contracts/proxies/actions/BasicActions.sol#L11-L11), [link](https://github.com/open-dollar/od-contracts/blob/v1.5.5-audit//src/contracts/proxies/actions/BasicActions.sol#L12-L12), [link](https://github.com/open-dollar/od-contracts/blob/v1.5.5-audit//src/contracts/proxies/actions/BasicActions.sol#L14-L14), [link](https://github.com/open-dollar/od-contracts/blob/v1.5.5-audit//src/contracts/proxies/actions/BasicActions.sol#L16-L16)


</details>


### [NC&#x2011;37] State variables should include comments 
Consider adding some comments on critical state variables to explain what they are supposed to do: this will help for future code reviews.


*There are 14 instances of this issue:*



<details>
<summary>see instances</summary>


```solidity
File: src/contracts/AccountingEngine.sol

//@audit ONE_HUNDRED_WAD need comments
28:   uint256 internal constant ONE_HUNDRED_WAD = 100 * WAD;


```

[link](https://github.com/open-dollar/od-contracts/blob/v1.5.5-audit//src/contracts/AccountingEngine.sol#L28-L28) 


```solidity

File: src/contracts/oracles/CamelotRelayer.sol

//@audit _CAMELOT_FACTORY need comments
20:   address internal constant _CAMELOT_FACTORY = GOERLI_CAMELOT_V3_FACTORY;


```

[link](https://github.com/open-dollar/od-contracts/blob/v1.5.5-audit//src/contracts/oracles/CamelotRelayer.sol#L20-L20) 


```solidity

File: src/contracts/factories/CamelotRelayerFactory.sol

//@audit _camelotRelayers need comments
17:   EnumerableSet.AddressSet internal _camelotRelayers;


```

[link](https://github.com/open-dollar/od-contracts/blob/v1.5.5-audit//src/contracts/factories/CamelotRelayerFactory.sol#L17-L17) 


```solidity

File: src/contracts/oracles/UniV3Relayer.sol

//@audit _UNI_V3_FACTORY need comments
18:   address internal constant _UNI_V3_FACTORY = GOERLI_UNISWAP_V3_FACTORY;


```

[link](https://github.com/open-dollar/od-contracts/blob/v1.5.5-audit//src/contracts/oracles/UniV3Relayer.sol#L18-L18) 


```solidity

File: src/contracts/proxies/ODProxy.sol

//@audit OWNER need comments
12:   address public immutable OWNER;


```

[link](https://github.com/open-dollar/od-contracts/blob/v1.5.5-audit//src/contracts/proxies/ODProxy.sol#L12-L12) 


```solidity

File: src/contracts/proxies/Vault721.sol

//@audit governor need comments
18:   address public governor;

//@audit safeManager need comments
19:   IODSafeManager public safeManager;

//@audit nftRenderer need comments
20:   NFTRenderer public nftRenderer;

//@audit contractMetaData need comments
22:   string public contractMetaData =

//@audit _proxyRegistry need comments
25:   mapping(address proxy => address user) internal _proxyRegistry;

//@audit _userRegistry need comments
26:   mapping(address user => address proxy) internal _userRegistry;


```

[link](https://github.com/open-dollar/od-contracts/blob/v1.5.5-audit//src/contracts/proxies/Vault721.sol#L18-L18) , [link](https://github.com/open-dollar/od-contracts/blob/v1.5.5-audit//src/contracts/proxies/Vault721.sol#L19-L19), [link](https://github.com/open-dollar/od-contracts/blob/v1.5.5-audit//src/contracts/proxies/Vault721.sol#L20-L20), [link](https://github.com/open-dollar/od-contracts/blob/v1.5.5-audit//src/contracts/proxies/Vault721.sol#L22-L22), [link](https://github.com/open-dollar/od-contracts/blob/v1.5.5-audit//src/contracts/proxies/Vault721.sol#L25-L25), [link](https://github.com/open-dollar/od-contracts/blob/v1.5.5-audit//src/contracts/proxies/Vault721.sol#L26-L26)


```solidity

File: src/contracts/proxies/ODSafeManager.sol

//@audit vault721 need comments
29:   IVault721 public vault721;

//@audit _safeId need comments
31:   uint256 internal _safeId; // Auto incremental

//@audit _usrSafes need comments
32:   mapping(address _safeOwner => EnumerableSet.UintSet) private _usrSafes;


```

[link](https://github.com/open-dollar/od-contracts/blob/v1.5.5-audit//src/contracts/proxies/ODSafeManager.sol#L29-L29) , [link](https://github.com/open-dollar/od-contracts/blob/v1.5.5-audit//src/contracts/proxies/ODSafeManager.sol#L31-L31), [link](https://github.com/open-dollar/od-contracts/blob/v1.5.5-audit//src/contracts/proxies/ODSafeManager.sol#L32-L32)


</details>


### [NC&#x2011;38] Strings should use double quotes rather than single quotes 
See the Solidity Style [Guide](https://docs.soliditylang.org/en/v0.8.20/style-guide.html#other-recommendations)


*There are 23 instances of this issue:*



<details>
<summary>see instances</summary>


```solidity
File: src/contracts/AccountingEngine.sol

288:     if (_param == 'surplusTransferPercentage') _params.surplusTransferPercentage = _uint256;

289:     else if (_param == 'surplusDelay') _params.surplusDelay = _uint256;

290:     else if (_param == 'popDebtDelay') _params.popDebtDelay = _uint256;

291:     else if (_param == 'disableCooldown') _params.disableCooldown = _uint256;

292:     else if (_param == 'surplusAmount') _params.surplusAmount = _uint256;

293:     else if (_param == 'debtAuctionBidSize') _params.debtAuctionBidSize = _uint256;

294:     else if (_param == 'debtAuctionMintedTokens') _params.debtAuctionMintedTokens = _uint256;

295:     else if (_param == 'surplusBuffer') _params.surplusBuffer = _uint256;

297:     else if (_param == 'surplusAuctionHouse') _setSurplusAuctionHouse(_address);

298:     else if (_param == 'debtAuctionHouse') debtAuctionHouse = IDebtAuctionHouse(_address);

299:     else if (_param == 'postSettlementSurplusDrain') postSettlementSurplusDrain = _address;

300:     else if (_param == 'extraSurplusReceiver') extraSurplusReceiver = _address;


```

[link](https://github.com/open-dollar/od-contracts/blob/v1.5.5-audit//src/contracts/AccountingEngine.sol#L288-L288) , [link](https://github.com/open-dollar/od-contracts/blob/v1.5.5-audit//src/contracts/AccountingEngine.sol#L289-L289), [link](https://github.com/open-dollar/od-contracts/blob/v1.5.5-audit//src/contracts/AccountingEngine.sol#L290-L290), [link](https://github.com/open-dollar/od-contracts/blob/v1.5.5-audit//src/contracts/AccountingEngine.sol#L291-L291), [link](https://github.com/open-dollar/od-contracts/blob/v1.5.5-audit//src/contracts/AccountingEngine.sol#L292-L292), [link](https://github.com/open-dollar/od-contracts/blob/v1.5.5-audit//src/contracts/AccountingEngine.sol#L293-L293), [link](https://github.com/open-dollar/od-contracts/blob/v1.5.5-audit//src/contracts/AccountingEngine.sol#L294-L294), [link](https://github.com/open-dollar/od-contracts/blob/v1.5.5-audit//src/contracts/AccountingEngine.sol#L295-L295), [link](https://github.com/open-dollar/od-contracts/blob/v1.5.5-audit//src/contracts/AccountingEngine.sol#L297-L297), [link](https://github.com/open-dollar/od-contracts/blob/v1.5.5-audit//src/contracts/AccountingEngine.sol#L298-L298), [link](https://github.com/open-dollar/od-contracts/blob/v1.5.5-audit//src/contracts/AccountingEngine.sol#L299-L299), [link](https://github.com/open-dollar/od-contracts/blob/v1.5.5-audit//src/contracts/AccountingEngine.sol#L300-L300)


```solidity

File: src/contracts/oracles/CamelotRelayer.sol

61:     symbol = string(abi.encodePacked(IERC20Metadata(_baseToken).symbol(), ' / ', IERC20Metadata(_quoteToken).symbol()));


```

[link](https://github.com/open-dollar/od-contracts/blob/v1.5.5-audit//src/contracts/oracles/CamelotRelayer.sol#L61-L61) 


```solidity

File: src/contracts/oracles/UniV3Relayer.sol

67:     symbol = string(abi.encodePacked(IERC20Metadata(_baseToken).symbol(), ' / ', IERC20Metadata(_quoteToken).symbol()));


```

[link](https://github.com/open-dollar/od-contracts/blob/v1.5.5-audit//src/contracts/oracles/UniV3Relayer.sol#L67-L67) 


```solidity

File: src/contracts/gov/ODGovernor.sol

40:     Governor('ODGovernor')


```

[link](https://github.com/open-dollar/od-contracts/blob/v1.5.5-audit//src/contracts/gov/ODGovernor.sol#L40-L40) 


```solidity

File: src/contracts/proxies/Vault721.sol

23:     '{"name": "Open Dollar Vaults","description": "Tradable Vaults for the Open Dollar stablecoin protocol. Caution! Trading this NFT means trading the ownership of your Vault in the Open Dollar protocol and all of the assets/collateral inside each Vault.","image": "https://app.opendollar.com/collectionImage.png","external_link": "https://opendollar.com"}';

33:   constructor(address _governor) ERC721('OpenDollar Vault', 'ODV') {

33:   constructor(address _governor) ERC721('OpenDollar Vault', 'ODV') {

95:     require(msg.sender == address(safeManager), 'V721: only safeManager');

96:     require(_proxyRegistry[_proxy] != address(0), 'V721: non-native proxy');

188:     require(to != address(0), 'V721: no burn');

148:     uri = string.concat('data:application/json;utf8,', contractMetaData);


```

[link](https://github.com/open-dollar/od-contracts/blob/v1.5.5-audit//src/contracts/proxies/Vault721.sol#L23-L23) , [link](https://github.com/open-dollar/od-contracts/blob/v1.5.5-audit//src/contracts/proxies/Vault721.sol#L33-L33), [link](https://github.com/open-dollar/od-contracts/blob/v1.5.5-audit//src/contracts/proxies/Vault721.sol#L33-L33), [link](https://github.com/open-dollar/od-contracts/blob/v1.5.5-audit//src/contracts/proxies/Vault721.sol#L95-L95), [link](https://github.com/open-dollar/od-contracts/blob/v1.5.5-audit//src/contracts/proxies/Vault721.sol#L96-L96), [link](https://github.com/open-dollar/od-contracts/blob/v1.5.5-audit//src/contracts/proxies/Vault721.sol#L188-L188), [link](https://github.com/open-dollar/od-contracts/blob/v1.5.5-audit//src/contracts/proxies/Vault721.sol#L148-L148)


```solidity

File: src/contracts/proxies/ODSafeManager.sol

137:     require(msg.sender == address(vault721), 'SafeMngr: Only Vault721');


```

[link](https://github.com/open-dollar/od-contracts/blob/v1.5.5-audit//src/contracts/proxies/ODSafeManager.sol#L137-L137) 


</details>


### [NC&#x2011;39] Contracts should have full test coverage 
While 100% code coverage does not guarantee that there are no bugs, it often will catch easy-to-find bugs, and will ensure that there are fewer regressions when the code invariably has to be modified. Furthermore, in order to get full coverage, code authors will often have to re-organize their code so that it is more modular, so that each component can be tested separately, which reduces interdependencies between modules and layers, and makes for code that is easier to reason about and audit.


*There are 1 instances of this issue:*



<details>
<summary>see instances</summary>


```solidity
File: src/contracts/AccountingEngine.sol

@audit Multiple files
1: 


```

[link](https://github.com/open-dollar/od-contracts/blob/v1.5.5-audit//src/contracts/AccountingEngine.sol#L1-L1) 


</details>


### [NC&#x2011;40] Contract declarations should have NatSpec `@title` annotations 



*There are 4 instances of this issue:*



<details>
<summary>see instances</summary>


```solidity
File: src/contracts/factories/CamelotRelayerFactory.sol

13: contract CamelotRelayerFactory is Authorizable, ICamelotRelayerFactory {


```

[link](https://github.com/open-dollar/od-contracts/blob/v1.5.5-audit//src/contracts/factories/CamelotRelayerFactory.sol#L13-L13) 


```solidity

File: src/contracts/gov/ODGovernor.sol

17: contract ODGovernor is


```

[link](https://github.com/open-dollar/od-contracts/blob/v1.5.5-audit//src/contracts/gov/ODGovernor.sol#L17-L17) 


```solidity

File: src/contracts/proxies/ODProxy.sol

7: contract ODProxy {


```

[link](https://github.com/open-dollar/od-contracts/blob/v1.5.5-audit//src/contracts/proxies/ODProxy.sol#L7-L7) 


```solidity

File: src/contracts/proxies/Vault721.sol

13: contract Vault721 is ERC721Enumerable {


```

[link](https://github.com/open-dollar/od-contracts/blob/v1.5.5-audit//src/contracts/proxies/Vault721.sol#L13-L13) 


</details>


### [NC&#x2011;41] Top level pragma declarations should be separated by two blank lines 



*There are 12 instances of this issue:*



<details>
<summary>see instances</summary>


```solidity
File: src/contracts/AccountingEngine.sol

2: pragma solidity 0.8.19;
3: 
4: import {IAccountingEngine} from '@interfaces/IAccountingEngine.sol';


```

[link](https://github.com/open-dollar/od-contracts/blob/v1.5.5-audit//src/contracts/AccountingEngine.sol#L2-L4) 


```solidity

File: src/contracts/oracles/CamelotRelayer.sol

2: pragma solidity 0.8.19;
3: 
4: import {IBaseOracle} from '@interfaces/oracles/IBaseOracle.sol';


```

[link](https://github.com/open-dollar/od-contracts/blob/v1.5.5-audit//src/contracts/oracles/CamelotRelayer.sol#L2-L4) 


```solidity

File: src/contracts/factories/CamelotRelayerFactory.sol

2: pragma solidity 0.8.19;
3: 
4: import {ICamelotRelayerFactory} from '@interfaces/factories/ICamelotRelayerFactory.sol';

11: import {EnumerableSet} from '@openzeppelin/utils/structs/EnumerableSet.sol';
12: 
13: contract CamelotRelayerFactory is Authorizable, ICamelotRelayerFactory {


```

[link](https://github.com/open-dollar/od-contracts/blob/v1.5.5-audit//src/contracts/factories/CamelotRelayerFactory.sol#L2-L4) , [link](https://github.com/open-dollar/od-contracts/blob/v1.5.5-audit//src/contracts/factories/CamelotRelayerFactory.sol#L11-L13)


```solidity

File: src/contracts/factories/CamelotRelayerChild.sol

2: pragma solidity 0.8.19;
3: 
4: import {ICamelotRelayerChild} from '@interfaces/factories/ICamelotRelayerChild.sol';


```

[link](https://github.com/open-dollar/od-contracts/blob/v1.5.5-audit//src/contracts/factories/CamelotRelayerChild.sol#L2-L4) 


```solidity

File: src/contracts/oracles/UniV3Relayer.sol

2: pragma solidity 0.8.19;
3: 
4: import {IBaseOracle} from '@interfaces/oracles/IBaseOracle.sol';


```

[link](https://github.com/open-dollar/od-contracts/blob/v1.5.5-audit//src/contracts/oracles/UniV3Relayer.sol#L2-L4) 


```solidity

File: src/contracts/gov/ODGovernor.sol

2: pragma solidity 0.8.19;
3: 
4: import {IVotes} from '@openzeppelin/governance/utils/IVotes.sol';

15: import {GovernorTimelockControl} from '@openzeppelin/governance/extensions/GovernorTimelockControl.sol';
16: 
17: contract ODGovernor is


```

[link](https://github.com/open-dollar/od-contracts/blob/v1.5.5-audit//src/contracts/gov/ODGovernor.sol#L2-L4) , [link](https://github.com/open-dollar/od-contracts/blob/v1.5.5-audit//src/contracts/gov/ODGovernor.sol#L15-L17)


```solidity

File: src/contracts/proxies/Vault721.sol

2: pragma solidity 0.8.19;
3: 
4: import {ERC721} from '@openzeppelin/token/ERC721/ERC721.sol';


```

[link](https://github.com/open-dollar/od-contracts/blob/v1.5.5-audit//src/contracts/proxies/Vault721.sol#L2-L4) 


```solidity

File: src/contracts/proxies/SAFEHandler.sol

2: pragma solidity 0.8.19;
3: 
4: import {ISAFEEngine} from '@interfaces/ISAFEEngine.sol';


```

[link](https://github.com/open-dollar/od-contracts/blob/v1.5.5-audit//src/contracts/proxies/SAFEHandler.sol#L2-L4) 


```solidity

File: src/contracts/proxies/ODSafeManager.sol

2: pragma solidity 0.8.19;
3: 
4: import {SAFEHandler} from '@contracts/proxies/SAFEHandler.sol';


```

[link](https://github.com/open-dollar/od-contracts/blob/v1.5.5-audit//src/contracts/proxies/ODSafeManager.sol#L2-L4) 


```solidity

File: src/contracts/proxies/actions/BasicActions.sol

2: pragma solidity 0.8.19;
3: 
4: import {ODSafeManager} from '@contracts/proxies/ODSafeManager.sol';


```

[link](https://github.com/open-dollar/od-contracts/blob/v1.5.5-audit//src/contracts/proxies/actions/BasicActions.sol#L2-L4) 


</details>


### [NC&#x2011;42] Critical functions should be a two step procedure 
Critical functions in Solidity contracts should follow a two-step procedure to enhance security, minimize human error, and ensure proper access control. By dividing sensitive operations into distinct phases, such as initiation and confirmation, developers can introduce a safeguard against unintended actions or unauthorized access.


*There are 5 instances of this issue:*



<details>
<summary>see instances</summary>


```solidity
File: src/contracts/AccountingEngine.sol

37:   function addAuthorization(address _account) external override(Authorizable, IAuthorizable) isAuthorized whenEnabled {


```

[link](https://github.com/open-dollar/od-contracts/blob/v1.5.5-audit//src/contracts/AccountingEngine.sol#L37-L37) 


```solidity

File: src/contracts/proxies/Vault721.sol

104:   function updateNftRenderer(

119:   function updateContractURI(string memory _metaData) external onlyGovernor {

126:   function setSafeManager(address _safeManager) external onlyGovernor {

133:   function setNftRenderer(address _nftRenderer) external onlyGovernor {


```

[link](https://github.com/open-dollar/od-contracts/blob/v1.5.5-audit//src/contracts/proxies/Vault721.sol#L104-L104) , [link](https://github.com/open-dollar/od-contracts/blob/v1.5.5-audit//src/contracts/proxies/Vault721.sol#L119-L119), [link](https://github.com/open-dollar/od-contracts/blob/v1.5.5-audit//src/contracts/proxies/Vault721.sol#L126-L126), [link](https://github.com/open-dollar/od-contracts/blob/v1.5.5-audit//src/contracts/proxies/Vault721.sol#L133-L133)


</details>


### [NC&#x2011;43] Event is missing `indexed` fields 
Index event fields make the field more quickly accessible to off-chain tools that parse events. However, note that each index field costs extra gas during emission, so it's not necessarily best to index the maximum allowed per event (three fields). Each event should use three indexed fields if there are three or more fields, and gas usage is not particularly of concern for the events in question. If there are fewer than three fields, all of the fields should be indexed.


*There are 1 instances of this issue:*



<details>
<summary>see instances</summary>


```solidity
File: src/contracts/proxies/Vault721.sol

28:   event CreateProxy(address indexed _user, address _proxy);


```

[link](https://github.com/open-dollar/od-contracts/blob/v1.5.5-audit//src/contracts/proxies/Vault721.sol#L28-L28) 


</details>


### [NC&#x2011;44] Unused Import 
Some files/Items are imported but never used


*There are 10 instances of this issue:*



<details>
<summary>see instances</summary>


```solidity
File: src/contracts/AccountingEngine.sol

//@audit `IAuthorizable` is not used
9: import {Authorizable, IAuthorizable} from '@contracts/utils/Authorizable.sol';


```

[link](https://github.com/open-dollar/od-contracts/blob/v1.5.5-audit//src/contracts/AccountingEngine.sol#L9-L9) 


```solidity

File: src/contracts/oracles/CamelotRelayer.sol

//@audit `CAMELOT_V3_FACTORY` is not used
11: import {CAMELOT_V3_FACTORY, GOERLI_CAMELOT_V3_FACTORY} from '@script/Registry.s.sol';


```

[link](https://github.com/open-dollar/od-contracts/blob/v1.5.5-audit//src/contracts/oracles/CamelotRelayer.sol#L11-L11) 


```solidity

File: src/contracts/oracles/UniV3Relayer.sol

//@audit `UNISWAP_V3_FACTORY` is not used
9: import {UNISWAP_V3_FACTORY, GOERLI_UNISWAP_V3_FACTORY} from '@script/Registry.s.sol';


```

[link](https://github.com/open-dollar/od-contracts/blob/v1.5.5-audit//src/contracts/oracles/UniV3Relayer.sol#L9-L9) 


```solidity

File: src/contracts/gov/ODGovernor.sol

//@audit `IERC165` is not used
5: import {IERC165} from '@openzeppelin/utils/introspection/IERC165.sol';


```

[link](https://github.com/open-dollar/od-contracts/blob/v1.5.5-audit//src/contracts/gov/ODGovernor.sol#L5-L5) 


```solidity

File: src/contracts/proxies/actions/BasicActions.sol

//@audit `ODProxy` is not used
5: import {ODProxy} from '@contracts/proxies/ODProxy.sol';

//@audit `ICoinJoin` is not used
8: import {ICoinJoin} from '@interfaces/utils/ICoinJoin.sol';

//@audit `ICollateralJoin` is not used
10: import {ICollateralJoin} from '@interfaces/utils/ICollateralJoin.sol';

//@audit `IERC20Metadata` is not used
11: import {IERC20Metadata} from '@openzeppelin/token/ERC20/extensions/IERC20Metadata.sol';

//@audit `WAD` is not used
14: import {Math, WAD, RAY, RAD} from '@libraries/Math.sol';

//@audit `RAD` is not used
14: import {Math, WAD, RAY, RAD} from '@libraries/Math.sol';


```

[link](https://github.com/open-dollar/od-contracts/blob/v1.5.5-audit//src/contracts/proxies/actions/BasicActions.sol#L5-L5) , [link](https://github.com/open-dollar/od-contracts/blob/v1.5.5-audit//src/contracts/proxies/actions/BasicActions.sol#L8-L8), [link](https://github.com/open-dollar/od-contracts/blob/v1.5.5-audit//src/contracts/proxies/actions/BasicActions.sol#L10-L10), [link](https://github.com/open-dollar/od-contracts/blob/v1.5.5-audit//src/contracts/proxies/actions/BasicActions.sol#L11-L11), [link](https://github.com/open-dollar/od-contracts/blob/v1.5.5-audit//src/contracts/proxies/actions/BasicActions.sol#L14-L14), [link](https://github.com/open-dollar/od-contracts/blob/v1.5.5-audit//src/contracts/proxies/actions/BasicActions.sol#L14-L14)


</details>


### [NC&#x2011;45] Unused parameter 



*There are 1 instances of this issue:*



<details>
<summary>see instances</summary>


```solidity
File: src/contracts/proxies/Vault721.sol

//@audit `batchSize` is not used
187:   function _afterTokenTransfer(address from, address to, uint256 firstTokenId, uint256 batchSize) internal override {


```

[link](https://github.com/open-dollar/od-contracts/blob/v1.5.5-audit//src/contracts/proxies/Vault721.sol#L187-L187) 


</details>


### [NC&#x2011;46] Use `bytes.concat()` on bytes instead of `abi.encodePacked()` for clearer semantic meaning 
Starting with version 0.8.4, Solidity has the `bytes.concat()` function, which allows one to concatenate a list of bytes/strings, without extra padding. Using this function rather than `abi.encodePacked()` makes the intended operation more clear, leading to less reviewer confusion.


*There are 2 instances of this issue:*



<details>
<summary>see instances</summary>


```solidity
File: src/contracts/oracles/CamelotRelayer.sol

61:     symbol = string(abi.encodePacked(IERC20Metadata(_baseToken).symbol(), ' / ', IERC20Metadata(_quoteToken).symbol()));


```

[link](https://github.com/open-dollar/od-contracts/blob/v1.5.5-audit//src/contracts/oracles/CamelotRelayer.sol#L61-L61) 


```solidity

File: src/contracts/oracles/UniV3Relayer.sol

67:     symbol = string(abi.encodePacked(IERC20Metadata(_baseToken).symbol(), ' / ', IERC20Metadata(_quoteToken).symbol()));


```

[link](https://github.com/open-dollar/od-contracts/blob/v1.5.5-audit//src/contracts/oracles/UniV3Relayer.sol#L67-L67) 


</details>


### [NC&#x2011;47] Use `string.concat()` on strings instead of `abi.encodePacked()` for clearer semantic meaning 
Starting with version 0.8.12, Solidity has the `string.concat()` function, which allows one to concatenate a list of strings, without extra padding. Using this function rather than `abi.encodePacked()` makes the intended operation more clear, leading to less reviewer confusion.


*There are 2 instances of this issue:*



<details>
<summary>see instances</summary>


```solidity
File: src/contracts/oracles/CamelotRelayer.sol

61:     symbol = string(abi.encodePacked(IERC20Metadata(_baseToken).symbol(), ' / ', IERC20Metadata(_quoteToken).symbol()));


```

[link](https://github.com/open-dollar/od-contracts/blob/v1.5.5-audit//src/contracts/oracles/CamelotRelayer.sol#L61-L61) 


```solidity

File: src/contracts/oracles/UniV3Relayer.sol

67:     symbol = string(abi.encodePacked(IERC20Metadata(_baseToken).symbol(), ' / ', IERC20Metadata(_quoteToken).symbol()));


```

[link](https://github.com/open-dollar/od-contracts/blob/v1.5.5-audit//src/contracts/oracles/UniV3Relayer.sol#L67-L67) 


</details>


### [NC&#x2011;48] Constants should be defined rather than using magic numbers 
Even [assembly](https://github.com/code-423n4/2022-05-opensea-seaport/blob/9d7ce4d08bf3c3010304a0476a785c70c0e90ae7/contracts/lib/TokenTransferrer.sol#L35-L39) can benefit from using readable constants instead of hex/numeric literals


*There are 8 instances of this issue:*



<details>
<summary>see instances</summary>


```solidity
File: src/contracts/oracles/CamelotRelayer.sol

//@audit Try to make a `constant` with `18` value
58:     multiplier = 18 - IERC20Metadata(_quoteToken).decimals();

//@audit Try to make a `constant` with `10` value
57:     baseAmount = uint128(10 ** IERC20Metadata(_baseToken).decimals());

//@audit Try to make a `constant` with `10` value
104:     return _quoteResult * 10 ** multiplier;


```

[link](https://github.com/open-dollar/od-contracts/blob/v1.5.5-audit//src/contracts/oracles/CamelotRelayer.sol#L58-L58) , [link](https://github.com/open-dollar/od-contracts/blob/v1.5.5-audit//src/contracts/oracles/CamelotRelayer.sol#L57-L57), [link](https://github.com/open-dollar/od-contracts/blob/v1.5.5-audit//src/contracts/oracles/CamelotRelayer.sol#L104-L104)


```solidity

File: src/contracts/oracles/UniV3Relayer.sol

//@audit Try to make a `constant` with `18` value
64:     multiplier = 18 - IERC20Metadata(_quoteToken).decimals();

//@audit Try to make a `constant` with `10` value
63:     baseAmount = uint128(10 ** IERC20Metadata(_baseToken).decimals());

//@audit Try to make a `constant` with `10` value
111:     return _quoteResult * 10 ** multiplier;


```

[link](https://github.com/open-dollar/od-contracts/blob/v1.5.5-audit//src/contracts/oracles/UniV3Relayer.sol#L64-L64) , [link](https://github.com/open-dollar/od-contracts/blob/v1.5.5-audit//src/contracts/oracles/UniV3Relayer.sol#L63-L63), [link](https://github.com/open-dollar/od-contracts/blob/v1.5.5-audit//src/contracts/oracles/UniV3Relayer.sol#L111-L111)


```solidity

File: src/contracts/gov/ODGovernor.sol

//@audit Try to make a `constant` with `15` value
41:     GovernorSettings(1, 15, 0)

//@audit Try to make a `constant` with `3` value
43:     GovernorVotesQuorumFraction(3)


```

[link](https://github.com/open-dollar/od-contracts/blob/v1.5.5-audit//src/contracts/gov/ODGovernor.sol#L41-L41) , [link](https://github.com/open-dollar/od-contracts/blob/v1.5.5-audit//src/contracts/gov/ODGovernor.sol#L43-L43)


</details>


### [NC&#x2011;49] Use the latest solidity (prior to 0.8.20 if on L2s) for deployment 
```
When deploying contracts, you should use the latest released version of Solidity.Apart from exceptional cases, only the latest version receives security fixes.
```
https://docs.soliditylang.org/en/v0.8.20/


*There are 11 instances of this issue:*



<details>
<summary>see instances</summary>


```solidity
File: src/contracts/AccountingEngine.sol

2: pragma solidity 0.8.19;


```

[link](https://github.com/open-dollar/od-contracts/blob/v1.5.5-audit//src/contracts/AccountingEngine.sol#L2-L2) 


```solidity

File: src/contracts/oracles/CamelotRelayer.sol

2: pragma solidity 0.8.19;


```

[link](https://github.com/open-dollar/od-contracts/blob/v1.5.5-audit//src/contracts/oracles/CamelotRelayer.sol#L2-L2) 


```solidity

File: src/contracts/factories/CamelotRelayerFactory.sol

2: pragma solidity 0.8.19;


```

[link](https://github.com/open-dollar/od-contracts/blob/v1.5.5-audit//src/contracts/factories/CamelotRelayerFactory.sol#L2-L2) 


```solidity

File: src/contracts/factories/CamelotRelayerChild.sol

2: pragma solidity 0.8.19;


```

[link](https://github.com/open-dollar/od-contracts/blob/v1.5.5-audit//src/contracts/factories/CamelotRelayerChild.sol#L2-L2) 


```solidity

File: src/contracts/oracles/UniV3Relayer.sol

2: pragma solidity 0.8.19;


```

[link](https://github.com/open-dollar/od-contracts/blob/v1.5.5-audit//src/contracts/oracles/UniV3Relayer.sol#L2-L2) 


```solidity

File: src/contracts/gov/ODGovernor.sol

2: pragma solidity 0.8.19;


```

[link](https://github.com/open-dollar/od-contracts/blob/v1.5.5-audit//src/contracts/gov/ODGovernor.sol#L2-L2) 


```solidity

File: src/contracts/proxies/ODProxy.sol

2: pragma solidity 0.8.19;


```

[link](https://github.com/open-dollar/od-contracts/blob/v1.5.5-audit//src/contracts/proxies/ODProxy.sol#L2-L2) 


```solidity

File: src/contracts/proxies/Vault721.sol

2: pragma solidity 0.8.19;


```

[link](https://github.com/open-dollar/od-contracts/blob/v1.5.5-audit//src/contracts/proxies/Vault721.sol#L2-L2) 


```solidity

File: src/contracts/proxies/SAFEHandler.sol

2: pragma solidity 0.8.19;


```

[link](https://github.com/open-dollar/od-contracts/blob/v1.5.5-audit//src/contracts/proxies/SAFEHandler.sol#L2-L2) 


```solidity

File: src/contracts/proxies/ODSafeManager.sol

2: pragma solidity 0.8.19;


```

[link](https://github.com/open-dollar/od-contracts/blob/v1.5.5-audit//src/contracts/proxies/ODSafeManager.sol#L2-L2) 


```solidity

File: src/contracts/proxies/actions/BasicActions.sol

2: pragma solidity 0.8.19;


```

[link](https://github.com/open-dollar/od-contracts/blob/v1.5.5-audit//src/contracts/proxies/actions/BasicActions.sol#L2-L2) 


</details>


### [NC&#x2011;50] Use a single file for system wide constants 
Consider grouping all the system constants under a single file. This finding shows only the first constant for each file.


*There are 3 instances of this issue:*



<details>
<summary>see instances</summary>


```solidity
File: src/contracts/AccountingEngine.sol

28:   uint256 internal constant ONE_HUNDRED_WAD = 100 * WAD;


```

[link](https://github.com/open-dollar/od-contracts/blob/v1.5.5-audit//src/contracts/AccountingEngine.sol#L28-L28) 


```solidity

File: src/contracts/oracles/CamelotRelayer.sol

20:   address internal constant _CAMELOT_FACTORY = GOERLI_CAMELOT_V3_FACTORY;


```

[link](https://github.com/open-dollar/od-contracts/blob/v1.5.5-audit//src/contracts/oracles/CamelotRelayer.sol#L20-L20) 


```solidity

File: src/contracts/oracles/UniV3Relayer.sol

18:   address internal constant _UNI_V3_FACTORY = GOERLI_UNISWAP_V3_FACTORY;


```

[link](https://github.com/open-dollar/od-contracts/blob/v1.5.5-audit//src/contracts/oracles/UniV3Relayer.sol#L18-L18) 


</details>


### [NC&#x2011;51] Consider using SMTChecker 
The SMTChecker is a valuable tool for Solidity developers as it helps detect potential vulnerabilities and logical errors in the contract's code. By utilizing Satisfiability Modulo Theories (SMT) solvers, it can reason about the potential states a contract can be in, and therefore, identify conditions that could lead to undesirable behavior. This automatic formal verification can catch issues that might otherwise be missed in manual code reviews or standard testing, enhancing the overall contract's security and reliability.


*There are 11 instances of this issue:*



<details>
<summary>see instances</summary>


```solidity
File: src/contracts/AccountingEngine.sol

2: pragma solidity 0.8.19;


```

[link](https://github.com/open-dollar/od-contracts/blob/v1.5.5-audit//src/contracts/AccountingEngine.sol#L2-L2) 


```solidity

File: src/contracts/oracles/CamelotRelayer.sol

2: pragma solidity 0.8.19;


```

[link](https://github.com/open-dollar/od-contracts/blob/v1.5.5-audit//src/contracts/oracles/CamelotRelayer.sol#L2-L2) 


```solidity

File: src/contracts/factories/CamelotRelayerFactory.sol

2: pragma solidity 0.8.19;


```

[link](https://github.com/open-dollar/od-contracts/blob/v1.5.5-audit//src/contracts/factories/CamelotRelayerFactory.sol#L2-L2) 


```solidity

File: src/contracts/factories/CamelotRelayerChild.sol

2: pragma solidity 0.8.19;


```

[link](https://github.com/open-dollar/od-contracts/blob/v1.5.5-audit//src/contracts/factories/CamelotRelayerChild.sol#L2-L2) 


```solidity

File: src/contracts/oracles/UniV3Relayer.sol

2: pragma solidity 0.8.19;


```

[link](https://github.com/open-dollar/od-contracts/blob/v1.5.5-audit//src/contracts/oracles/UniV3Relayer.sol#L2-L2) 


```solidity

File: src/contracts/gov/ODGovernor.sol

2: pragma solidity 0.8.19;


```

[link](https://github.com/open-dollar/od-contracts/blob/v1.5.5-audit//src/contracts/gov/ODGovernor.sol#L2-L2) 


```solidity

File: src/contracts/proxies/ODProxy.sol

2: pragma solidity 0.8.19;


```

[link](https://github.com/open-dollar/od-contracts/blob/v1.5.5-audit//src/contracts/proxies/ODProxy.sol#L2-L2) 


```solidity

File: src/contracts/proxies/Vault721.sol

2: pragma solidity 0.8.19;


```

[link](https://github.com/open-dollar/od-contracts/blob/v1.5.5-audit//src/contracts/proxies/Vault721.sol#L2-L2) 


```solidity

File: src/contracts/proxies/SAFEHandler.sol

2: pragma solidity 0.8.19;


```

[link](https://github.com/open-dollar/od-contracts/blob/v1.5.5-audit//src/contracts/proxies/SAFEHandler.sol#L2-L2) 


```solidity

File: src/contracts/proxies/ODSafeManager.sol

2: pragma solidity 0.8.19;


```

[link](https://github.com/open-dollar/od-contracts/blob/v1.5.5-audit//src/contracts/proxies/ODSafeManager.sol#L2-L2) 


```solidity

File: src/contracts/proxies/actions/BasicActions.sol

2: pragma solidity 0.8.19;


```

[link](https://github.com/open-dollar/od-contracts/blob/v1.5.5-audit//src/contracts/proxies/actions/BasicActions.sol#L2-L2) 


</details>


### [NC&#x2011;52] Utility contracts can be made into libraries 



*There are 2 instances of this issue:*



<details>
<summary>see instances</summary>


```solidity
File: src/contracts/factories/CamelotRelayerChild.sol

14: contract CamelotRelayerChild is CamelotRelayer, FactoryChild, ICamelotRelayerChild {


```

[link](https://github.com/open-dollar/od-contracts/blob/v1.5.5-audit//src/contracts/factories/CamelotRelayerChild.sol#L14-L14) 


```solidity

File: src/contracts/proxies/SAFEHandler.sol

11: contract SAFEHandler {


```

[link](https://github.com/open-dollar/od-contracts/blob/v1.5.5-audit//src/contracts/proxies/SAFEHandler.sol#L11-L11) 


</details>


### [NC&#x2011;53] High cyclomatic complexity 
Consider breaking down these blocks into more manageable units, by splitting things into utility functions, by reducing nesting, and by using early returns


*There are 2 instances of this issue:*



<details>
<summary>see instances</summary>


```solidity
File: src/contracts/AccountingEngine.sol

198:   function auctionSurplus() external returns (uint256 _id) {
199:     if(_params.surplusTransferPercentage > WAD) revert AccEng_surplusTransferPercentOverLimit();
200:     if (_params.surplusAmount == 0) revert AccEng_NullAmount();
201:     if (extraSurplusReceiver == address(0)) revert AccEng_NullSurplusReceiver();
202:     if (block.timestamp < lastSurplusTime + _params.surplusDelay) revert AccEng_SurplusCooldown();
203: 
204:     uint256 _coinBalance = safeEngine.coinBalance(address(this));
205:     uint256 _debtBalance = safeEngine.debtBalance(address(this));
206:     (_coinBalance, _debtBalance) = _settleDebt(_coinBalance, _debtBalance, _unqueuedUnauctionedDebt(_debtBalance));
207: 
208:     if (_coinBalance < _debtBalance + _params.surplusAmount + _params.surplusBuffer) {
209:       revert AccEng_InsufficientSurplus();
210:     }
211: 
212:     // auction surplus percentage
213:     if (_params.surplusTransferPercentage < ONE_HUNDRED_WAD) {
214:       _id = surplusAuctionHouse.startAuction({
215:         _amountToSell: _params.surplusAmount.wmul(ONE_HUNDRED_WAD - _params.surplusTransferPercentage),
216:         _initialBid: 0
217:       });
218: 
219:       lastSurplusTime = block.timestamp;
220:       emit AuctionSurplus(_id, 0, _params.surplusAmount.wmul(ONE_HUNDRED_WAD - _params.surplusTransferPercentage));
221:     }
222: 
223:     // transfer surplus percentage
224:     if (_params.surplusTransferPercentage > 0) {
225:       if (extraSurplusReceiver == address(0)) revert AccEng_NullSurplusReceiver();
226: 
227:       safeEngine.transferInternalCoins({
228:         _source: address(this),
229:         _destination: extraSurplusReceiver,
230:         _rad: _params.surplusAmount.wmul(_params.surplusTransferPercentage)
231:       });
232: 
233:       lastSurplusTime = block.timestamp;
234:       emit TransferSurplus(extraSurplusReceiver, _params.surplusAmount.wmul(_params.surplusTransferPercentage));
235:     }
236:   }

283:   function _modifyParameters(bytes32 _param, bytes memory _data) internal override {
284:     uint256 _uint256 = _data.toUint256();
285:     address _address = _data.toAddress();
286: 
287:     // params
288:     if (_param == 'surplusTransferPercentage') _params.surplusTransferPercentage = _uint256;
289:     else if (_param == 'surplusDelay') _params.surplusDelay = _uint256;
290:     else if (_param == 'popDebtDelay') _params.popDebtDelay = _uint256;
291:     else if (_param == 'disableCooldown') _params.disableCooldown = _uint256;
292:     else if (_param == 'surplusAmount') _params.surplusAmount = _uint256;
293:     else if (_param == 'debtAuctionBidSize') _params.debtAuctionBidSize = _uint256;
294:     else if (_param == 'debtAuctionMintedTokens') _params.debtAuctionMintedTokens = _uint256;
295:     else if (_param == 'surplusBuffer') _params.surplusBuffer = _uint256;
296:     // registry
297:     else if (_param == 'surplusAuctionHouse') _setSurplusAuctionHouse(_address);
298:     else if (_param == 'debtAuctionHouse') debtAuctionHouse = IDebtAuctionHouse(_address);
299:     else if (_param == 'postSettlementSurplusDrain') postSettlementSurplusDrain = _address;
300:     else if (_param == 'extraSurplusReceiver') extraSurplusReceiver = _address;
301:     else revert UnrecognizedParam();
302:   }


```

[link](https://github.com/open-dollar/od-contracts/blob/v1.5.5-audit//src/contracts/AccountingEngine.sol#L198-L236) , [link](https://github.com/open-dollar/od-contracts/blob/v1.5.5-audit//src/contracts/AccountingEngine.sol#L283-L302)


</details>


### [NC&#x2011;54] A function which defines named returns in it's declaration doesn't need to use return 
Remove the return statement once ensuring it is safe to do so


*There are 10 instances of this issue:*



<details>
<summary>see instances</summary>


```solidity
File: src/contracts/AccountingEngine.sol

61:   function params() external view returns (AccountingEngineParams memory _accEngineParams) {
62:     return _params;
63:   }

104:   function unqueuedUnauctionedDebt() external view returns (uint256 __unqueuedUnauctionedDebt) {
105:     return _unqueuedUnauctionedDebt(safeEngine.debtBalance(address(this)));
106:   }

108:   function _unqueuedUnauctionedDebt(uint256 _debtBalance) internal view returns (uint256 __unqueuedUnauctionedDebt) {
109:     return (_debtBalance - totalQueuedDebt) - totalOnAuctionDebt;
110:   }


```

[link](https://github.com/open-dollar/od-contracts/blob/v1.5.5-audit//src/contracts/AccountingEngine.sol#L61-L63) , [link](https://github.com/open-dollar/od-contracts/blob/v1.5.5-audit//src/contracts/AccountingEngine.sol#L104-L106), [link](https://github.com/open-dollar/od-contracts/blob/v1.5.5-audit//src/contracts/AccountingEngine.sol#L108-L110)


```solidity

File: src/contracts/oracles/CamelotRelayer.sol

68:   function getResultWithValidity() external view returns (uint256 _result, bool _validity) {
69:     // If the pool doesn't have enough history return false
70:     if (OracleLibrary.getOldestObservationSecondsAgo(camelotPair) < quotePeriod) {
71:       return (0, false);
72:     }
73:     // Consult the query with a TWAP period of quotePeriod
74:     (int24 _arithmeticMeanTick,) = OracleLibrary.consult(camelotPair, quotePeriod);
75:     // Calculate the quote amount
76:     uint256 _quoteAmount = OracleLibrary.getQuoteAtTick({
77:       tick: _arithmeticMeanTick,
78:       baseAmount: baseAmount,
79:       baseToken: baseToken,
80:       quoteToken: quoteToken
81:     });
82:     // Process the quote result to 18 decimal quote
83:     _result = _parseResult(_quoteAmount);
84:     _validity = true;
85:   }

103:   function _parseResult(uint256 _quoteResult) internal view returns (uint256 _result) {
104:     return _quoteResult * 10 ** multiplier;
105:   }


```

[link](https://github.com/open-dollar/od-contracts/blob/v1.5.5-audit//src/contracts/oracles/CamelotRelayer.sol#L68-L85) , [link](https://github.com/open-dollar/od-contracts/blob/v1.5.5-audit//src/contracts/oracles/CamelotRelayer.sol#L103-L105)


```solidity

File: src/contracts/factories/CamelotRelayerFactory.sol

34:   function camelotRelayersList() external view returns (address[] memory _camelotRelayersList) {
35:     return _camelotRelayers.values();
36:   }


```

[link](https://github.com/open-dollar/od-contracts/blob/v1.5.5-audit//src/contracts/factories/CamelotRelayerFactory.sol#L34-L36) 


```solidity

File: src/contracts/oracles/UniV3Relayer.sol

74:   function getResultWithValidity() external view returns (uint256 _result, bool _validity) {
75:     // If the pool doesn't have enough history return false
76:     if (OracleLibrary.getOldestObservationSecondsAgo(uniV3Pool) < quotePeriod) {
77:       return (0, false);
78:     }
79:     // Consult the query with a TWAP period of quotePeriod
80:     (int24 _arithmeticMeanTick,) = OracleLibrary.consult(uniV3Pool, quotePeriod);
81:     // Calculate the quote amount
82:     uint256 _quoteAmount = OracleLibrary.getQuoteAtTick({
83:       tick: _arithmeticMeanTick,
84:       baseAmount: baseAmount,
85:       baseToken: baseToken,
86:       quoteToken: quoteToken
87:     });
88:     // Process the quote result to 18 decimal quote
89:     _result = _parseResult(_quoteAmount);
90:     _validity = true;
91:   }

110:   function _parseResult(uint256 _quoteResult) internal view returns (uint256 _result) {
111:     return _quoteResult * 10 ** multiplier;
112:   }


```

[link](https://github.com/open-dollar/od-contracts/blob/v1.5.5-audit//src/contracts/oracles/UniV3Relayer.sol#L74-L91) , [link](https://github.com/open-dollar/od-contracts/blob/v1.5.5-audit//src/contracts/oracles/UniV3Relayer.sol#L110-L112)


```solidity

File: src/contracts/proxies/ODSafeManager.sol

118:   function openSAFE(bytes32 _cType, address _usr) external returns (uint256 _id) {
119:     if (_usr == address(0)) revert ZeroAddress();
120: 
121:     ++_safeId;
122:     address _safeHandler = address(new SAFEHandler(safeEngine));
123: 
124:     _safeData[_safeId] = SAFEData({owner: _usr, safeHandler: _safeHandler, collateralType: _cType});
125: 
126:     _usrSafes[_usr].add(_safeId);
127:     _usrSafesPerCollat[_usr][_cType].add(_safeId);
128: 
129:     vault721.mint(_usr, _safeId);
130: 
131:     emit OpenSAFE(msg.sender, _usr, _safeId);
132:     return _safeId;
133:   }


```

[link](https://github.com/open-dollar/od-contracts/blob/v1.5.5-audit//src/contracts/proxies/ODSafeManager.sol#L118-L133) 


```solidity

File: src/contracts/proxies/actions/BasicActions.sol

226:   function openSAFE(address _manager, bytes32 _cType, address _usr) external delegateCall returns (uint256 _safeId) {
227:     return _openSAFE(_manager, _cType, _usr);
228:   }


```

[link](https://github.com/open-dollar/od-contracts/blob/v1.5.5-audit//src/contracts/proxies/actions/BasicActions.sol#L226-L228) 


</details>


### [NC&#x2011;55] `error` declarations should have NatSpec descriptions 



*There are 6 instances of this issue:*



<details>
<summary>see instances</summary>


```solidity
File: src/contracts/proxies/ODProxy.sol

8:   error TargetAddressRequired();

9:   error TargetCallFailed(bytes _response);

10:   error OnlyOwner();


```

[link](https://github.com/open-dollar/od-contracts/blob/v1.5.5-audit//src/contracts/proxies/ODProxy.sol#L8-L8) , [link](https://github.com/open-dollar/od-contracts/blob/v1.5.5-audit//src/contracts/proxies/ODProxy.sol#L9-L9), [link](https://github.com/open-dollar/od-contracts/blob/v1.5.5-audit//src/contracts/proxies/ODProxy.sol#L10-L10)


```solidity

File: src/contracts/proxies/Vault721.sol

14:   error NotGovernor();

15:   error ProxyAlreadyExist();

16:   error ZeroAddress();


```

[link](https://github.com/open-dollar/od-contracts/blob/v1.5.5-audit//src/contracts/proxies/Vault721.sol#L14-L14) , [link](https://github.com/open-dollar/od-contracts/blob/v1.5.5-audit//src/contracts/proxies/Vault721.sol#L15-L15), [link](https://github.com/open-dollar/od-contracts/blob/v1.5.5-audit//src/contracts/proxies/Vault721.sol#L16-L16)


</details>


### [NC&#x2011;56] Contract declarations should have NatSpec `@dev` annotations 



*There are 6 instances of this issue:*



<details>
<summary>see instances</summary>


```solidity
File: src/contracts/factories/CamelotRelayerFactory.sol

13: contract CamelotRelayerFactory is Authorizable, ICamelotRelayerFactory {


```

[link](https://github.com/open-dollar/od-contracts/blob/v1.5.5-audit//src/contracts/factories/CamelotRelayerFactory.sol#L13-L13) 


```solidity

File: src/contracts/factories/CamelotRelayerChild.sol

10: /**
11:  * @title  CamelotRelayerChild
12:  * @notice This contract inherits all the functionality of `CamelotRelayer.sol` to be factory deployed
13:  */


```

[link](https://github.com/open-dollar/od-contracts/blob/v1.5.5-audit//src/contracts/factories/CamelotRelayerChild.sol#L10-L13) 


```solidity

File: src/contracts/gov/ODGovernor.sol

17: contract ODGovernor is


```

[link](https://github.com/open-dollar/od-contracts/blob/v1.5.5-audit//src/contracts/gov/ODGovernor.sol#L17-L17) 


```solidity

File: src/contracts/proxies/ODProxy.sol

7: contract ODProxy {


```

[link](https://github.com/open-dollar/od-contracts/blob/v1.5.5-audit//src/contracts/proxies/ODProxy.sol#L7-L7) 


```solidity

File: src/contracts/proxies/Vault721.sol

13: contract Vault721 is ERC721Enumerable {


```

[link](https://github.com/open-dollar/od-contracts/blob/v1.5.5-audit//src/contracts/proxies/Vault721.sol#L13-L13) 


```solidity

File: src/contracts/proxies/actions/BasicActions.sol

18: /**
19:  * @title  BasicActions
20:  * @notice This contract defines the actions that can be executed to manage a SAFE
21:  */


```

[link](https://github.com/open-dollar/od-contracts/blob/v1.5.5-audit//src/contracts/proxies/actions/BasicActions.sol#L18-L21) 


</details>


### [NC&#x2011;57] Contract should expose an `interface` 
The `contract`s should expose an `interface` so that other projects can more easily integrate with it, without having to develop their own non-standard variants.


*There are 55 instances of this issue:*



<details>
<summary>see instances</summary>


```solidity
File: src/contracts/AccountingEngine.sol

61:   function params() external view returns (AccountingEngineParams memory _accEngineParams) {

104:   function unqueuedUnauctionedDebt() external view returns (uint256 __unqueuedUnauctionedDebt) {

115:   function pushDebtToQueue(uint256 _debtBlock) external isAuthorized {

123:   function popDebtFromQueue(uint256 _debtBlockTimestamp) external {

139:   function settleDebt(uint256 _rad) external {

159:   function cancelAuctionedDebtWithSurplus(uint256 _rad) external {

175:   function auctionDebt() external returns (uint256 _id) {

198:   function auctionSurplus() external returns (uint256 _id) {

260:   function transferPostSettlementSurplus() external whenDisabled {


```

[link](https://github.com/open-dollar/od-contracts/blob/v1.5.5-audit//src/contracts/AccountingEngine.sol#L61-L61) , [link](https://github.com/open-dollar/od-contracts/blob/v1.5.5-audit//src/contracts/AccountingEngine.sol#L104-L104), [link](https://github.com/open-dollar/od-contracts/blob/v1.5.5-audit//src/contracts/AccountingEngine.sol#L115-L115), [link](https://github.com/open-dollar/od-contracts/blob/v1.5.5-audit//src/contracts/AccountingEngine.sol#L123-L123), [link](https://github.com/open-dollar/od-contracts/blob/v1.5.5-audit//src/contracts/AccountingEngine.sol#L139-L139), [link](https://github.com/open-dollar/od-contracts/blob/v1.5.5-audit//src/contracts/AccountingEngine.sol#L159-L159), [link](https://github.com/open-dollar/od-contracts/blob/v1.5.5-audit//src/contracts/AccountingEngine.sol#L175-L175), [link](https://github.com/open-dollar/od-contracts/blob/v1.5.5-audit//src/contracts/AccountingEngine.sol#L198-L198), [link](https://github.com/open-dollar/od-contracts/blob/v1.5.5-audit//src/contracts/AccountingEngine.sol#L260-L260)


```solidity

File: src/contracts/oracles/CamelotRelayer.sol

68:   function getResultWithValidity() external view returns (uint256 _result, bool _validity) {

91:   function read() external view returns (uint256 _result) {


```

[link](https://github.com/open-dollar/od-contracts/blob/v1.5.5-audit//src/contracts/oracles/CamelotRelayer.sol#L68-L68) , [link](https://github.com/open-dollar/od-contracts/blob/v1.5.5-audit//src/contracts/oracles/CamelotRelayer.sol#L91-L91)


```solidity

File: src/contracts/factories/CamelotRelayerFactory.sol

23:   function deployCamelotRelayer(

34:   function camelotRelayersList() external view returns (address[] memory _camelotRelayersList) {


```

[link](https://github.com/open-dollar/od-contracts/blob/v1.5.5-audit//src/contracts/factories/CamelotRelayerFactory.sol#L23-L23) , [link](https://github.com/open-dollar/od-contracts/blob/v1.5.5-audit//src/contracts/factories/CamelotRelayerFactory.sol#L34-L34)


```solidity

File: src/contracts/oracles/UniV3Relayer.sol

74:   function getResultWithValidity() external view returns (uint256 _result, bool _validity) {

97:   function read() external view returns (uint256 _result) {


```

[link](https://github.com/open-dollar/od-contracts/blob/v1.5.5-audit//src/contracts/oracles/UniV3Relayer.sol#L74-L74) , [link](https://github.com/open-dollar/od-contracts/blob/v1.5.5-audit//src/contracts/oracles/UniV3Relayer.sol#L97-L97)


```solidity

File: src/contracts/proxies/ODProxy.sol

26:   function execute(address _target, bytes memory _data) external payable onlyOwner returns (bytes memory _response) {


```

[link](https://github.com/open-dollar/od-contracts/blob/v1.5.5-audit//src/contracts/proxies/ODProxy.sol#L26-L26) 


```solidity

File: src/contracts/proxies/Vault721.sol

56:   function initializeManager() external {

63:   function initializeRenderer() external {

70:   function getProxy(address _user) external view returns (address _proxy) {

77:   function build() external returns (address payable _proxy) {

85:   function build(address _user) external returns (address payable _proxy) {

94:   function mint(address _proxy, uint256 _safeId) external {

104:   function updateNftRenderer(

119:   function updateContractURI(string memory _metaData) external onlyGovernor {

126:   function setSafeManager(address _safeManager) external onlyGovernor {

133:   function setNftRenderer(address _nftRenderer) external onlyGovernor {

147:   function contractURI() public view returns (string memory uri) {


```

[link](https://github.com/open-dollar/od-contracts/blob/v1.5.5-audit//src/contracts/proxies/Vault721.sol#L56-L56) , [link](https://github.com/open-dollar/od-contracts/blob/v1.5.5-audit//src/contracts/proxies/Vault721.sol#L63-L63), [link](https://github.com/open-dollar/od-contracts/blob/v1.5.5-audit//src/contracts/proxies/Vault721.sol#L70-L70), [link](https://github.com/open-dollar/od-contracts/blob/v1.5.5-audit//src/contracts/proxies/Vault721.sol#L77-L77), [link](https://github.com/open-dollar/od-contracts/blob/v1.5.5-audit//src/contracts/proxies/Vault721.sol#L85-L85), [link](https://github.com/open-dollar/od-contracts/blob/v1.5.5-audit//src/contracts/proxies/Vault721.sol#L94-L94), [link](https://github.com/open-dollar/od-contracts/blob/v1.5.5-audit//src/contracts/proxies/Vault721.sol#L104-L104), [link](https://github.com/open-dollar/od-contracts/blob/v1.5.5-audit//src/contracts/proxies/Vault721.sol#L119-L119), [link](https://github.com/open-dollar/od-contracts/blob/v1.5.5-audit//src/contracts/proxies/Vault721.sol#L126-L126), [link](https://github.com/open-dollar/od-contracts/blob/v1.5.5-audit//src/contracts/proxies/Vault721.sol#L133-L133), [link](https://github.com/open-dollar/od-contracts/blob/v1.5.5-audit//src/contracts/proxies/Vault721.sol#L147-L147)


```solidity

File: src/contracts/proxies/ODSafeManager.sol

73:   function getSafes(address _usr) external view returns (uint256[] memory _safes) {

78:   function getSafes(address _usr, bytes32 _cType) external view returns (uint256[] memory _safes) {

83:   function getSafesData(address _usr)

98:   function safeData(uint256 _safe) external view returns (SAFEData memory _sData) {

105:   function allowSAFE(uint256 _safe, address _usr, uint256 _ok) external safeAllowed(_safe) {

112:   function allowHandler(address _usr, uint256 _ok) external {

118:   function openSAFE(bytes32 _cType, address _usr) external returns (uint256 _id) {

136:   function transferSAFEOwnership(uint256 _safe, address _dst) external {

155:   function modifySAFECollateralization(

168:   function transferCollateral(uint256 _safe, address _dst, uint256 _wad) external safeAllowed(_safe) {

175:   function transferCollateral(bytes32 _cType, uint256 _safe, address _dst, uint256 _wad) external safeAllowed(_safe) {

182:   function transferInternalCoins(uint256 _safe, address _dst, uint256 _rad) external safeAllowed(_safe) {

189:   function quitSystem(uint256 _safe, address _dst) external safeAllowed(_safe) handlerAllowed(_dst) {

205:   function enterSystem(address _src, uint256 _safe) external handlerAllowed(_src) safeAllowed(_safe) {

217:   function moveSAFE(uint256 _safeSrc, uint256 _safeDst) external safeAllowed(_safeSrc) safeAllowed(_safeDst) {

235:   function addSAFE(uint256 _safe) external {

242:   function removeSAFE(uint256 _safe) external safeAllowed(_safe) {

249:   function protectSAFE(uint256 _safe, address _liquidationEngine, address _saviour) external safeAllowed(_safe) {


```

[link](https://github.com/open-dollar/od-contracts/blob/v1.5.5-audit//src/contracts/proxies/ODSafeManager.sol#L73-L73) , [link](https://github.com/open-dollar/od-contracts/blob/v1.5.5-audit//src/contracts/proxies/ODSafeManager.sol#L78-L78), [link](https://github.com/open-dollar/od-contracts/blob/v1.5.5-audit//src/contracts/proxies/ODSafeManager.sol#L83-L83), [link](https://github.com/open-dollar/od-contracts/blob/v1.5.5-audit//src/contracts/proxies/ODSafeManager.sol#L98-L98), [link](https://github.com/open-dollar/od-contracts/blob/v1.5.5-audit//src/contracts/proxies/ODSafeManager.sol#L105-L105), [link](https://github.com/open-dollar/od-contracts/blob/v1.5.5-audit//src/contracts/proxies/ODSafeManager.sol#L112-L112), [link](https://github.com/open-dollar/od-contracts/blob/v1.5.5-audit//src/contracts/proxies/ODSafeManager.sol#L118-L118), [link](https://github.com/open-dollar/od-contracts/blob/v1.5.5-audit//src/contracts/proxies/ODSafeManager.sol#L136-L136), [link](https://github.com/open-dollar/od-contracts/blob/v1.5.5-audit//src/contracts/proxies/ODSafeManager.sol#L155-L155), [link](https://github.com/open-dollar/od-contracts/blob/v1.5.5-audit//src/contracts/proxies/ODSafeManager.sol#L168-L168), [link](https://github.com/open-dollar/od-contracts/blob/v1.5.5-audit//src/contracts/proxies/ODSafeManager.sol#L175-L175), [link](https://github.com/open-dollar/od-contracts/blob/v1.5.5-audit//src/contracts/proxies/ODSafeManager.sol#L182-L182), [link](https://github.com/open-dollar/od-contracts/blob/v1.5.5-audit//src/contracts/proxies/ODSafeManager.sol#L189-L189), [link](https://github.com/open-dollar/od-contracts/blob/v1.5.5-audit//src/contracts/proxies/ODSafeManager.sol#L205-L205), [link](https://github.com/open-dollar/od-contracts/blob/v1.5.5-audit//src/contracts/proxies/ODSafeManager.sol#L217-L217), [link](https://github.com/open-dollar/od-contracts/blob/v1.5.5-audit//src/contracts/proxies/ODSafeManager.sol#L235-L235), [link](https://github.com/open-dollar/od-contracts/blob/v1.5.5-audit//src/contracts/proxies/ODSafeManager.sol#L242-L242), [link](https://github.com/open-dollar/od-contracts/blob/v1.5.5-audit//src/contracts/proxies/ODSafeManager.sol#L249-L249)


```solidity

File: src/contracts/proxies/actions/BasicActions.sol

226:   function openSAFE(address _manager, bytes32 _cType, address _usr) external delegateCall returns (uint256 _safeId) {

231:   function generateDebt(

242:   function repayDebt(

253:   function lockTokenCollateral(

269:   function freeTokenCollateral(

282:   function repayAllDebt(

313:   function lockTokenCollateralAndGenerateDebt(

328:   function openLockTokenCollateralAndGenerateDebt(

345:   function repayDebtAndFreeTokenCollateral(

374:   function repayAllDebtAndFreeTokenCollateral(


```

[link](https://github.com/open-dollar/od-contracts/blob/v1.5.5-audit//src/contracts/proxies/actions/BasicActions.sol#L226-L226) , [link](https://github.com/open-dollar/od-contracts/blob/v1.5.5-audit//src/contracts/proxies/actions/BasicActions.sol#L231-L231), [link](https://github.com/open-dollar/od-contracts/blob/v1.5.5-audit//src/contracts/proxies/actions/BasicActions.sol#L242-L242), [link](https://github.com/open-dollar/od-contracts/blob/v1.5.5-audit//src/contracts/proxies/actions/BasicActions.sol#L253-L253), [link](https://github.com/open-dollar/od-contracts/blob/v1.5.5-audit//src/contracts/proxies/actions/BasicActions.sol#L269-L269), [link](https://github.com/open-dollar/od-contracts/blob/v1.5.5-audit//src/contracts/proxies/actions/BasicActions.sol#L282-L282), [link](https://github.com/open-dollar/od-contracts/blob/v1.5.5-audit//src/contracts/proxies/actions/BasicActions.sol#L313-L313), [link](https://github.com/open-dollar/od-contracts/blob/v1.5.5-audit//src/contracts/proxies/actions/BasicActions.sol#L328-L328), [link](https://github.com/open-dollar/od-contracts/blob/v1.5.5-audit//src/contracts/proxies/actions/BasicActions.sol#L345-L345), [link](https://github.com/open-dollar/od-contracts/blob/v1.5.5-audit//src/contracts/proxies/actions/BasicActions.sol#L374-L374)


</details>


### [NC&#x2011;58] Contract declarations should have NatSpec `@notice` annotations 



*There are 4 instances of this issue:*



<details>
<summary>see instances</summary>


```solidity
File: src/contracts/factories/CamelotRelayerFactory.sol

13: contract CamelotRelayerFactory is Authorizable, ICamelotRelayerFactory {


```

[link](https://github.com/open-dollar/od-contracts/blob/v1.5.5-audit//src/contracts/factories/CamelotRelayerFactory.sol#L13-L13) 


```solidity

File: src/contracts/gov/ODGovernor.sol

17: contract ODGovernor is


```

[link](https://github.com/open-dollar/od-contracts/blob/v1.5.5-audit//src/contracts/gov/ODGovernor.sol#L17-L17) 


```solidity

File: src/contracts/proxies/ODProxy.sol

7: contract ODProxy {


```

[link](https://github.com/open-dollar/od-contracts/blob/v1.5.5-audit//src/contracts/proxies/ODProxy.sol#L7-L7) 


```solidity

File: src/contracts/proxies/Vault721.sol

13: contract Vault721 is ERC721Enumerable {


```

[link](https://github.com/open-dollar/od-contracts/blob/v1.5.5-audit//src/contracts/proxies/Vault721.sol#L13-L13) 


</details>


### [NC&#x2011;59] Do not use UNDERSCORE in `struct` elements names 
For better maintainability, please consider creating and using a constant for those strings instead of hardcoding 


*There are 1 instances of this issue:*



<details>
<summary>see instances</summary>


```solidity
File: src/contracts/proxies/ODSafeManager.sol

//@audit `_i` 
91:     for (uint256 _i; _i < _safes.length; _i++) {
92:       _safeHandlers[_i] = _safeData[_safes[_i]].safeHandler;
93:       _cTypes[_i] = _safeData[_safes[_i]].collateralType;
94:     }


```

[link](https://github.com/open-dollar/od-contracts/blob/v1.5.5-audit//src/contracts/proxies/ODSafeManager.sol#L91-L94) 


</details>


### [NC&#x2011;60] `event` declarations should have NatSpec descriptions 



*There are 1 instances of this issue:*



<details>
<summary>see instances</summary>


```solidity
File: src/contracts/proxies/Vault721.sol

28:   event CreateProxy(address indexed _user, address _proxy);


```

[link](https://github.com/open-dollar/od-contracts/blob/v1.5.5-audit//src/contracts/proxies/Vault721.sol#L28-L28) 


</details>


### [NC&#x2011;61] `function` names should use lowerCamelCase 
Here is an example of camelCase/lowerCamelCase and other types:
'helloWorld' is a CamelCase
'HelloWorld' is Not CamelCase (PascalCase)
'hello_world' is Not CamelCase (snake_case)
[For more details](https://khalilstemmler.com/blogs/camel-case-snake-case-pascal-case/)


*There are 38 instances of this issue:*



<details>
<summary>see instances</summary>


```solidity
File: src/contracts/AccountingEngine.sol

//@audit `` is not in CamelCase
86:   constructor(

//@audit `_unqueuedUnauctionedDebt` is not in CamelCase
108:   function _unqueuedUnauctionedDebt(uint256 _debtBalance) internal view returns (uint256 __unqueuedUnauctionedDebt) {

//@audit `_settleDebt` is not in CamelCase
143:   function _settleDebt(

//@audit `_onContractDisable` is not in CamelCase
247:   function _onContractDisable() internal override {

//@audit `_modifyParameters` is not in CamelCase
283:   function _modifyParameters(bytes32 _param, bytes memory _data) internal override {

//@audit `_setSurplusAuctionHouse` is not in CamelCase
305:   function _setSurplusAuctionHouse(address _surplusAuctionHouse) internal {

//@audit `_validateParameters` is not in CamelCase
314:   function _validateParameters() internal view override {


```

[link](https://github.com/open-dollar/od-contracts/blob/v1.5.5-audit//src/contracts/AccountingEngine.sol#L86-L86) , [link](https://github.com/open-dollar/od-contracts/blob/v1.5.5-audit//src/contracts/AccountingEngine.sol#L108-L108), [link](https://github.com/open-dollar/od-contracts/blob/v1.5.5-audit//src/contracts/AccountingEngine.sol#L143-L143), [link](https://github.com/open-dollar/od-contracts/blob/v1.5.5-audit//src/contracts/AccountingEngine.sol#L247-L247), [link](https://github.com/open-dollar/od-contracts/blob/v1.5.5-audit//src/contracts/AccountingEngine.sol#L283-L283), [link](https://github.com/open-dollar/od-contracts/blob/v1.5.5-audit//src/contracts/AccountingEngine.sol#L305-L305), [link](https://github.com/open-dollar/od-contracts/blob/v1.5.5-audit//src/contracts/AccountingEngine.sol#L314-L314)


```solidity

File: src/contracts/oracles/CamelotRelayer.sol

//@audit `` is not in CamelCase
40:   constructor(address _baseToken, address _quoteToken, uint32 _quotePeriod) {

//@audit `_parseResult` is not in CamelCase
103:   function _parseResult(uint256 _quoteResult) internal view returns (uint256 _result) {


```

[link](https://github.com/open-dollar/od-contracts/blob/v1.5.5-audit//src/contracts/oracles/CamelotRelayer.sol#L40-L40) , [link](https://github.com/open-dollar/od-contracts/blob/v1.5.5-audit//src/contracts/oracles/CamelotRelayer.sol#L103-L103)


```solidity

File: src/contracts/factories/CamelotRelayerFactory.sol

//@audit `` is not in CamelCase
20:   constructor() Authorizable(msg.sender) {}


```

[link](https://github.com/open-dollar/od-contracts/blob/v1.5.5-audit//src/contracts/factories/CamelotRelayerFactory.sol#L20-L20) 


```solidity

File: src/contracts/factories/CamelotRelayerChild.sol

//@audit `` is not in CamelCase
16:   constructor(


```

[link](https://github.com/open-dollar/od-contracts/blob/v1.5.5-audit//src/contracts/factories/CamelotRelayerChild.sol#L16-L16) 


```solidity

File: src/contracts/oracles/UniV3Relayer.sol

//@audit `` is not in CamelCase
47:   constructor(address _baseToken, address _quoteToken, uint24 _feeTier, uint32 _quotePeriod) {

//@audit `_parseResult` is not in CamelCase
110:   function _parseResult(uint256 _quoteResult) internal view returns (uint256 _result) {


```

[link](https://github.com/open-dollar/od-contracts/blob/v1.5.5-audit//src/contracts/oracles/UniV3Relayer.sol#L47-L47) , [link](https://github.com/open-dollar/od-contracts/blob/v1.5.5-audit//src/contracts/oracles/UniV3Relayer.sol#L110-L110)


```solidity

File: src/contracts/gov/ODGovernor.sol

//@audit `` is not in CamelCase
36:   constructor(

//@audit `_execute` is not in CamelCase
104:   function _execute(

//@audit `_cancel` is not in CamelCase
117:   function _cancel(

//@audit `_executor` is not in CamelCase
129:   function _executor() internal view override(Governor, GovernorTimelockControl) returns (address) {


```

[link](https://github.com/open-dollar/od-contracts/blob/v1.5.5-audit//src/contracts/gov/ODGovernor.sol#L36-L36) , [link](https://github.com/open-dollar/od-contracts/blob/v1.5.5-audit//src/contracts/gov/ODGovernor.sol#L104-L104), [link](https://github.com/open-dollar/od-contracts/blob/v1.5.5-audit//src/contracts/gov/ODGovernor.sol#L117-L117), [link](https://github.com/open-dollar/od-contracts/blob/v1.5.5-audit//src/contracts/gov/ODGovernor.sol#L129-L129)


```solidity

File: src/contracts/proxies/ODProxy.sol

//@audit `` is not in CamelCase
14:   constructor(address _owner) {


```

[link](https://github.com/open-dollar/od-contracts/blob/v1.5.5-audit//src/contracts/proxies/ODProxy.sol#L14-L14) 


```solidity

File: src/contracts/proxies/Vault721.sol

//@audit `` is not in CamelCase
33:   constructor(address _governor) ERC721('OpenDollar Vault', 'ODV') {

//@audit `_isNotProxy` is not in CamelCase
154:   function _isNotProxy(address _user) internal view returns (bool) {

//@audit `_build` is not in CamelCase
162:   function _build(address _user) internal returns (address payable _proxy) {

//@audit `_setSafeManager` is not in CamelCase
172:   function _setSafeManager(address _safeManager) internal nonZero(_safeManager) {

//@audit `_setNftRenderer` is not in CamelCase
179:   function _setNftRenderer(address _nftRenderer) internal nonZero(_nftRenderer) {

//@audit `_afterTokenTransfer` is not in CamelCase
187:   function _afterTokenTransfer(address from, address to, uint256 firstTokenId, uint256 batchSize) internal override {


```

[link](https://github.com/open-dollar/od-contracts/blob/v1.5.5-audit//src/contracts/proxies/Vault721.sol#L33-L33) , [link](https://github.com/open-dollar/od-contracts/blob/v1.5.5-audit//src/contracts/proxies/Vault721.sol#L154-L154), [link](https://github.com/open-dollar/od-contracts/blob/v1.5.5-audit//src/contracts/proxies/Vault721.sol#L162-L162), [link](https://github.com/open-dollar/od-contracts/blob/v1.5.5-audit//src/contracts/proxies/Vault721.sol#L172-L172), [link](https://github.com/open-dollar/od-contracts/blob/v1.5.5-audit//src/contracts/proxies/Vault721.sol#L179-L179), [link](https://github.com/open-dollar/od-contracts/blob/v1.5.5-audit//src/contracts/proxies/Vault721.sol#L187-L187)


```solidity

File: src/contracts/proxies/SAFEHandler.sol

//@audit `` is not in CamelCase
16:   constructor(address _safeEngine) {


```

[link](https://github.com/open-dollar/od-contracts/blob/v1.5.5-audit//src/contracts/proxies/SAFEHandler.sol#L16-L16) 


```solidity

File: src/contracts/proxies/ODSafeManager.sol

//@audit `` is not in CamelCase
64:   constructor(address _safeEngine, address _vault721) {


```

[link](https://github.com/open-dollar/od-contracts/blob/v1.5.5-audit//src/contracts/proxies/ODSafeManager.sol#L64-L64) 


```solidity

File: src/contracts/proxies/actions/BasicActions.sol

//@audit `_getGeneratedDeltaDebt` is not in CamelCase
31:   function _getGeneratedDeltaDebt(

//@audit `_getRepaidDeltaDebt` is not in CamelCase
53:   function _getRepaidDeltaDebt(

//@audit `_getRepaidDebt` is not in CamelCase
72:   function _getRepaidDebt(

//@audit `_generateDebt` is not in CamelCase
94:   function _generateDebt(

//@audit `_repayDebt` is not in CamelCase
121:   function _repayDebt(

//@audit `_openSAFE` is not in CamelCase
142:   function _openSAFE(address _manager, bytes32 _cType, address _usr) internal returns (uint256 _safeId) {

//@audit `_transferCollateral` is not in CamelCase
147:   function _transferCollateral(address _manager, uint256 _safeId, address _dst, uint256 _deltaWad) internal {

//@audit `_transferInternalCoins` is not in CamelCase
153:   function _transferInternalCoins(address _manager, uint256 _safeId, address _dst, uint256 _rad) internal {

//@audit `_modifySAFECollateralization` is not in CamelCase
158:   function _modifySAFECollateralization(

//@audit `_lockTokenCollateralAndGenerateDebt` is not in CamelCase
170:   function _lockTokenCollateralAndGenerateDebt(

//@audit `_collectAndExitCoins` is not in CamelCase
201:   function _collectAndExitCoins(address _manager, address _coinJoin, uint256 _safeId, uint256 _deltaWad) internal {

//@audit `_collectAndExitCollateral` is not in CamelCase
211:   function _collectAndExitCollateral(


```

[link](https://github.com/open-dollar/od-contracts/blob/v1.5.5-audit//src/contracts/proxies/actions/BasicActions.sol#L31-L31) , [link](https://github.com/open-dollar/od-contracts/blob/v1.5.5-audit//src/contracts/proxies/actions/BasicActions.sol#L53-L53), [link](https://github.com/open-dollar/od-contracts/blob/v1.5.5-audit//src/contracts/proxies/actions/BasicActions.sol#L72-L72), [link](https://github.com/open-dollar/od-contracts/blob/v1.5.5-audit//src/contracts/proxies/actions/BasicActions.sol#L94-L94), [link](https://github.com/open-dollar/od-contracts/blob/v1.5.5-audit//src/contracts/proxies/actions/BasicActions.sol#L121-L121), [link](https://github.com/open-dollar/od-contracts/blob/v1.5.5-audit//src/contracts/proxies/actions/BasicActions.sol#L142-L142), [link](https://github.com/open-dollar/od-contracts/blob/v1.5.5-audit//src/contracts/proxies/actions/BasicActions.sol#L147-L147), [link](https://github.com/open-dollar/od-contracts/blob/v1.5.5-audit//src/contracts/proxies/actions/BasicActions.sol#L153-L153), [link](https://github.com/open-dollar/od-contracts/blob/v1.5.5-audit//src/contracts/proxies/actions/BasicActions.sol#L158-L158), [link](https://github.com/open-dollar/od-contracts/blob/v1.5.5-audit//src/contracts/proxies/actions/BasicActions.sol#L170-L170), [link](https://github.com/open-dollar/od-contracts/blob/v1.5.5-audit//src/contracts/proxies/actions/BasicActions.sol#L201-L201), [link](https://github.com/open-dollar/od-contracts/blob/v1.5.5-audit//src/contracts/proxies/actions/BasicActions.sol#L211-L211)


</details>


### [NC&#x2011;62] Expressions for constant values should use `immutable` rather than `constant` 
While it does not save gas for some simple binary expressions because the compiler knows that developers often make this mistake, it's still best to use the right tool for the task at hand. There is a difference between `constant` variables and `immutable` variables, and they should each be used in their appropriate contexts. `constants` should be used for literal values written into the code, and `immutable` variables should be used for expressions, or values calculated in, or passed into the constructor.


*There are 1 instances of this issue:*



<details>
<summary>see instances</summary>


```solidity
File: src/contracts/AccountingEngine.sol

28:   uint256 internal constant ONE_HUNDRED_WAD = 100 * WAD;


```

[link](https://github.com/open-dollar/od-contracts/blob/v1.5.5-audit//src/contracts/AccountingEngine.sol#L28-L28) 


</details>


### [NC&#x2011;63] Contract uses both `require()`/`revert()` as well as custom errors 
Consider using just one method in a single file. The below instances represents the less used technique


*There are 5 instances of this issue:*



<details>
<summary>see instances</summary>


```solidity
File: src/contracts/proxies/Vault721.sol

95:     require(msg.sender == address(safeManager), 'V721: only safeManager');

96:     require(_proxyRegistry[_proxy] != address(0), 'V721: non-native proxy');

111:     require(_safeManager != address(0));

188:     require(to != address(0), 'V721: no burn');


```

[link](https://github.com/open-dollar/od-contracts/blob/v1.5.5-audit//src/contracts/proxies/Vault721.sol#L95-L95) , [link](https://github.com/open-dollar/od-contracts/blob/v1.5.5-audit//src/contracts/proxies/Vault721.sol#L96-L96), [link](https://github.com/open-dollar/od-contracts/blob/v1.5.5-audit//src/contracts/proxies/Vault721.sol#L111-L111), [link](https://github.com/open-dollar/od-contracts/blob/v1.5.5-audit//src/contracts/proxies/Vault721.sol#L188-L188)


```solidity

File: src/contracts/proxies/ODSafeManager.sol

137:     require(msg.sender == address(vault721), 'SafeMngr: Only Vault721');


```

[link](https://github.com/open-dollar/od-contracts/blob/v1.5.5-audit//src/contracts/proxies/ODSafeManager.sol#L137-L137) 


</details>


## Gas Optimizations

### [GAS&#x2011;1] Use assembly to check for `address(0)` 
*Saves 6 gas per instance*


*There are 17 instances of this issue:*



<details>
<summary>see instances</summary>


```solidity
File: src/contracts/AccountingEngine.sol

201:     if (extraSurplusReceiver == address(0)) revert AccEng_NullSurplusReceiver();

225:       if (extraSurplusReceiver == address(0)) revert AccEng_NullSurplusReceiver();

261:     if (address(postSettlementSurplusDrain) == address(0)) revert AccEng_NullSurplusReceiver();

306:     if (address(surplusAuctionHouse) != address(0)) {


```

[link](https://github.com/open-dollar/od-contracts/blob/v1.5.5-audit//src/contracts/AccountingEngine.sol#L201-L201) , [link](https://github.com/open-dollar/od-contracts/blob/v1.5.5-audit//src/contracts/AccountingEngine.sol#L225-L225), [link](https://github.com/open-dollar/od-contracts/blob/v1.5.5-audit//src/contracts/AccountingEngine.sol#L261-L261), [link](https://github.com/open-dollar/od-contracts/blob/v1.5.5-audit//src/contracts/AccountingEngine.sol#L306-L306)


```solidity

File: src/contracts/oracles/CamelotRelayer.sol

43:     if (camelotPair == address(0)) revert CamelotRelayer_InvalidPool();


```

[link](https://github.com/open-dollar/od-contracts/blob/v1.5.5-audit//src/contracts/oracles/CamelotRelayer.sol#L43-L43) 


```solidity

File: src/contracts/oracles/UniV3Relayer.sol

49:     if (uniV3Pool == address(0)) revert UniV3Relayer_InvalidPool();


```

[link](https://github.com/open-dollar/od-contracts/blob/v1.5.5-audit//src/contracts/oracles/UniV3Relayer.sol#L49-L49) 


```solidity

File: src/contracts/proxies/ODProxy.sol

27:     if (_target == address(0)) revert TargetAddressRequired();


```

[link](https://github.com/open-dollar/od-contracts/blob/v1.5.5-audit//src/contracts/proxies/ODProxy.sol#L27-L27) 


```solidity

File: src/contracts/proxies/ODSafeManager.sol

119:     if (_usr == address(0)) revert ZeroAddress();

139:     if (_dst == address(0)) revert ZeroAddress();


```

[link](https://github.com/open-dollar/od-contracts/blob/v1.5.5-audit//src/contracts/proxies/ODSafeManager.sol#L119-L119) , [link](https://github.com/open-dollar/od-contracts/blob/v1.5.5-audit//src/contracts/proxies/ODSafeManager.sol#L139-L139)


```solidity

File: src/contracts/proxies/Vault721.sol

49:     if (_addr == address(0)) revert ZeroAddress();

57:     if (address(safeManager) == address(0)) _setSafeManager(msg.sender);

64:     if (address(nftRenderer) == address(0)) _setNftRenderer(msg.sender);

96:     require(_proxyRegistry[_proxy] != address(0), 'V721: non-native proxy');

111:     require(_safeManager != address(0));

155:     return _userRegistry[_user] == address(0) || ODProxy(_userRegistry[_user]).OWNER() != _user;

188:     require(to != address(0), 'V721: no burn');

189:     if (from != address(0)) {


```

[link](https://github.com/open-dollar/od-contracts/blob/v1.5.5-audit//src/contracts/proxies/Vault721.sol#L49-L49) , [link](https://github.com/open-dollar/od-contracts/blob/v1.5.5-audit//src/contracts/proxies/Vault721.sol#L57-L57), [link](https://github.com/open-dollar/od-contracts/blob/v1.5.5-audit//src/contracts/proxies/Vault721.sol#L64-L64), [link](https://github.com/open-dollar/od-contracts/blob/v1.5.5-audit//src/contracts/proxies/Vault721.sol#L96-L96), [link](https://github.com/open-dollar/od-contracts/blob/v1.5.5-audit//src/contracts/proxies/Vault721.sol#L111-L111), [link](https://github.com/open-dollar/od-contracts/blob/v1.5.5-audit//src/contracts/proxies/Vault721.sol#L155-L155), [link](https://github.com/open-dollar/od-contracts/blob/v1.5.5-audit//src/contracts/proxies/Vault721.sol#L188-L188), [link](https://github.com/open-dollar/od-contracts/blob/v1.5.5-audit//src/contracts/proxies/Vault721.sol#L189-L189)


</details>


### [GAS&#x2011;2] Optimize Address Storage Value Management with `assembly` 



*There are 17 instances of this issue:*



<details>
<summary>see instances</summary>


```solidity
File: src/contracts/AccountingEngine.sol

299:     else if (_param == 'postSettlementSurplusDrain') postSettlementSurplusDrain = _address;

300:     else if (_param == 'extraSurplusReceiver') extraSurplusReceiver = _address;


```

[link](https://github.com/open-dollar/od-contracts/blob/v1.5.5-audit//src/contracts/AccountingEngine.sol#L299-L299) , [link](https://github.com/open-dollar/od-contracts/blob/v1.5.5-audit//src/contracts/AccountingEngine.sol#L300-L300)


```solidity

File: src/contracts/oracles/CamelotRelayer.sol

42:     camelotPair = IAlgebraFactory(_CAMELOT_FACTORY).poolByPair(_baseToken, _quoteToken);

50:       baseToken = _token0;

51:       quoteToken = _token1;

53:       baseToken = _token1;

54:       quoteToken = _token0;


```

[link](https://github.com/open-dollar/od-contracts/blob/v1.5.5-audit//src/contracts/oracles/CamelotRelayer.sol#L42-L42) , [link](https://github.com/open-dollar/od-contracts/blob/v1.5.5-audit//src/contracts/oracles/CamelotRelayer.sol#L50-L50), [link](https://github.com/open-dollar/od-contracts/blob/v1.5.5-audit//src/contracts/oracles/CamelotRelayer.sol#L51-L51), [link](https://github.com/open-dollar/od-contracts/blob/v1.5.5-audit//src/contracts/oracles/CamelotRelayer.sol#L53-L53), [link](https://github.com/open-dollar/od-contracts/blob/v1.5.5-audit//src/contracts/oracles/CamelotRelayer.sol#L54-L54)


```solidity

File: src/contracts/oracles/UniV3Relayer.sol

48:     uniV3Pool = IUniswapV3Factory(_UNI_V3_FACTORY).getPool(_baseToken, _quoteToken, _feeTier);

56:       baseToken = _token0;

57:       quoteToken = _token1;

59:       baseToken = _token1;

60:       quoteToken = _token0;


```

[link](https://github.com/open-dollar/od-contracts/blob/v1.5.5-audit//src/contracts/oracles/UniV3Relayer.sol#L48-L48) , [link](https://github.com/open-dollar/od-contracts/blob/v1.5.5-audit//src/contracts/oracles/UniV3Relayer.sol#L56-L56), [link](https://github.com/open-dollar/od-contracts/blob/v1.5.5-audit//src/contracts/oracles/UniV3Relayer.sol#L57-L57), [link](https://github.com/open-dollar/od-contracts/blob/v1.5.5-audit//src/contracts/oracles/UniV3Relayer.sol#L59-L59), [link](https://github.com/open-dollar/od-contracts/blob/v1.5.5-audit//src/contracts/oracles/UniV3Relayer.sol#L60-L60)


```solidity

File: src/contracts/proxies/ODProxy.sol

15:     OWNER = _owner;


```

[link](https://github.com/open-dollar/od-contracts/blob/v1.5.5-audit//src/contracts/proxies/ODProxy.sol#L15-L15) 


```solidity

File: src/contracts/proxies/ODSafeManager.sol

65:     safeEngine = _safeEngine.assertNonNull();


```

[link](https://github.com/open-dollar/od-contracts/blob/v1.5.5-audit//src/contracts/proxies/ODSafeManager.sol#L65-L65) 


```solidity

File: src/contracts/proxies/Vault721.sol

34:     governor = _governor;

164:     _proxyRegistry[_proxy] = _user;

165:     _userRegistry[_user] = _proxy;


```

[link](https://github.com/open-dollar/od-contracts/blob/v1.5.5-audit//src/contracts/proxies/Vault721.sol#L34-L34) , [link](https://github.com/open-dollar/od-contracts/blob/v1.5.5-audit//src/contracts/proxies/Vault721.sol#L164-L164), [link](https://github.com/open-dollar/od-contracts/blob/v1.5.5-audit//src/contracts/proxies/Vault721.sol#L165-L165)


</details>


### [GAS&#x2011;3] Use assembly to emit events 
We can use assembly to emit events efficiently by utilizing `scratch space` and the `free memory pointer`. This will allow us to potentially avoid memory expansion costs. Note: In order to do this optimization safely, we will need to cache and restore the free memory pointer.


*There are 22 instances of this issue:*



<details>
<summary>see instances</summary>


```solidity
File: src/contracts/AccountingEngine.sol

119:     emit PushDebtToQueue(block.timestamp, _debtBlock);

133:     emit PopDebtFromQueue(_debtBlockTimestamp, _debtBlock);

155:     emit SettleDebt(_rad, _newCoinBalance, _newDebtBalance);

169:     emit CancelDebt(_rad, _coinBalance - _rad, safeEngine.debtBalance(address(this)));

192:     emit AuctionDebt(_id, _params.debtAuctionMintedTokens, _params.debtAuctionBidSize);

220:       emit AuctionSurplus(_id, 0, _params.surplusAmount.wmul(ONE_HUNDRED_WAD - _params.surplusTransferPercentage));

234:       emit TransferSurplus(extraSurplusReceiver, _params.surplusAmount.wmul(_params.surplusTransferPercentage));

276:       emit TransferSurplus(postSettlementSurplusDrain, _coinBalance);


```

[link](https://github.com/open-dollar/od-contracts/blob/v1.5.5-audit//src/contracts/AccountingEngine.sol#L119-L119) , [link](https://github.com/open-dollar/od-contracts/blob/v1.5.5-audit//src/contracts/AccountingEngine.sol#L133-L133), [link](https://github.com/open-dollar/od-contracts/blob/v1.5.5-audit//src/contracts/AccountingEngine.sol#L155-L155), [link](https://github.com/open-dollar/od-contracts/blob/v1.5.5-audit//src/contracts/AccountingEngine.sol#L169-L169), [link](https://github.com/open-dollar/od-contracts/blob/v1.5.5-audit//src/contracts/AccountingEngine.sol#L192-L192), [link](https://github.com/open-dollar/od-contracts/blob/v1.5.5-audit//src/contracts/AccountingEngine.sol#L220-L220), [link](https://github.com/open-dollar/od-contracts/blob/v1.5.5-audit//src/contracts/AccountingEngine.sol#L234-L234), [link](https://github.com/open-dollar/od-contracts/blob/v1.5.5-audit//src/contracts/AccountingEngine.sol#L276-L276)


```solidity

File: src/contracts/factories/CamelotRelayerFactory.sol

30:     emit NewCamelotRelayer(address(_camelotRelayer), _baseToken, _quoteToken, _quotePeriod);


```

[link](https://github.com/open-dollar/od-contracts/blob/v1.5.5-audit//src/contracts/factories/CamelotRelayerFactory.sol#L30-L30) 


```solidity

File: src/contracts/proxies/ODSafeManager.sol

108:     emit AllowSAFE(msg.sender, _safe, _usr, _ok);

114:     emit AllowHandler(msg.sender, _usr, _ok);

131:     emit OpenSAFE(msg.sender, _usr, _safeId);

151:     emit TransferSAFEOwnership(msg.sender, _safe, _dst);

164:     emit ModifySAFECollateralization(msg.sender, _safe, _deltaCollateral, _deltaDebt);

171:     emit TransferCollateral(msg.sender, _safe, _dst, _wad);

178:     emit TransferCollateral(msg.sender, _cType, _safe, _dst, _wad);

185:     emit TransferInternalCoins(msg.sender, _safe, _dst, _rad);

201:     emit QuitSystem(msg.sender, _safe, _dst);

213:     emit EnterSystem(msg.sender, _src, _safe);

231:     emit MoveSAFE(msg.sender, _safeSrc, _safeDst);

252:     emit ProtectSAFE(msg.sender, _safe, _liquidationEngine, _saviour);


```

[link](https://github.com/open-dollar/od-contracts/blob/v1.5.5-audit//src/contracts/proxies/ODSafeManager.sol#L108-L108) , [link](https://github.com/open-dollar/od-contracts/blob/v1.5.5-audit//src/contracts/proxies/ODSafeManager.sol#L114-L114), [link](https://github.com/open-dollar/od-contracts/blob/v1.5.5-audit//src/contracts/proxies/ODSafeManager.sol#L131-L131), [link](https://github.com/open-dollar/od-contracts/blob/v1.5.5-audit//src/contracts/proxies/ODSafeManager.sol#L151-L151), [link](https://github.com/open-dollar/od-contracts/blob/v1.5.5-audit//src/contracts/proxies/ODSafeManager.sol#L164-L164), [link](https://github.com/open-dollar/od-contracts/blob/v1.5.5-audit//src/contracts/proxies/ODSafeManager.sol#L171-L171), [link](https://github.com/open-dollar/od-contracts/blob/v1.5.5-audit//src/contracts/proxies/ODSafeManager.sol#L178-L178), [link](https://github.com/open-dollar/od-contracts/blob/v1.5.5-audit//src/contracts/proxies/ODSafeManager.sol#L185-L185), [link](https://github.com/open-dollar/od-contracts/blob/v1.5.5-audit//src/contracts/proxies/ODSafeManager.sol#L201-L201), [link](https://github.com/open-dollar/od-contracts/blob/v1.5.5-audit//src/contracts/proxies/ODSafeManager.sol#L213-L213), [link](https://github.com/open-dollar/od-contracts/blob/v1.5.5-audit//src/contracts/proxies/ODSafeManager.sol#L231-L231), [link](https://github.com/open-dollar/od-contracts/blob/v1.5.5-audit//src/contracts/proxies/ODSafeManager.sol#L252-L252)


```solidity

File: src/contracts/proxies/Vault721.sol

166:     emit CreateProxy(_user, address(_proxy));


```

[link](https://github.com/open-dollar/od-contracts/blob/v1.5.5-audit//src/contracts/proxies/Vault721.sol#L166-L166) 


</details>


### [GAS&#x2011;4] Use byte32 in place of string 
For strings of 32 char strings and below you can use bytes32 instead as it's more gas efficient


*There are 2 instances of this issue:*



<details>
<summary>see instances</summary>


```solidity
File: src/contracts/oracles/CamelotRelayer.sol

61:     symbol = string(abi.encodePacked(IERC20Metadata(_baseToken).symbol(), ' / ', IERC20Metadata(_quoteToken).symbol()));


```

[link](https://github.com/open-dollar/od-contracts/blob/v1.5.5-audit//src/contracts/oracles/CamelotRelayer.sol#L61-L61) 


```solidity

File: src/contracts/oracles/UniV3Relayer.sol

67:     symbol = string(abi.encodePacked(IERC20Metadata(_baseToken).symbol(), ' / ', IERC20Metadata(_quoteToken).symbol()));


```

[link](https://github.com/open-dollar/od-contracts/blob/v1.5.5-audit//src/contracts/oracles/UniV3Relayer.sol#L67-L67) 


</details>


### [GAS&#x2011;5] Cache array length outside of loop 
If not cached, the solidity compiler will always read the length of the array during each iteration. That is, if it is a storage array, this is an extra sload operation (100 additional extra gas for each iteration except for the first) and if it is a memory array, this is an extra mload operation (3 additional gas for each iteration except for the first).


*There are 1 instances of this issue:*



<details>
<summary>see instances</summary>


```solidity
File: src/contracts/proxies/ODSafeManager.sol

91:     for (uint256 _i; _i < _safes.length; _i++) {


```

[link](https://github.com/open-dollar/od-contracts/blob/v1.5.5-audit//src/contracts/proxies/ODSafeManager.sol#L91-L91) 


</details>


### [GAS&#x2011;6] State variables should be cached in stack variables rather than re-reading them from storage 
The instances below point to the second+ access of a state variable within a function. Caching of a state variable replaces each Gwarmaccess (100 gas) with a much cheaper stack read. Other less obvious fixes/optimizations include having local memory caches of state variable structs, or having local caches of state variable contracts/addresses.

*Saves 100 gas per instance*


*There are 11 instances of this issue:*



<details>
<summary>see instances</summary>


```solidity
File: src/contracts/AccountingEngine.sol

234:       emit TransferSurplus(extraSurplusReceiver, _params.surplusAmount.wmul(_params.surplusTransferPercentage));

276:       emit TransferSurplus(postSettlementSurplusDrain, _coinBalance);

307:       safeEngine.denySAFEModification(address(surplusAuctionHouse));


```

[link](https://github.com/open-dollar/od-contracts/blob/v1.5.5-audit//src/contracts/AccountingEngine.sol#L234-L234) , [link](https://github.com/open-dollar/od-contracts/blob/v1.5.5-audit//src/contracts/AccountingEngine.sol#L276-L276), [link](https://github.com/open-dollar/od-contracts/blob/v1.5.5-audit//src/contracts/AccountingEngine.sol#L307-L307)


```solidity

File: src/contracts/oracles/CamelotRelayer.sol

46:     address _token1 = ICamelotPair(camelotPair).token1();

74:     (int24 _arithmeticMeanTick,) = OracleLibrary.consult(camelotPair, quotePeriod);


```

[link](https://github.com/open-dollar/od-contracts/blob/v1.5.5-audit//src/contracts/oracles/CamelotRelayer.sol#L46-L46) , [link](https://github.com/open-dollar/od-contracts/blob/v1.5.5-audit//src/contracts/oracles/CamelotRelayer.sol#L74-L74)


```solidity

File: src/contracts/oracles/UniV3Relayer.sol

52:     address _token1 = IUniswapV3Pool(uniV3Pool).token1();

80:     (int24 _arithmeticMeanTick,) = OracleLibrary.consult(uniV3Pool, quotePeriod);


```

[link](https://github.com/open-dollar/od-contracts/blob/v1.5.5-audit//src/contracts/oracles/UniV3Relayer.sol#L52-L52) , [link](https://github.com/open-dollar/od-contracts/blob/v1.5.5-audit//src/contracts/oracles/UniV3Relayer.sol#L80-L80)


```solidity

File: src/contracts/proxies/ODSafeManager.sol

127:     _usrSafesPerCollat[_usr][_cType].add(_safeId);

194:     ISAFEEngine(safeEngine).transferSAFECollateralAndDebt(

210:     ISAFEEngine(safeEngine).transferSAFECollateralAndDebt(

224:     ISAFEEngine(safeEngine).transferSAFECollateralAndDebt(


```

[link](https://github.com/open-dollar/od-contracts/blob/v1.5.5-audit//src/contracts/proxies/ODSafeManager.sol#L127-L127) , [link](https://github.com/open-dollar/od-contracts/blob/v1.5.5-audit//src/contracts/proxies/ODSafeManager.sol#L194-L194), [link](https://github.com/open-dollar/od-contracts/blob/v1.5.5-audit//src/contracts/proxies/ODSafeManager.sol#L210-L210), [link](https://github.com/open-dollar/od-contracts/blob/v1.5.5-audit//src/contracts/proxies/ODSafeManager.sol#L224-L224)


</details>


### [GAS&#x2011;7] Use calldata instead of memory for function arguments that do not get mutated 
Mark data types as `calldata` instead of `memory` where possible. This makes it so that the data is not automatically loaded into memory. If the data passed into the function does not need to be changed (like updating values in an array), it can be passed in as `calldata`. The one exception to this is if the argument must later be passed into another function that takes an argument that specifies `memory` storage.


*There are 1 instances of this issue:*



<details>
<summary>see instances</summary>


```solidity
File: src/contracts/proxies/Vault721.sol

//@audit Make `_metaData` as a calldata
119:   function updateContractURI(string memory _metaData) external onlyGovernor {


```

[link](https://github.com/open-dollar/od-contracts/blob/v1.5.5-audit//src/contracts/proxies/Vault721.sol#L119-L119) 


</details>


### [GAS&#x2011;8] Add `unchecked {}` for subtractions where the operands cannot underflow because of a previous `require()` or `if`-statement 
`require(a <= b); x = b - a` => `require(a <= b); unchecked { x = b - a }`


*There are 2 instances of this issue:*



<details>
<summary>see instances</summary>


```solidity
File: src/contracts/AccountingEngine.sol

152:     _newCoinBalance = _coinBalance - _rad;

169:     emit CancelDebt(_rad, _coinBalance - _rad, safeEngine.debtBalance(address(this)));


```

[link](https://github.com/open-dollar/od-contracts/blob/v1.5.5-audit//src/contracts/AccountingEngine.sol#L152-L152) , [link](https://github.com/open-dollar/od-contracts/blob/v1.5.5-audit//src/contracts/AccountingEngine.sol#L169-L169)


</details>


### [GAS&#x2011;9] `x += y` costs more gas than `x = x + y` for state variables 
Not inlining costs 20 to 40 gas because of two extra JUMP instructions and additional stack operations needed for function calls.


*There are 2 instances of this issue:*



<details>
<summary>see instances</summary>


```solidity
File: src/contracts/AccountingEngine.sol

167:     totalOnAuctionDebt -= _rad;

184:     totalOnAuctionDebt += _params.debtAuctionBidSize;


```

[link](https://github.com/open-dollar/od-contracts/blob/v1.5.5-audit//src/contracts/AccountingEngine.sol#L167-L167) , [link](https://github.com/open-dollar/od-contracts/blob/v1.5.5-audit//src/contracts/AccountingEngine.sol#L184-L184)


</details>


### [GAS&#x2011;10] Use custom errors rather than `revert()`/`require()` strings to save gas 
Custom errors are available from solidity version 0.8.4. Custom errors save [**~50 gas**](https://gist.github.com/IllIllI000/ad1bd0d29a0101b25e57c293b4b0c746) each time they're hit by [avoiding having to allocate and store the revert string](https://blog.soliditylang.org/2021/04/21/custom-errors/#errors-in-depth). Not defining the strings also save deployment gas


*There are 4 instances of this issue:*



<details>
<summary>see instances</summary>


```solidity
File: src/contracts/proxies/ODSafeManager.sol

137:     require(msg.sender == address(vault721), 'SafeMngr: Only Vault721');


```

[link](https://github.com/open-dollar/od-contracts/blob/v1.5.5-audit//src/contracts/proxies/ODSafeManager.sol#L137-L137) 


```solidity

File: src/contracts/proxies/Vault721.sol

95:     require(msg.sender == address(safeManager), 'V721: only safeManager');

96:     require(_proxyRegistry[_proxy] != address(0), 'V721: non-native proxy');

188:     require(to != address(0), 'V721: no burn');


```

[link](https://github.com/open-dollar/od-contracts/blob/v1.5.5-audit//src/contracts/proxies/Vault721.sol#L95-L95) , [link](https://github.com/open-dollar/od-contracts/blob/v1.5.5-audit//src/contracts/proxies/Vault721.sol#L96-L96), [link](https://github.com/open-dollar/od-contracts/blob/v1.5.5-audit//src/contracts/proxies/Vault721.sol#L188-L188)


</details>


### [GAS&#x2011;11] Divisions which do not divide by -X cannot overflow or overflow so such operations can be unchecked to save gas 
Make such found divisions are unchecked when ensured it is safe to do so


*There are 3 instances of this issue:*



<details>
<summary>see instances</summary>


```solidity
File: src/contracts/proxies/actions/BasicActions.sol

43:       _deltaDebt = ((_deltaWad * RAY - _coinAmount) / _rate).toInt();

63:     _deltaDebt = (_coinAmount / _rate).toInt();

85:     _deltaWad = _rad / RAY;


```

[link](https://github.com/open-dollar/od-contracts/blob/v1.5.5-audit//src/contracts/proxies/actions/BasicActions.sol#L43-L43) , [link](https://github.com/open-dollar/od-contracts/blob/v1.5.5-audit//src/contracts/proxies/actions/BasicActions.sol#L63-L63), [link](https://github.com/open-dollar/od-contracts/blob/v1.5.5-audit//src/contracts/proxies/actions/BasicActions.sol#L85-L85)


</details>


### [GAS&#x2011;12] Do not calculate constants 
Due to how constant variables are implemented (replacements at compile-time), an expression assigned to a constant variable is recomputed each time that the variable is used, which wastes some gas.


*There are 1 instances of this issue:*



<details>
<summary>see instances</summary>


```solidity
File: src/contracts/AccountingEngine.sol

28:   uint256 internal constant ONE_HUNDRED_WAD = 100 * WAD;


```

[link](https://github.com/open-dollar/od-contracts/blob/v1.5.5-audit//src/contracts/AccountingEngine.sol#L28-L28) 


</details>


### [GAS&#x2011;13] Stack variable cost less while used in emiting event 
Even if the variable is going to be used only one time, caching a state variable and use its cache in an emit would help you reduce the cost by at least ***9 gas***


*There are 10 instances of this issue:*



<details>
<summary>see instances</summary>


```solidity
File: src/contracts/AccountingEngine.sol

// @audit `safeEngine` is a state variable
169:     emit CancelDebt(_rad, _coinBalance - _rad, safeEngine.debtBalance(address(this)));

// @audit `_params` is a state variable
192:     emit AuctionDebt(_id, _params.debtAuctionMintedTokens, _params.debtAuctionBidSize);

// @audit `_params` is a state variable
192:     emit AuctionDebt(_id, _params.debtAuctionMintedTokens, _params.debtAuctionBidSize);

// @audit `_params` is a state variable
220:       emit AuctionSurplus(_id, 0, _params.surplusAmount.wmul(ONE_HUNDRED_WAD - _params.surplusTransferPercentage));

// @audit `_params` is a state variable
220:       emit AuctionSurplus(_id, 0, _params.surplusAmount.wmul(ONE_HUNDRED_WAD - _params.surplusTransferPercentage));

// @audit `extraSurplusReceiver` is a state variable
234:       emit TransferSurplus(extraSurplusReceiver, _params.surplusAmount.wmul(_params.surplusTransferPercentage));

// @audit `_params` is a state variable
234:       emit TransferSurplus(extraSurplusReceiver, _params.surplusAmount.wmul(_params.surplusTransferPercentage));

// @audit `_params` is a state variable
234:       emit TransferSurplus(extraSurplusReceiver, _params.surplusAmount.wmul(_params.surplusTransferPercentage));

// @audit `postSettlementSurplusDrain` is a state variable
276:       emit TransferSurplus(postSettlementSurplusDrain, _coinBalance);


```

[link](https://github.com/open-dollar/od-contracts/blob/v1.5.5-audit//src/contracts/AccountingEngine.sol#L169-L169) , [link](https://github.com/open-dollar/od-contracts/blob/v1.5.5-audit//src/contracts/AccountingEngine.sol#L192-L192), [link](https://github.com/open-dollar/od-contracts/blob/v1.5.5-audit//src/contracts/AccountingEngine.sol#L192-L192), [link](https://github.com/open-dollar/od-contracts/blob/v1.5.5-audit//src/contracts/AccountingEngine.sol#L220-L220), [link](https://github.com/open-dollar/od-contracts/blob/v1.5.5-audit//src/contracts/AccountingEngine.sol#L220-L220), [link](https://github.com/open-dollar/od-contracts/blob/v1.5.5-audit//src/contracts/AccountingEngine.sol#L234-L234), [link](https://github.com/open-dollar/od-contracts/blob/v1.5.5-audit//src/contracts/AccountingEngine.sol#L234-L234), [link](https://github.com/open-dollar/od-contracts/blob/v1.5.5-audit//src/contracts/AccountingEngine.sol#L234-L234), [link](https://github.com/open-dollar/od-contracts/blob/v1.5.5-audit//src/contracts/AccountingEngine.sol#L276-L276)


```solidity

File: src/contracts/proxies/ODSafeManager.sol

// @audit `_safeId` is a state variable
131:     emit OpenSAFE(msg.sender, _usr, _safeId);


```

[link](https://github.com/open-dollar/od-contracts/blob/v1.5.5-audit//src/contracts/proxies/ODSafeManager.sol#L131-L131) 


</details>


### [GAS&#x2011;14] Superfluous event fields 
`block.timestamp` and `block.number` are added to event information by default so adding them manually wastes gas


*There are 1 instances of this issue:*



<details>
<summary>see instances</summary>


```solidity
File: src/contracts/AccountingEngine.sol

119:     emit PushDebtToQueue(block.timestamp, _debtBlock);


```

[link](https://github.com/open-dollar/od-contracts/blob/v1.5.5-audit//src/contracts/AccountingEngine.sol#L119-L119) 


</details>


### [GAS&#x2011;15] Use `ERC721A` instead `ERC721` 
`ERC721A` is an improvement standard for `ERC721` tokens. It was proposed by the Azuki team and used for developing their NFT collection. Compared with `ERC721`, `ERC721A` is a more gas-efficient standard to mint a lot of of NFTs simultaneously. It allows developers to mint multiple NFTs at the same gas price. This has been a great improvement due to Ethereum’s sky-rocketing gas fee. Reference: https://nextrope.com/erc721-vs-erc721a-2/.


*There are 1 instances of this issue:*



<details>
<summary>see instances</summary>


```solidity
File: src/contracts/proxies/Vault721.sol

4: import {ERC721} from '@openzeppelin/token/ERC721/ERC721.sol';


```

[link](https://github.com/open-dollar/od-contracts/blob/v1.5.5-audit//src/contracts/proxies/Vault721.sol#L4-L4) 


</details>


### [GAS&#x2011;16] The result of function calls should be cached rather than re-calling the function 
The instances below point to the second+ call of the function within a single function


*There are 1 instances of this issue:*



<details>
<summary>see instances</summary>


```solidity
File: src/contracts/AccountingEngine.sol

// @audit AccEng_NullSurplusReceiver() is called 2 times in the function `auctionSurplus`
225:       if (extraSurplusReceiver == address(0)) revert AccEng_NullSurplusReceiver();


```

[link](https://github.com/open-dollar/od-contracts/blob/v1.5.5-audit//src/contracts/AccountingEngine.sol#L225-L225) 


</details>


### [GAS&#x2011;17] `internal` functions only called once can be inlined to save gas 
Not inlining costs 20 to 40 gas because of two extra JUMP instructions and additional stack operations needed for function calls.


*There are 4 instances of this issue:*



<details>
<summary>see instances</summary>


```solidity
File: src/contracts/proxies/actions/BasicActions.sol

094:   function _generateDebt(
095:     address _manager,
096:     address _taxCollector,
097:     address _coinJoin,
098:     uint256 _safeId,
099:     uint256 _deltaWad
100:   ) internal {

121:   function _repayDebt(
122:     address _manager,
123:     address _taxCollector,
124:     address _coinJoin,
125:     uint256 _safeId,
126:     uint256 _deltaWad
127:   ) internal {

147:   function _transferCollateral(address _manager, uint256 _safeId, address _dst, uint256 _deltaWad) internal {

153:   function _transferInternalCoins(address _manager, uint256 _safeId, address _dst, uint256 _rad) internal {


```

[link](https://github.com/open-dollar/od-contracts/blob/v1.5.5-audit//src/contracts/proxies/actions/BasicActions.sol#L94-L100) , [link](https://github.com/open-dollar/od-contracts/blob/v1.5.5-audit//src/contracts/proxies/actions/BasicActions.sol#L121-L127), [link](https://github.com/open-dollar/od-contracts/blob/v1.5.5-audit//src/contracts/proxies/actions/BasicActions.sol#L147-L147), [link](https://github.com/open-dollar/od-contracts/blob/v1.5.5-audit//src/contracts/proxies/actions/BasicActions.sol#L153-L153)


</details>


### [GAS&#x2011;18] Multiple `address`/ID mappings can be combined into a single `mapping` of an `address`/ID to a `struct`, where appropriate 
Saves a storage slot for the mapping. Depending on the circumstances and sizes of types, can avoid a Gsset (**20000 gas**) per mapping combined. Reads and subsequent writes can also be cheaper when a function requires both values and they both fit in the same storage slot. Finally, if both fields are accessed in the same function, can save **~42 gas per access** due to [not having to recalculate the key's keccak256 hash](https://gist.github.com/IllIllI000/ec23a57daa30a8f8ca8b9681c8ccefb0) (Gkeccak256 - 30 gas) and that calculation's associated stack operations.


*There are 6 instances of this issue:*



<details>
<summary>see instances</summary>


```solidity
File: src/contracts/proxies/ODSafeManager.sol

32:   mapping(address _safeOwner => EnumerableSet.UintSet) private _usrSafes;

34:   mapping(address _safeOwner => mapping(bytes32 _cType => EnumerableSet.UintSet)) private _usrSafesPerCollat;

39:   mapping(address _owner => mapping(uint256 _safeId => mapping(address _caller => uint256 _ok))) public safeCan;

41:   mapping(address _safeHandler => mapping(address _caller => uint256 _ok)) public handlerCan;


```

[link](https://github.com/open-dollar/od-contracts/blob/v1.5.5-audit//src/contracts/proxies/ODSafeManager.sol#L32-L32) , [link](https://github.com/open-dollar/od-contracts/blob/v1.5.5-audit//src/contracts/proxies/ODSafeManager.sol#L34-L34), [link](https://github.com/open-dollar/od-contracts/blob/v1.5.5-audit//src/contracts/proxies/ODSafeManager.sol#L39-L39), [link](https://github.com/open-dollar/od-contracts/blob/v1.5.5-audit//src/contracts/proxies/ODSafeManager.sol#L41-L41)


```solidity

File: src/contracts/proxies/Vault721.sol

25:   mapping(address proxy => address user) internal _proxyRegistry;

26:   mapping(address user => address proxy) internal _userRegistry;


```

[link](https://github.com/open-dollar/od-contracts/blob/v1.5.5-audit//src/contracts/proxies/Vault721.sol#L25-L25) , [link](https://github.com/open-dollar/od-contracts/blob/v1.5.5-audit//src/contracts/proxies/Vault721.sol#L26-L26)


</details>


### [GAS&#x2011;19] Optimize names to save gas 
`public`/`external` function names and `public` member variable names can be optimized to save gas. See [this](https://gist.github.com/IllIllI000/a5d8b486a8259f9f77891a919febd1a9) link for an example of how it works. Below are the interfaces/abstract contracts that can be optimized so that the most frequently-called functions use the least amount of gas possible during method lookup. Method IDs that have two leading zero bytes can save **128 gas** each during deployment, and renaming functions to have lower method IDs will save **22 gas** per call, [per sorted position shifted](https://medium.com/joyso/solidity-how-does-function-name-affect-gas-consumption-in-smart-contract-47d270d8ac92)


*There are 2 instances of this issue:*



<details>
<summary>see instances</summary>


```solidity
File: src/contracts/proxies/ODProxy.sol

// @audit execute(address,bytes) ==> execute_uaI(address,bytes),0000642d
7: contract ODProxy {


```

[link](https://github.com/open-dollar/od-contracts/blob/v1.5.5-audit//src/contracts/proxies/ODProxy.sol#L7-L7) 


```solidity

File: src/contracts/proxies/Vault721.sol

// @audit initializeManager() ==> initializeManager_965(),0000a899
// @audit initializeRenderer() ==> initializeRenderer_Y7O(),00002af9
// @audit getProxy(address) ==> getProxy_dCG(address),0000a5fd
// @audit build() ==> build_j6W(),0000f8a0
// @audit build(address) ==> build_13(address),000084bb
// @audit mint(address,uint256) ==> mint_Qgo(address,uint256),00001784
// @audit updateNftRenderer(address,address,address,address) ==> updateNftRenderer_0bV(address,address,address,address),0000ebea
// @audit updateContractURI(string) ==> updateContractURI_fxg(string),0000ae47
// @audit setSafeManager(address) ==> setSafeManager_Wdb(address),0000d894
// @audit setNftRenderer(address) ==> setNftRenderer_joa(address),0000d789
// @audit contractURI() ==> contractURI_0hx(),000078ff
13: contract Vault721 is ERC721Enumerable {


```

[link](https://github.com/open-dollar/od-contracts/blob/v1.5.5-audit//src/contracts/proxies/Vault721.sol#L13-L13) 


</details>


### [GAS&#x2011;20] Not using the named return variables anywhere in the function is confusing 
Consider changing the variable to be an unnamed one, since the variable is never assigned, nor is it returned by name. If the optimizer is not turned on, leaving the code as it is will also waste gas for the stack variable.


*There are 8 instances of this issue:*



<details>
<summary>see instances</summary>


```solidity
File: src/contracts/AccountingEngine.sol

// @audit _accEngineParams
61:   function params() external view returns (AccountingEngineParams memory _accEngineParams) {

// @audit __unqueuedUnauctionedDebt
104:   function unqueuedUnauctionedDebt() external view returns (uint256 __unqueuedUnauctionedDebt) {

// @audit __unqueuedUnauctionedDebt
108:   function _unqueuedUnauctionedDebt(uint256 _debtBalance) internal view returns (uint256 __unqueuedUnauctionedDebt) {


```

[link](https://github.com/open-dollar/od-contracts/blob/v1.5.5-audit//src/contracts/AccountingEngine.sol#L61-L61) , [link](https://github.com/open-dollar/od-contracts/blob/v1.5.5-audit//src/contracts/AccountingEngine.sol#L104-L104), [link](https://github.com/open-dollar/od-contracts/blob/v1.5.5-audit//src/contracts/AccountingEngine.sol#L108-L108)


```solidity

File: src/contracts/factories/CamelotRelayerFactory.sol

// @audit _camelotRelayersList
34:   function camelotRelayersList() external view returns (address[] memory _camelotRelayersList) {


```

[link](https://github.com/open-dollar/od-contracts/blob/v1.5.5-audit//src/contracts/factories/CamelotRelayerFactory.sol#L34-L34) 


```solidity

File: src/contracts/oracles/CamelotRelayer.sol

// @audit _result
103:   function _parseResult(uint256 _quoteResult) internal view returns (uint256 _result) {


```

[link](https://github.com/open-dollar/od-contracts/blob/v1.5.5-audit//src/contracts/oracles/CamelotRelayer.sol#L103-L103) 


```solidity

File: src/contracts/oracles/UniV3Relayer.sol

// @audit _result
110:   function _parseResult(uint256 _quoteResult) internal view returns (uint256 _result) {


```

[link](https://github.com/open-dollar/od-contracts/blob/v1.5.5-audit//src/contracts/oracles/UniV3Relayer.sol#L110-L110) 


```solidity

File: src/contracts/proxies/ODSafeManager.sol

// @audit _id
118:   function openSAFE(bytes32 _cType, address _usr) external returns (uint256 _id) {


```

[link](https://github.com/open-dollar/od-contracts/blob/v1.5.5-audit//src/contracts/proxies/ODSafeManager.sol#L118-L118) 


```solidity

File: src/contracts/proxies/actions/BasicActions.sol

// @audit _safeId
226:   function openSAFE(address _manager, bytes32 _cType, address _usr) external delegateCall returns (uint256 _safeId) {


```

[link](https://github.com/open-dollar/od-contracts/blob/v1.5.5-audit//src/contracts/proxies/actions/BasicActions.sol#L226-L226) 


</details>


### [GAS&#x2011;21] Constructors can be marked `payable` 
Payable functions cost less gas to execute, since the compiler does not have to add extra checks to ensure that a payment wasn't provided.A constructor can safely be marked as payable, since only the deployer would be able to pass funds, and the project itself would not pass any funds.


*There are 10 instances of this issue:*



<details>
<summary>see instances</summary>


```solidity
File: src/contracts/AccountingEngine.sol

86:   constructor(
87:     address _safeEngine,
88:     address _surplusAuctionHouse,
89:     address _debtAuctionHouse,
90:     AccountingEngineParams memory _accEngineParams
91:   ) Authorizable(msg.sender) validParams {


```

[link](https://github.com/open-dollar/od-contracts/blob/v1.5.5-audit//src/contracts/AccountingEngine.sol#L86-L91) 


```solidity

File: src/contracts/factories/CamelotRelayerChild.sol

16:   constructor(
17:     address _baseToken,
18:     address _quoteToken,
19:     uint32 _quotePeriod
20:   ) CamelotRelayer(_baseToken, _quoteToken, _quotePeriod) {}


```

[link](https://github.com/open-dollar/od-contracts/blob/v1.5.5-audit//src/contracts/factories/CamelotRelayerChild.sol#L16-L20) 


```solidity

File: src/contracts/factories/CamelotRelayerFactory.sol

20:   constructor() Authorizable(msg.sender) {}
21: 


```

[link](https://github.com/open-dollar/od-contracts/blob/v1.5.5-audit//src/contracts/factories/CamelotRelayerFactory.sol#L20-L21) 


```solidity

File: src/contracts/gov/ODGovernor.sol

36:   constructor(
37:     address _token,
38:     TimelockController _timelock
39:   )
40:     Governor('ODGovernor')
41:     GovernorSettings(1, 15, 0)
42:     GovernorVotes(IVotes(_token))
43:     GovernorVotesQuorumFraction(3)
44:     GovernorTimelockControl(_timelock)
45:   {}


```

[link](https://github.com/open-dollar/od-contracts/blob/v1.5.5-audit//src/contracts/gov/ODGovernor.sol#L36-L45) 


```solidity

File: src/contracts/oracles/CamelotRelayer.sol

40:   constructor(address _baseToken, address _quoteToken, uint32 _quotePeriod) {
41:     // camelotPair = ICamelotFactory(_CAMELOT_FACTORY).getPair(_baseToken, _quoteToken);


```

[link](https://github.com/open-dollar/od-contracts/blob/v1.5.5-audit//src/contracts/oracles/CamelotRelayer.sol#L40-L41) 


```solidity

File: src/contracts/oracles/UniV3Relayer.sol

47:   constructor(address _baseToken, address _quoteToken, uint24 _feeTier, uint32 _quotePeriod) {
48:     uniV3Pool = IUniswapV3Factory(_UNI_V3_FACTORY).getPool(_baseToken, _quoteToken, _feeTier);


```

[link](https://github.com/open-dollar/od-contracts/blob/v1.5.5-audit//src/contracts/oracles/UniV3Relayer.sol#L47-L48) 


```solidity

File: src/contracts/proxies/ODProxy.sol

14:   constructor(address _owner) {
15:     OWNER = _owner;


```

[link](https://github.com/open-dollar/od-contracts/blob/v1.5.5-audit//src/contracts/proxies/ODProxy.sol#L14-L15) 


```solidity

File: src/contracts/proxies/ODSafeManager.sol

64:   constructor(address _safeEngine, address _vault721) {
65:     safeEngine = _safeEngine.assertNonNull();


```

[link](https://github.com/open-dollar/od-contracts/blob/v1.5.5-audit//src/contracts/proxies/ODSafeManager.sol#L64-L65) 


```solidity

File: src/contracts/proxies/SAFEHandler.sol

16:   constructor(address _safeEngine) {
17:     ISAFEEngine(_safeEngine).approveSAFEModification(msg.sender);


```

[link](https://github.com/open-dollar/od-contracts/blob/v1.5.5-audit//src/contracts/proxies/SAFEHandler.sol#L16-L17) 


```solidity

File: src/contracts/proxies/Vault721.sol

33:   constructor(address _governor) ERC721('OpenDollar Vault', 'ODV') {
34:     governor = _governor;


```

[link](https://github.com/open-dollar/od-contracts/blob/v1.5.5-audit//src/contracts/proxies/Vault721.sol#L33-L34) 


</details>


### [GAS&#x2011;22] Functions guaranteed to revert when called by normal users can be marked `payable` 
If a function modifier such as `onlyOwner` is used, the function will revert if a normal user tries to pay the function. Marking the function as `payable` will lower the gas cost for legitimate callers because the compiler will not include checks for whether a payment was provided.The extra opcodes avoided are `CALLVALUE`(2), `DUP1`(3), `ISZERO`(3), `PUSH2`(3), `JUMPI`(10), `PUSH1`(3), `DUP1`(3), `REVERT`(0), `JUMPDEST`(1), `POP`(2), which costs an average of about ** 21 gas per call ** to the function, in addition to the extra deployment cost


*There are 4 instances of this issue:*



<details>
<summary>see instances</summary>


```solidity
File: src/contracts/proxies/Vault721.sol

104:   function updateNftRenderer(
105:     address _nftRenderer,
106:     address _oracleRelayer,
107:     address _taxCollector,
108:     address _collateralJoinFactory
109:   ) external onlyGovernor nonZero(_oracleRelayer) nonZero(_taxCollector) nonZero(_collateralJoinFactory) {

119:   function updateContractURI(string memory _metaData) external onlyGovernor {

126:   function setSafeManager(address _safeManager) external onlyGovernor {

133:   function setNftRenderer(address _nftRenderer) external onlyGovernor {


```

[link](https://github.com/open-dollar/od-contracts/blob/v1.5.5-audit//src/contracts/proxies/Vault721.sol#L104-L109) , [link](https://github.com/open-dollar/od-contracts/blob/v1.5.5-audit//src/contracts/proxies/Vault721.sol#L119-L119), [link](https://github.com/open-dollar/od-contracts/blob/v1.5.5-audit//src/contracts/proxies/Vault721.sol#L126-L126), [link](https://github.com/open-dollar/od-contracts/blob/v1.5.5-audit//src/contracts/proxies/Vault721.sol#L133-L133)


</details>


### [GAS&#x2011;23] Avoid updating storage when the value hasn't changed to save gas 
If the old value is equal to the new value, not re-storing the value will avoid a Gsreset (**2900 gas**), potentially at the expense of a Gcoldsload (**2100 gas**) or a Gwarmaccess (**100 gas**)


*There are 6 instances of this issue:*



<details>
<summary>see instances</summary>


```solidity
File: src/contracts/AccountingEngine.sol

139:   function settleDebt(uint256 _rad) external {


```

[link](https://github.com/open-dollar/od-contracts/blob/v1.5.5-audit//src/contracts/AccountingEngine.sol#L139-L139) 


```solidity

File: src/contracts/proxies/ODSafeManager.sol

155:   function modifySAFECollateralization(


```

[link](https://github.com/open-dollar/od-contracts/blob/v1.5.5-audit//src/contracts/proxies/ODSafeManager.sol#L155-L155) 


```solidity

File: src/contracts/proxies/Vault721.sol

104:   function updateNftRenderer(

119:   function updateContractURI(string memory _metaData) external onlyGovernor {

126:   function setSafeManager(address _safeManager) external onlyGovernor {

133:   function setNftRenderer(address _nftRenderer) external onlyGovernor {


```

[link](https://github.com/open-dollar/od-contracts/blob/v1.5.5-audit//src/contracts/proxies/Vault721.sol#L104-L104) , [link](https://github.com/open-dollar/od-contracts/blob/v1.5.5-audit//src/contracts/proxies/Vault721.sol#L119-L119), [link](https://github.com/open-dollar/od-contracts/blob/v1.5.5-audit//src/contracts/proxies/Vault721.sol#L126-L126), [link](https://github.com/open-dollar/od-contracts/blob/v1.5.5-audit//src/contracts/proxies/Vault721.sol#L133-L133)


</details>


### [GAS&#x2011;24] Usage of `uints`/`ints` smaller than 32 bytes (256 bits) incurs overhead 
> When using elements that are smaller than 32 bytes, your contract's gas usage may be higher. This is because the EVM operates on 32 bytes at a time. Therefore, if the element is smaller than that, the EVM must use more operations in order to reduce the size of the element from 32 bytes to the desired size.
https://docs.soliditylang.org/en/v0.8.11/internals/layout_in_storage.html
Each operation involving a `uint8` costs an extra [** 22 - 28 gas **](https://gist.github.com/IllIllI000/9388d20c70f9a4632eb3ca7836f54977) (depending on whether the other operand is also a variable of type `uint8`) as compared to ones involving `uint256`, due to the compiler having to clear the higher bits of the memory word before operating on the `uint8`, as well as the associated stack operations of doing so. Use a larger size then downcast where needed


*There are 9 instances of this issue:*



<details>
<summary>see instances</summary>


```solidity
File: src/contracts/factories/CamelotRelayerChild.sol

//@audit `_quotePeriod` is `uint32`
19:     uint32 _quotePeriod


```

[link](https://github.com/open-dollar/od-contracts/blob/v1.5.5-audit//src/contracts/factories/CamelotRelayerChild.sol#L19-L19) 


```solidity

File: src/contracts/factories/CamelotRelayerFactory.sol

//@audit `_quotePeriod` is `uint32`
26:     uint32 _quotePeriod


```

[link](https://github.com/open-dollar/od-contracts/blob/v1.5.5-audit//src/contracts/factories/CamelotRelayerFactory.sol#L26-L26) 


```solidity

File: src/contracts/oracles/CamelotRelayer.sol

//@audit `_quotePeriod` is `uint32`
40:   constructor(address _baseToken, address _quoteToken, uint32 _quotePeriod) {

//@audit `_arithmeticMeanTick` is `int24`
74:     (int24 _arithmeticMeanTick,) = OracleLibrary.consult(camelotPair, quotePeriod);

//@audit `_arithmeticMeanTick` is `int24`
93:     (int24 _arithmeticMeanTick,) = OracleLibrary.consult(camelotPair, quotePeriod);


```

[link](https://github.com/open-dollar/od-contracts/blob/v1.5.5-audit//src/contracts/oracles/CamelotRelayer.sol#L40-L40) , [link](https://github.com/open-dollar/od-contracts/blob/v1.5.5-audit//src/contracts/oracles/CamelotRelayer.sol#L74-L74), [link](https://github.com/open-dollar/od-contracts/blob/v1.5.5-audit//src/contracts/oracles/CamelotRelayer.sol#L93-L93)


```solidity

File: src/contracts/oracles/UniV3Relayer.sol

//@audit `_feeTier` is `uint24`
47:   constructor(address _baseToken, address _quoteToken, uint24 _feeTier, uint32 _quotePeriod) {

//@audit `_quotePeriod` is `uint32`
47:   constructor(address _baseToken, address _quoteToken, uint24 _feeTier, uint32 _quotePeriod) {

//@audit `_arithmeticMeanTick` is `int24`
80:     (int24 _arithmeticMeanTick,) = OracleLibrary.consult(uniV3Pool, quotePeriod);

//@audit `_arithmeticMeanTick` is `int24`
99:     (int24 _arithmeticMeanTick,) = OracleLibrary.consult(uniV3Pool, quotePeriod);


```

[link](https://github.com/open-dollar/od-contracts/blob/v1.5.5-audit//src/contracts/oracles/UniV3Relayer.sol#L47-L47) , [link](https://github.com/open-dollar/od-contracts/blob/v1.5.5-audit//src/contracts/oracles/UniV3Relayer.sol#L47-L47), [link](https://github.com/open-dollar/od-contracts/blob/v1.5.5-audit//src/contracts/oracles/UniV3Relayer.sol#L80-L80), [link](https://github.com/open-dollar/od-contracts/blob/v1.5.5-audit//src/contracts/oracles/UniV3Relayer.sol#L99-L99)


</details>


### [GAS&#x2011;25] The use of a logical AND in place of double if is slightly less gas efficient in instances where there isn't a corresponding else statement for the given if statement 
Using a double if statement instead of logical AND (&&) can provide similar short-circuiting behavior whereas double if is slightly more efficient.


*There are 2 instances of this issue:*



<details>
<summary>see instances</summary>


```solidity
File: src/contracts/proxies/ODSafeManager.sol

51:     if (msg.sender != _owner && safeCan[_owner][_safe][msg.sender] == 0) revert SafeNotAllowed();
52:     _;

60:     if (msg.sender != _handler && handlerCan[_handler][msg.sender] == 0) revert HandlerNotAllowed();
61:     _;


```

[link](https://github.com/open-dollar/od-contracts/blob/v1.5.5-audit//src/contracts/proxies/ODSafeManager.sol#L51-L52) , [link](https://github.com/open-dollar/od-contracts/blob/v1.5.5-audit//src/contracts/proxies/ODSafeManager.sol#L60-L61)


</details>


### [GAS&#x2011;26] State variables only set in the constructor should be declared `immutable` 
Avoids a Gsset(** 20000 gas**) in the constructor, and replaces the first access in each transaction(Gcoldsload - ** 2100 gas **) and each access thereafter(Gwarmacces - ** 100 gas **) with a`PUSH32`(** 3 gas **).

While`string`s are not value types, and therefore cannot be`immutable` / `constant` if not hard - coded outside of the constructor, the same behavior can be achieved by making the current contract `abstract` with `virtual` functions for the`string` accessors, and having a child contract override the functions with the hard - coded implementation - specific values.


*There are 11 instances of this issue:*



<details>
<summary>see instances</summary>


```solidity
File: src/contracts/AccountingEngine.sol

92:     safeEngine = ISAFEEngine(_safeEngine.assertNonNull());


```

[link](https://github.com/open-dollar/od-contracts/blob/v1.5.5-audit//src/contracts/AccountingEngine.sol#L92-L92) 


```solidity

File: src/contracts/oracles/CamelotRelayer.sol

42:     camelotPair = IAlgebraFactory(_CAMELOT_FACTORY).poolByPair(_baseToken, _quoteToken);

53:       baseToken = _token1;

54:       quoteToken = _token0;

57:     baseAmount = uint128(10 ** IERC20Metadata(_baseToken).decimals());

58:     multiplier = 18 - IERC20Metadata(_quoteToken).decimals();

59:     quotePeriod = _quotePeriod;

61:     symbol = string(abi.encodePacked(IERC20Metadata(_baseToken).symbol(), ' / ', IERC20Metadata(_quoteToken).symbol()));


```

[link](https://github.com/open-dollar/od-contracts/blob/v1.5.5-audit//src/contracts/oracles/CamelotRelayer.sol#L42-L42) , [link](https://github.com/open-dollar/od-contracts/blob/v1.5.5-audit//src/contracts/oracles/CamelotRelayer.sol#L53-L53), [link](https://github.com/open-dollar/od-contracts/blob/v1.5.5-audit//src/contracts/oracles/CamelotRelayer.sol#L54-L54), [link](https://github.com/open-dollar/od-contracts/blob/v1.5.5-audit//src/contracts/oracles/CamelotRelayer.sol#L57-L57), [link](https://github.com/open-dollar/od-contracts/blob/v1.5.5-audit//src/contracts/oracles/CamelotRelayer.sol#L58-L58), [link](https://github.com/open-dollar/od-contracts/blob/v1.5.5-audit//src/contracts/oracles/CamelotRelayer.sol#L59-L59), [link](https://github.com/open-dollar/od-contracts/blob/v1.5.5-audit//src/contracts/oracles/CamelotRelayer.sol#L61-L61)


```solidity

File: src/contracts/oracles/UniV3Relayer.sol

48:     uniV3Pool = IUniswapV3Factory(_UNI_V3_FACTORY).getPool(_baseToken, _quoteToken, _feeTier);


```

[link](https://github.com/open-dollar/od-contracts/blob/v1.5.5-audit//src/contracts/oracles/UniV3Relayer.sol#L48-L48) 


```solidity

File: src/contracts/proxies/ODSafeManager.sol

66:     vault721 = IVault721(_vault721);


```

[link](https://github.com/open-dollar/od-contracts/blob/v1.5.5-audit//src/contracts/proxies/ODSafeManager.sol#L66-L66) 


```solidity

File: src/contracts/proxies/Vault721.sol

34:     governor = _governor;


```

[link](https://github.com/open-dollar/od-contracts/blob/v1.5.5-audit//src/contracts/proxies/Vault721.sol#L34-L34) 


</details>


### [GAS&#x2011;27] Using `storage` instead of `memory` for structs/arrays saves gas 
When fetching data from a storage location, assigning the data to a `memory` variable causes all fields of the struct/array to be read from storage, which incurs a Gcoldsload (**2100 gas**) for *each* field of the struct/array. If the fields are read from the new memory variable, they incur an additional `MLOAD` rather than a cheap stack read. Instead of declearing the variable with the `memory` keyword, declaring the variable with the `storage` keyword and caching any fields that need to be re-read in stack variables, will be much cheaper, only incuring the Gcoldsload for the fields actually read. The only time it makes sense to read the whole struct/array into a `memory` variable, is if the full struct/array is being returned by the function, is being passed to a function that requires `memory`, or if the array/struct is being read from another `memory` array/struct


*There are 3 instances of this issue:*



<details>
<summary>see instances</summary>


```solidity
File: src/contracts/proxies/ODSafeManager.sol

191:     ISAFEEngine.SAFE memory _safeInfo = ISAFEEngine(safeEngine).safes(_sData.collateralType, _sData.safeHandler);

207:     ISAFEEngine.SAFE memory _safeInfo = ISAFEEngine(safeEngine).safes(_sData.collateralType, _sData.safeHandler);

221:     ISAFEEngine.SAFE memory _safeInfo = ISAFEEngine(safeEngine).safes(_srcData.collateralType, _srcData.safeHandler);


```

[link](https://github.com/open-dollar/od-contracts/blob/v1.5.5-audit//src/contracts/proxies/ODSafeManager.sol#L191-L191) , [link](https://github.com/open-dollar/od-contracts/blob/v1.5.5-audit//src/contracts/proxies/ODSafeManager.sol#L207-L207), [link](https://github.com/open-dollar/od-contracts/blob/v1.5.5-audit//src/contracts/proxies/ODSafeManager.sol#L221-L221)


</details>


### [GAS&#x2011;28] `>=`/`<=` costs less gas than `>`/`<` 
The compiler uses opcodes `GT` and `ISZERO` for solidity code that uses `>`, but only requires `LT` for `>=`, [which saves **3 gas**](https://gist.github.com/IllIllI000/3dc79d25acccfa16dee4e83ffdc6ffde)


*There are 19 instances of this issue:*



<details>
<summary>see instances</summary>


```solidity
File: src/contracts/AccountingEngine.sol

124:     if (block.timestamp < _debtBlockTimestamp + _params.popDebtDelay) revert AccEng_PopDebtCooldown();

148:     if (_rad > _coinBalance) revert AccEng_InsufficientSurplus();

149:     if (_rad > _unqueuedUnauctionedDebt(_debtBalance)) revert AccEng_InsufficientDebt();

160:     if (_rad > totalOnAuctionDebt) revert AccEng_InsufficientDebt();

164:     if (_rad > _coinBalance) revert AccEng_InsufficientSurplus();

181:     if (_params.debtAuctionBidSize > _unqueuedUnauctionedDebt(_debtBalance)) revert AccEng_InsufficientDebt();

199:     if(_params.surplusTransferPercentage > WAD) revert AccEng_surplusTransferPercentOverLimit();

202:     if (block.timestamp < lastSurplusTime + _params.surplusDelay) revert AccEng_SurplusCooldown();

208:     if (_coinBalance < _debtBalance + _params.surplusAmount + _params.surplusBuffer) {

213:     if (_params.surplusTransferPercentage < ONE_HUNDRED_WAD) {

224:     if (_params.surplusTransferPercentage > 0) {

262:     if (block.timestamp < disableTimestamp + _params.disableCooldown) revert AccEng_PostSettlementCooldown();

269:     if (_coinBalance > 0) {


```

[link](https://github.com/open-dollar/od-contracts/blob/v1.5.5-audit//src/contracts/AccountingEngine.sol#L124-L124) , [link](https://github.com/open-dollar/od-contracts/blob/v1.5.5-audit//src/contracts/AccountingEngine.sol#L148-L148), [link](https://github.com/open-dollar/od-contracts/blob/v1.5.5-audit//src/contracts/AccountingEngine.sol#L149-L149), [link](https://github.com/open-dollar/od-contracts/blob/v1.5.5-audit//src/contracts/AccountingEngine.sol#L160-L160), [link](https://github.com/open-dollar/od-contracts/blob/v1.5.5-audit//src/contracts/AccountingEngine.sol#L164-L164), [link](https://github.com/open-dollar/od-contracts/blob/v1.5.5-audit//src/contracts/AccountingEngine.sol#L181-L181), [link](https://github.com/open-dollar/od-contracts/blob/v1.5.5-audit//src/contracts/AccountingEngine.sol#L199-L199), [link](https://github.com/open-dollar/od-contracts/blob/v1.5.5-audit//src/contracts/AccountingEngine.sol#L202-L202), [link](https://github.com/open-dollar/od-contracts/blob/v1.5.5-audit//src/contracts/AccountingEngine.sol#L208-L208), [link](https://github.com/open-dollar/od-contracts/blob/v1.5.5-audit//src/contracts/AccountingEngine.sol#L213-L213), [link](https://github.com/open-dollar/od-contracts/blob/v1.5.5-audit//src/contracts/AccountingEngine.sol#L224-L224), [link](https://github.com/open-dollar/od-contracts/blob/v1.5.5-audit//src/contracts/AccountingEngine.sol#L262-L262), [link](https://github.com/open-dollar/od-contracts/blob/v1.5.5-audit//src/contracts/AccountingEngine.sol#L269-L269)


```solidity

File: src/contracts/oracles/CamelotRelayer.sol

70:     if (OracleLibrary.getOldestObservationSecondsAgo(camelotPair) < quotePeriod) {


```

[link](https://github.com/open-dollar/od-contracts/blob/v1.5.5-audit//src/contracts/oracles/CamelotRelayer.sol#L70-L70) 


```solidity

File: src/contracts/oracles/UniV3Relayer.sol

76:     if (OracleLibrary.getOldestObservationSecondsAgo(uniV3Pool) < quotePeriod) {


```

[link](https://github.com/open-dollar/od-contracts/blob/v1.5.5-audit//src/contracts/oracles/UniV3Relayer.sol#L76-L76) 


```solidity

File: src/contracts/proxies/ODSafeManager.sol

91:     for (uint256 _i; _i < _safes.length; _i++) {


```

[link](https://github.com/open-dollar/od-contracts/blob/v1.5.5-audit//src/contracts/proxies/ODSafeManager.sol#L91-L91) 


```solidity

File: src/contracts/proxies/actions/BasicActions.sol

41:     if (_coinAmount < _deltaWad * RAY) {

45:       _deltaDebt = uint256(_deltaDebt) * _rate < _deltaWad * RAY ? _deltaDebt + 1 : _deltaDebt;

87:     _deltaWad = _deltaWad * RAY < _rad ? _deltaWad + 1 : _deltaWad;


```

[link](https://github.com/open-dollar/od-contracts/blob/v1.5.5-audit//src/contracts/proxies/actions/BasicActions.sol#L41-L41) , [link](https://github.com/open-dollar/od-contracts/blob/v1.5.5-audit//src/contracts/proxies/actions/BasicActions.sol#L45-L45), [link](https://github.com/open-dollar/od-contracts/blob/v1.5.5-audit//src/contracts/proxies/actions/BasicActions.sol#L87-L87)


</details>


### [GAS&#x2011;29] Use assembly to validate `msg.sender` 
We can use assembly to efficiently validate msg.sender with the least amount of opcodes necessary. For more details check the following report [Here](https://code4rena.com/reports/2023-05-juicebox#g-06-use-assembly-to-validate-msgsender)


*There are 12 instances of this issue:*



<details>
<summary>see instances</summary>


```solidity
File: src/contracts/proxies/ODProxy.sol

22:     if (msg.sender != OWNER) revert OnlyOwner();


```

[link](https://github.com/open-dollar/od-contracts/blob/v1.5.5-audit//src/contracts/proxies/ODProxy.sol#L22-L22) 


```solidity

File: src/contracts/proxies/ODSafeManager.sol

51:     if (msg.sender != _owner && safeCan[_owner][_safe][msg.sender] == 0) revert SafeNotAllowed();

51:     if (msg.sender != _owner && safeCan[_owner][_safe][msg.sender] == 0) revert SafeNotAllowed();

51:     if (msg.sender != _owner && safeCan[_owner][_safe][msg.sender] == 0) revert SafeNotAllowed();

51:     if (msg.sender != _owner && safeCan[_owner][_safe][msg.sender] == 0) revert SafeNotAllowed();

60:     if (msg.sender != _handler && handlerCan[_handler][msg.sender] == 0) revert HandlerNotAllowed();

60:     if (msg.sender != _handler && handlerCan[_handler][msg.sender] == 0) revert HandlerNotAllowed();

60:     if (msg.sender != _handler && handlerCan[_handler][msg.sender] == 0) revert HandlerNotAllowed();

60:     if (msg.sender != _handler && handlerCan[_handler][msg.sender] == 0) revert HandlerNotAllowed();

137:     require(msg.sender == address(vault721), 'SafeMngr: Only Vault721');


```

[link](https://github.com/open-dollar/od-contracts/blob/v1.5.5-audit//src/contracts/proxies/ODSafeManager.sol#L51-L51) , [link](https://github.com/open-dollar/od-contracts/blob/v1.5.5-audit//src/contracts/proxies/ODSafeManager.sol#L51-L51), [link](https://github.com/open-dollar/od-contracts/blob/v1.5.5-audit//src/contracts/proxies/ODSafeManager.sol#L51-L51), [link](https://github.com/open-dollar/od-contracts/blob/v1.5.5-audit//src/contracts/proxies/ODSafeManager.sol#L51-L51), [link](https://github.com/open-dollar/od-contracts/blob/v1.5.5-audit//src/contracts/proxies/ODSafeManager.sol#L60-L60), [link](https://github.com/open-dollar/od-contracts/blob/v1.5.5-audit//src/contracts/proxies/ODSafeManager.sol#L60-L60), [link](https://github.com/open-dollar/od-contracts/blob/v1.5.5-audit//src/contracts/proxies/ODSafeManager.sol#L60-L60), [link](https://github.com/open-dollar/od-contracts/blob/v1.5.5-audit//src/contracts/proxies/ODSafeManager.sol#L60-L60), [link](https://github.com/open-dollar/od-contracts/blob/v1.5.5-audit//src/contracts/proxies/ODSafeManager.sol#L137-L137)


```solidity

File: src/contracts/proxies/Vault721.sol

41:     if (msg.sender != governor) revert NotGovernor();

95:     require(msg.sender == address(safeManager), 'V721: only safeManager');


```

[link](https://github.com/open-dollar/od-contracts/blob/v1.5.5-audit//src/contracts/proxies/Vault721.sol#L41-L41) , [link](https://github.com/open-dollar/od-contracts/blob/v1.5.5-audit//src/contracts/proxies/Vault721.sol#L95-L95)


</details>


### [GAS&#x2011;30] `++i` costs less gas than `i++`, especially when it's used in `for`-loops (`--i`/`i--` too) 
*Saves 5 gas per loop*


*There are 1 instances of this issue:*



<details>
<summary>see instances</summary>


```solidity
File: src/contracts/proxies/ODSafeManager.sol

91:     for (uint256 _i; _i < _safes.length; _i++) {


```

[link](https://github.com/open-dollar/od-contracts/blob/v1.5.5-audit//src/contracts/proxies/ODSafeManager.sol#L91-L91) 


</details>


### [GAS&#x2011;31] Unnecessary casting as variable is already of the same type 



*There are 1 instances of this issue:*



<details>
<summary>see instances</summary>


```solidity
File: src/contracts/AccountingEngine.sol

//@audit `postSettlementSurplusDrain` is getting converted from `address` to `address`
261:     if (address(postSettlementSurplusDrain) == address(0)) revert AccEng_NullSurplusReceiver();


```

[link](https://github.com/open-dollar/od-contracts/blob/v1.5.5-audit//src/contracts/AccountingEngine.sol#L261-L261) 


</details>


### [GAS&#x2011;32] Stat variables can be packed into fewer storage slots by truncating timestamp bytes 
By using a `uint32` rather than a larger type for variables that track timestamps, one can save gas by using fewer storage slots per struct, at the expense of the protocol breaking after the year 2106 (when `uint32` wraps). If this is an acceptable tradeoff, each slot saved can avoid an extra Gsset (**20000 gas**) for the first setting of the stat variable. Subsequent reads as well as writes have smaller gas savings


*There are 1 instances of this issue:*



<details>
<summary>see instances</summary>


```solidity
File: src/contracts/AccountingEngine.sol

//@audit the following variables could be packed: 
  uint256 public lastSurplusTime;
   uint256 public disableTimestamp;
 
23: contract AccountingEngine is Authorizable, Modifiable, Disableable, IAccountingEngine {


```

[link](https://github.com/open-dollar/od-contracts/blob/v1.5.5-audit//src/contracts/AccountingEngine.sol#L23-L23) 


</details>


### [GAS&#x2011;33] State variables can be packed into fewer storage slots 
If variables occupying the same slot are both written the same function or by the constructor, avoids a separate Gsset (**20000 gas**). Reads of the variables can also be cheaper


*There are 2 instances of this issue:*



<details>
<summary>see instances</summary>


```solidity
File: src/contracts/oracles/CamelotRelayer.sol

// @audit from 8 to 7 you need to change the structure elements order to: , string, uint256, address, address, address, address, uint128, uint32
018: contract CamelotRelayer is IBaseOracle, ICamelotRelayer {
019:   // --- Registry ---
020:   address internal constant _CAMELOT_FACTORY = GOERLI_CAMELOT_V3_FACTORY;
021: 
022:   /// @inheritdoc ICamelotRelayer
023:   address public camelotPair;
024:   /// @inheritdoc ICamelotRelayer
025:   address public baseToken;
026:   /// @inheritdoc ICamelotRelayer
027:   address public quoteToken;
028: 
029:   // --- Data ---
030:   /// @inheritdoc IBaseOracle
031:   string public symbol;
032: 
033:   /// @inheritdoc ICamelotRelayer
034:   uint128 public baseAmount;
035:   /// @inheritdoc ICamelotRelayer
036:   uint256 public multiplier;
037:   /// @inheritdoc ICamelotRelayer
038:   uint32 public quotePeriod;
039: 
040:   constructor(address _baseToken, address _quoteToken, uint32 _quotePeriod) {
041:     // camelotPair = ICamelotFactory(_CAMELOT_FACTORY).getPair(_baseToken, _quoteToken);
042:     camelotPair = IAlgebraFactory(_CAMELOT_FACTORY).poolByPair(_baseToken, _quoteToken);
043:     if (camelotPair == address(0)) revert CamelotRelayer_InvalidPool();
044: 
045:     address _token0 = ICamelotPair(camelotPair).token0();
046:     address _token1 = ICamelotPair(camelotPair).token1();
047: 
048:     // The factory validates that both token0 and token1 are desired baseToken and quoteTokens
049:     if (_token0 == _baseToken) {
050:       baseToken = _token0;
051:       quoteToken = _token1;
052:     } else {
053:       baseToken = _token1;
054:       quoteToken = _token0;
055:     }
056: 
057:     baseAmount = uint128(10 ** IERC20Metadata(_baseToken).decimals());
058:     multiplier = 18 - IERC20Metadata(_quoteToken).decimals();
059:     quotePeriod = _quotePeriod;
060: 
061:     symbol = string(abi.encodePacked(IERC20Metadata(_baseToken).symbol(), ' / ', IERC20Metadata(_quoteToken).symbol()));
062:   }
063: 
064:   /**
065:    * @dev    Method will return invalid if the pool doesn't have enough history
066:    * @inheritdoc IBaseOracle
067:    */
068:   function getResultWithValidity() external view returns (uint256 _result, bool _validity) {
069:     // If the pool doesn't have enough history return false
070:     if (OracleLibrary.getOldestObservationSecondsAgo(camelotPair) < quotePeriod) {
071:       return (0, false);
072:     }
073:     // Consult the query with a TWAP period of quotePeriod
074:     (int24 _arithmeticMeanTick,) = OracleLibrary.consult(camelotPair, quotePeriod);
075:     // Calculate the quote amount
076:     uint256 _quoteAmount = OracleLibrary.getQuoteAtTick({
077:       tick: _arithmeticMeanTick,
078:       baseAmount: baseAmount,
079:       baseToken: baseToken,
080:       quoteToken: quoteToken
081:     });
082:     // Process the quote result to 18 decimal quote
083:     _result = _parseResult(_quoteAmount);
084:     _validity = true;
085:   }
086: 
087:   /**
088:    * @dev    This method may revert with 'OLD!' if the pool doesn't have enough cardinality or initialized history
089:    * @inheritdoc IBaseOracle
090:    */
091:   function read() external view returns (uint256 _result) {
092:     // This call may revert with 'OLD!' if the pool doesn't have enough cardinality or initialized history
093:     (int24 _arithmeticMeanTick,) = OracleLibrary.consult(camelotPair, quotePeriod);
094:     uint256 _quoteAmount = OracleLibrary.getQuoteAtTick({
095:       tick: _arithmeticMeanTick,
096:       baseAmount: baseAmount,
097:       baseToken: baseToken,
098:       quoteToken: quoteToken
099:     });
100:     _result = _parseResult(_quoteAmount);
101:   }
102: 
103:   function _parseResult(uint256 _quoteResult) internal view returns (uint256 _result) {
104:     return _quoteResult * 10 ** multiplier;
105:   }
106: }


```

[link](https://github.com/open-dollar/od-contracts/blob/v1.5.5-audit//src/contracts/oracles/CamelotRelayer.sol#L18-L106) 


```solidity

File: src/contracts/oracles/UniV3Relayer.sol

// @audit from 8 to 7 you need to change the structure elements order to: , string, uint256, address, address, address, address, uint128, uint32
016: contract UniV3Relayer is IBaseOracle, IUniV3Relayer {
017:   // --- Registry ---
018:   address internal constant _UNI_V3_FACTORY = GOERLI_UNISWAP_V3_FACTORY;
019: 
020:   /// @inheritdoc IUniV3Relayer
021:   address public uniV3Pool;
022:   /// @inheritdoc IUniV3Relayer
023:   address public baseToken;
024:   /// @inheritdoc IUniV3Relayer
025:   address public quoteToken;
026: 
027:   // --- Data ---
028: 
029:   /// @inheritdoc IBaseOracle
030:   string public symbol;
031: 
032:   /// @inheritdoc IUniV3Relayer
033:   uint128 public baseAmount;
034:   /// @inheritdoc IUniV3Relayer
035:   uint256 public multiplier;
036:   /// @inheritdoc IUniV3Relayer
037:   uint32 public quotePeriod;
038: 
039:   // --- Init ---
040: 
041:   /**
042:    * @param  _baseToken Address of the base token used to consult the quote
043:    * @param  _quoteToken Address of the token used as a quote reference
044:    * @param  _feeTier Fee tier of the pool used to consult the quote
045:    * @param  _quotePeriod Length in seconds of the TWAP used to consult the pool
046:    */
047:   constructor(address _baseToken, address _quoteToken, uint24 _feeTier, uint32 _quotePeriod) {
048:     uniV3Pool = IUniswapV3Factory(_UNI_V3_FACTORY).getPool(_baseToken, _quoteToken, _feeTier);
049:     if (uniV3Pool == address(0)) revert UniV3Relayer_InvalidPool();
050: 
051:     address _token0 = IUniswapV3Pool(uniV3Pool).token0();
052:     address _token1 = IUniswapV3Pool(uniV3Pool).token1();
053: 
054:     // The factory validates that both token0 and token1 are desired baseToken and quoteTokens
055:     if (_token0 == _baseToken) {
056:       baseToken = _token0;
057:       quoteToken = _token1;
058:     } else {
059:       baseToken = _token1;
060:       quoteToken = _token0;
061:     }
062: 
063:     baseAmount = uint128(10 ** IERC20Metadata(_baseToken).decimals());
064:     multiplier = 18 - IERC20Metadata(_quoteToken).decimals();
065:     quotePeriod = _quotePeriod;
066: 
067:     symbol = string(abi.encodePacked(IERC20Metadata(_baseToken).symbol(), ' / ', IERC20Metadata(_quoteToken).symbol()));
068:   }
069: 
070:   /**
071:    * @dev    Method will return invalid if the pool doesn't have enough history
072:    * @inheritdoc IBaseOracle
073:    */
074:   function getResultWithValidity() external view returns (uint256 _result, bool _validity) {
075:     // If the pool doesn't have enough history return false
076:     if (OracleLibrary.getOldestObservationSecondsAgo(uniV3Pool) < quotePeriod) {
077:       return (0, false);
078:     }
079:     // Consult the query with a TWAP period of quotePeriod
080:     (int24 _arithmeticMeanTick,) = OracleLibrary.consult(uniV3Pool, quotePeriod);
081:     // Calculate the quote amount
082:     uint256 _quoteAmount = OracleLibrary.getQuoteAtTick({
083:       tick: _arithmeticMeanTick,
084:       baseAmount: baseAmount,
085:       baseToken: baseToken,
086:       quoteToken: quoteToken
087:     });
088:     // Process the quote result to 18 decimal quote
089:     _result = _parseResult(_quoteAmount);
090:     _validity = true;
091:   }
092: 
093:   /**
094:    * @dev    This method may revert with 'OLD!' if the pool doesn't have enough cardinality or initialized history
095:    * @inheritdoc IBaseOracle
096:    */
097:   function read() external view returns (uint256 _result) {
098:     // This call may revert with 'OLD!' if the pool doesn't have enough cardinality or initialized history
099:     (int24 _arithmeticMeanTick,) = OracleLibrary.consult(uniV3Pool, quotePeriod);
100:     uint256 _quoteAmount = OracleLibrary.getQuoteAtTick({
101:       tick: _arithmeticMeanTick,
102:       baseAmount: baseAmount,
103:       baseToken: baseToken,
104:       quoteToken: quoteToken
105:     });
106:     _result = _parseResult(_quoteAmount);
107:   }
108: 
109:   /// @notice Parses the result from the aggregator into 18 decimals format
110:   function _parseResult(uint256 _quoteResult) internal view returns (uint256 _result) {
111:     return _quoteResult * 10 ** multiplier;
112:   }
113: }


```

[link](https://github.com/open-dollar/od-contracts/blob/v1.5.5-audit//src/contracts/oracles/UniV3Relayer.sol#L16-L113) 


</details>


### [GAS&#x2011;34] Use `do while` loops instead of `for` loops 
A `do while` loop will cost less gas since the condition is not being checked for the first iteration, Check my example on [github](https://github.com/he110-1/gasOptimization/blob/main/forToDoWhileOptimizationProof.sol). Actually, `do while` alwayse cast less gas compared to `For` check my second example [github](https://github.com/he110-1/gasOptimization/blob/main/forToDoWhileOptimizationProof2.sol)


*There are 1 instances of this issue:*



<details>
<summary>see instances</summary>


```solidity
File: src/contracts/proxies/ODSafeManager.sol

91:     for (uint256 _i; _i < _safes.length; _i++) {


```

[link](https://github.com/open-dollar/od-contracts/blob/v1.5.5-audit//src/contracts/proxies/ODSafeManager.sol#L91-L91) 


</details>


### [GAS&#x2011;35] Use `+=` for `mapping`s 
Using `+=` for mappings saves **[40 gas](https://gist.github.com/IllIllI000/4fc5f83a9edc6ed16677258bf58f32a5)** due to not having to recalculate the mapping's value's hash


*There are 1 instances of this issue:*



<details>
<summary>see instances</summary>


```solidity
File: src/contracts/AccountingEngine.sol

116:     debtQueue[block.timestamp] = debtQueue[block.timestamp] + _debtBlock;


```

[link](https://github.com/open-dollar/od-contracts/blob/v1.5.5-audit//src/contracts/AccountingEngine.sol#L116-L116) 


</details>


### [GAS&#x2011;36] Simple checks for zero `uint` can be done using assembly to save gas 



*There are 6 instances of this issue:*



<details>
<summary>see instances</summary>


```solidity
File: src/contracts/AccountingEngine.sol

128:     if (_debtBlock == 0) revert AccEng_NullAmount();

176:     if (_params.debtAuctionBidSize == 0) revert AccEng_DebtAuctionDisabled();

200:     if (_params.surplusAmount == 0) revert AccEng_NullAmount();


```

[link](https://github.com/open-dollar/od-contracts/blob/v1.5.5-audit//src/contracts/AccountingEngine.sol#L128-L128) , [link](https://github.com/open-dollar/od-contracts/blob/v1.5.5-audit//src/contracts/AccountingEngine.sol#L176-L176), [link](https://github.com/open-dollar/od-contracts/blob/v1.5.5-audit//src/contracts/AccountingEngine.sol#L200-L200)


```solidity

File: src/contracts/proxies/ODSafeManager.sol

51:     if (msg.sender != _owner && safeCan[_owner][_safe][msg.sender] == 0) revert SafeNotAllowed();

60:     if (msg.sender != _handler && handlerCan[_handler][msg.sender] == 0) revert HandlerNotAllowed();


```

[link](https://github.com/open-dollar/od-contracts/blob/v1.5.5-audit//src/contracts/proxies/ODSafeManager.sol#L51-L51) , [link](https://github.com/open-dollar/od-contracts/blob/v1.5.5-audit//src/contracts/proxies/ODSafeManager.sol#L60-L60)


```solidity

File: src/contracts/proxies/actions/BasicActions.sol

148:     if (_deltaWad == 0) return;


```

[link](https://github.com/open-dollar/od-contracts/blob/v1.5.5-audit//src/contracts/proxies/actions/BasicActions.sol#L148-L148) 


</details>


### [GAS&#x2011;37] `++i`/`i++` should be `unchecked{++i}`/`unchecked{i++}` when it is not possible for them to overflow, as is the case when used in `for`- and `while`-loops 
The `unchecked` keyword is new in solidity version 0.8.0, so this only applies to that version or higher, which these instances are. This saves **30-40 gas [per loop](https://gist.github.com/hrkrshnn/ee8fabd532058307229d65dcd5836ddc#the-increment-in-for-loop-post-condition-can-be-made-unchecked)**


*There are 1 instances of this issue:*



<details>
<summary>see instances</summary>


```solidity
File: src/contracts/proxies/ODSafeManager.sol

91:     for (uint256 _i; _i < _safes.length; _i++) {


```

[link](https://github.com/open-dollar/od-contracts/blob/v1.5.5-audit//src/contracts/proxies/ODSafeManager.sol#L91-L91) 


</details>
