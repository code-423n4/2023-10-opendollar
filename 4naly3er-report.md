# Report


## Gas Optimizations


| |Issue|Instances|
|-|:-|:-:|
| [GAS-1](#GAS-1) | Cache array length outside of loop | 1 |
| [GAS-2](#GAS-2) | For Operations that will not overflow, you could use unchecked | 218 |
| [GAS-3](#GAS-3) | Functions guaranteed to revert when called by normal users can be marked `payable` | 3 |
| [GAS-4](#GAS-4) | `++i` costs less gas than `i++`, especially when it's used in `for`-loops (`--i`/`i--` too) | 1 |
| [GAS-5](#GAS-5) | Use != 0 instead of > 0 for unsigned integer comparison | 2 |
### <a name="GAS-1"></a>[GAS-1] Cache array length outside of loop
If not cached, the solidity compiler will always read the length of the array during each iteration. That is, if it is a storage array, this is an extra sload operation (100 additional extra gas for each iteration except for the first) and if it is a memory array, this is an extra mload operation (3 additional gas for each iteration except for the first).

*Instances (1)*:
```solidity
File: src/contracts/proxies/ODSafeManager.sol

91:     for (uint256 _i; _i < _safes.length; _i++) {

```

### <a name="GAS-2"></a>[GAS-2] For Operations that will not overflow, you could use unchecked

*Instances (218)*:
```solidity
File: src/contracts/AccountingEngine.sol

4: import {IAccountingEngine} from '@interfaces/IAccountingEngine.sol';

5: import {IDebtAuctionHouse} from '@interfaces/IDebtAuctionHouse.sol';

6: import {ISurplusAuctionHouse} from '@interfaces/ISurplusAuctionHouse.sol';

7: import {ISAFEEngine} from '@interfaces/ISAFEEngine.sol';

9: import {Authorizable, IAuthorizable} from '@contracts/utils/Authorizable.sol';

9: import {Authorizable, IAuthorizable} from '@contracts/utils/Authorizable.sol';

10: import {Disableable} from '@contracts/utils/Disableable.sol';

10: import {Disableable} from '@contracts/utils/Disableable.sol';

11: import {Modifiable} from '@contracts/utils/Modifiable.sol';

11: import {Modifiable} from '@contracts/utils/Modifiable.sol';

13: import {Encoding} from '@libraries/Encoding.sol';

14: import {Math, WAD} from '@libraries/Math.sol';

15: import {Assertions} from '@libraries/Assertions.sol';

28:   uint256 internal constant ONE_HUNDRED_WAD = 100 * WAD;

70:   uint256 public /* RAD */ totalOnAuctionDebt;

70:   uint256 public /* RAD */ totalOnAuctionDebt;

70:   uint256 public /* RAD */ totalOnAuctionDebt;

70:   uint256 public /* RAD */ totalOnAuctionDebt;

72:   uint256 public /* RAD */ totalQueuedDebt;

72:   uint256 public /* RAD */ totalQueuedDebt;

72:   uint256 public /* RAD */ totalQueuedDebt;

72:   uint256 public /* RAD */ totalQueuedDebt;

109:     return (_debtBalance - totalQueuedDebt) - totalOnAuctionDebt;

109:     return (_debtBalance - totalQueuedDebt) - totalOnAuctionDebt;

116:     debtQueue[block.timestamp] = debtQueue[block.timestamp] + _debtBlock;

117:     totalQueuedDebt = totalQueuedDebt + _debtBlock;

124:     if (block.timestamp < _debtBlockTimestamp + _params.popDebtDelay) revert AccEng_PopDebtCooldown();

130:     totalQueuedDebt = totalQueuedDebt - _debtBlock;

152:     _newCoinBalance = _coinBalance - _rad;

153:     _newDebtBalance = _debtBalance - _rad;

167:     totalOnAuctionDebt -= _rad;

169:     emit CancelDebt(_rad, _coinBalance - _rad, safeEngine.debtBalance(address(this)));

184:     totalOnAuctionDebt += _params.debtAuctionBidSize;

202:     if (block.timestamp < lastSurplusTime + _params.surplusDelay) revert AccEng_SurplusCooldown();

208:     if (_coinBalance < _debtBalance + _params.surplusAmount + _params.surplusBuffer) {

208:     if (_coinBalance < _debtBalance + _params.surplusAmount + _params.surplusBuffer) {

215:         _amountToSell: _params.surplusAmount.wmul(ONE_HUNDRED_WAD - _params.surplusTransferPercentage),

220:       emit AuctionSurplus(_id, 0, _params.surplusAmount.wmul(ONE_HUNDRED_WAD - _params.surplusTransferPercentage));

262:     if (block.timestamp < disableTimestamp + _params.disableCooldown) revert AccEng_PostSettlementCooldown();

```

```solidity
File: src/contracts/factories/CamelotRelayerChild.sol

4: import {ICamelotRelayerChild} from '@interfaces/factories/ICamelotRelayerChild.sol';

4: import {ICamelotRelayerChild} from '@interfaces/factories/ICamelotRelayerChild.sol';

6: import {CamelotRelayer} from '@contracts/oracles/CamelotRelayer.sol';

6: import {CamelotRelayer} from '@contracts/oracles/CamelotRelayer.sol';

8: import {FactoryChild} from '@contracts/factories/FactoryChild.sol';

8: import {FactoryChild} from '@contracts/factories/FactoryChild.sol';

```

```solidity
File: src/contracts/factories/CamelotRelayerFactory.sol

4: import {ICamelotRelayerFactory} from '@interfaces/factories/ICamelotRelayerFactory.sol';

4: import {ICamelotRelayerFactory} from '@interfaces/factories/ICamelotRelayerFactory.sol';

5: import {IBaseOracle} from '@interfaces/oracles/IBaseOracle.sol';

5: import {IBaseOracle} from '@interfaces/oracles/IBaseOracle.sol';

7: import {CamelotRelayerChild} from '@contracts/factories/CamelotRelayerChild.sol';

7: import {CamelotRelayerChild} from '@contracts/factories/CamelotRelayerChild.sol';

9: import {Authorizable} from '@contracts/utils/Authorizable.sol';

9: import {Authorizable} from '@contracts/utils/Authorizable.sol';

11: import {EnumerableSet} from '@openzeppelin/utils/structs/EnumerableSet.sol';

11: import {EnumerableSet} from '@openzeppelin/utils/structs/EnumerableSet.sol';

11: import {EnumerableSet} from '@openzeppelin/utils/structs/EnumerableSet.sol';

```

```solidity
File: src/contracts/gov/ODGovernor.sol

4: import {IVotes} from '@openzeppelin/governance/utils/IVotes.sol';

4: import {IVotes} from '@openzeppelin/governance/utils/IVotes.sol';

4: import {IVotes} from '@openzeppelin/governance/utils/IVotes.sol';

5: import {IERC165} from '@openzeppelin/utils/introspection/IERC165.sol';

5: import {IERC165} from '@openzeppelin/utils/introspection/IERC165.sol';

5: import {IERC165} from '@openzeppelin/utils/introspection/IERC165.sol';

6: import {IGovernor} from '@openzeppelin/governance/IGovernor.sol';

6: import {IGovernor} from '@openzeppelin/governance/IGovernor.sol';

8: import {TimelockController} from '@openzeppelin/governance/TimelockController.sol';

8: import {TimelockController} from '@openzeppelin/governance/TimelockController.sol';

10: import {Governor} from '@openzeppelin/governance/Governor.sol';

10: import {Governor} from '@openzeppelin/governance/Governor.sol';

11: import {GovernorSettings} from '@openzeppelin/governance/extensions/GovernorSettings.sol';

11: import {GovernorSettings} from '@openzeppelin/governance/extensions/GovernorSettings.sol';

11: import {GovernorSettings} from '@openzeppelin/governance/extensions/GovernorSettings.sol';

12: import {GovernorCompatibilityBravo} from '@openzeppelin/governance/compatibility/GovernorCompatibilityBravo.sol';

12: import {GovernorCompatibilityBravo} from '@openzeppelin/governance/compatibility/GovernorCompatibilityBravo.sol';

12: import {GovernorCompatibilityBravo} from '@openzeppelin/governance/compatibility/GovernorCompatibilityBravo.sol';

13: import {GovernorVotes} from '@openzeppelin/governance/extensions/GovernorVotes.sol';

13: import {GovernorVotes} from '@openzeppelin/governance/extensions/GovernorVotes.sol';

13: import {GovernorVotes} from '@openzeppelin/governance/extensions/GovernorVotes.sol';

14: import {GovernorVotesQuorumFraction} from '@openzeppelin/governance/extensions/GovernorVotesQuorumFraction.sol';

14: import {GovernorVotesQuorumFraction} from '@openzeppelin/governance/extensions/GovernorVotesQuorumFraction.sol';

14: import {GovernorVotesQuorumFraction} from '@openzeppelin/governance/extensions/GovernorVotesQuorumFraction.sol';

15: import {GovernorTimelockControl} from '@openzeppelin/governance/extensions/GovernorTimelockControl.sol';

15: import {GovernorTimelockControl} from '@openzeppelin/governance/extensions/GovernorTimelockControl.sol';

15: import {GovernorTimelockControl} from '@openzeppelin/governance/extensions/GovernorTimelockControl.sol';

```

```solidity
File: src/contracts/oracles/CamelotRelayer.sol

4: import {IBaseOracle} from '@interfaces/oracles/IBaseOracle.sol';

4: import {IBaseOracle} from '@interfaces/oracles/IBaseOracle.sol';

5: import {ICamelotRelayer} from '@interfaces/oracles/ICamelotRelayer.sol';

5: import {ICamelotRelayer} from '@interfaces/oracles/ICamelotRelayer.sol';

6: import {IERC20Metadata} from '@openzeppelin/token/ERC20/extensions/IERC20Metadata.sol';

6: import {IERC20Metadata} from '@openzeppelin/token/ERC20/extensions/IERC20Metadata.sol';

6: import {IERC20Metadata} from '@openzeppelin/token/ERC20/extensions/IERC20Metadata.sol';

6: import {IERC20Metadata} from '@openzeppelin/token/ERC20/extensions/IERC20Metadata.sol';

8: import {IAlgebraFactory} from '@interfaces/factories/IAlgebraFactory.sol';

8: import {IAlgebraFactory} from '@interfaces/factories/IAlgebraFactory.sol';

9: import {ICamelotPair} from '@camelot/interfaces/ICamelotPair.sol';

9: import {ICamelotPair} from '@camelot/interfaces/ICamelotPair.sol';

10: import {OracleLibrary} from '@uniswap/v3-periphery/contracts/libraries/OracleLibrary.sol';

10: import {OracleLibrary} from '@uniswap/v3-periphery/contracts/libraries/OracleLibrary.sol';

10: import {OracleLibrary} from '@uniswap/v3-periphery/contracts/libraries/OracleLibrary.sol';

10: import {OracleLibrary} from '@uniswap/v3-periphery/contracts/libraries/OracleLibrary.sol';

10: import {OracleLibrary} from '@uniswap/v3-periphery/contracts/libraries/OracleLibrary.sol';

11: import {CAMELOT_V3_FACTORY, GOERLI_CAMELOT_V3_FACTORY} from '@script/Registry.s.sol';

57:     baseAmount = uint128(10 ** IERC20Metadata(_baseToken).decimals());

57:     baseAmount = uint128(10 ** IERC20Metadata(_baseToken).decimals());

58:     multiplier = 18 - IERC20Metadata(_quoteToken).decimals();

61:     symbol = string(abi.encodePacked(IERC20Metadata(_baseToken).symbol(), ' / ', IERC20Metadata(_quoteToken).symbol()));

104:     return _quoteResult * 10 ** multiplier;

104:     return _quoteResult * 10 ** multiplier;

104:     return _quoteResult * 10 ** multiplier;

```

```solidity
File: src/contracts/oracles/UniV3Relayer.sol

4: import {IBaseOracle} from '@interfaces/oracles/IBaseOracle.sol';

4: import {IBaseOracle} from '@interfaces/oracles/IBaseOracle.sol';

5: import {IUniV3Relayer} from '@interfaces/oracles/IUniV3Relayer.sol';

5: import {IUniV3Relayer} from '@interfaces/oracles/IUniV3Relayer.sol';

6: import {IERC20Metadata} from '@openzeppelin/token/ERC20/extensions/IERC20Metadata.sol';

6: import {IERC20Metadata} from '@openzeppelin/token/ERC20/extensions/IERC20Metadata.sol';

6: import {IERC20Metadata} from '@openzeppelin/token/ERC20/extensions/IERC20Metadata.sol';

6: import {IERC20Metadata} from '@openzeppelin/token/ERC20/extensions/IERC20Metadata.sol';

7: import {IUniswapV3Factory} from '@uniswap/v3-core/contracts/interfaces/IUniswapV3Factory.sol';

7: import {IUniswapV3Factory} from '@uniswap/v3-core/contracts/interfaces/IUniswapV3Factory.sol';

7: import {IUniswapV3Factory} from '@uniswap/v3-core/contracts/interfaces/IUniswapV3Factory.sol';

7: import {IUniswapV3Factory} from '@uniswap/v3-core/contracts/interfaces/IUniswapV3Factory.sol';

7: import {IUniswapV3Factory} from '@uniswap/v3-core/contracts/interfaces/IUniswapV3Factory.sol';

8: import {OracleLibrary, IUniswapV3Pool} from '@uniswap/v3-periphery/contracts/libraries/OracleLibrary.sol';

8: import {OracleLibrary, IUniswapV3Pool} from '@uniswap/v3-periphery/contracts/libraries/OracleLibrary.sol';

8: import {OracleLibrary, IUniswapV3Pool} from '@uniswap/v3-periphery/contracts/libraries/OracleLibrary.sol';

8: import {OracleLibrary, IUniswapV3Pool} from '@uniswap/v3-periphery/contracts/libraries/OracleLibrary.sol';

8: import {OracleLibrary, IUniswapV3Pool} from '@uniswap/v3-periphery/contracts/libraries/OracleLibrary.sol';

9: import {UNISWAP_V3_FACTORY, GOERLI_UNISWAP_V3_FACTORY} from '@script/Registry.s.sol';

63:     baseAmount = uint128(10 ** IERC20Metadata(_baseToken).decimals());

63:     baseAmount = uint128(10 ** IERC20Metadata(_baseToken).decimals());

64:     multiplier = 18 - IERC20Metadata(_quoteToken).decimals();

67:     symbol = string(abi.encodePacked(IERC20Metadata(_baseToken).symbol(), ' / ', IERC20Metadata(_quoteToken).symbol()));

111:     return _quoteResult * 10 ** multiplier;

111:     return _quoteResult * 10 ** multiplier;

111:     return _quoteResult * 10 ** multiplier;

```

```solidity
File: src/contracts/proxies/ODSafeManager.sol

4: import {SAFEHandler} from '@contracts/proxies/SAFEHandler.sol';

4: import {SAFEHandler} from '@contracts/proxies/SAFEHandler.sol';

5: import {ISAFEEngine} from '@interfaces/ISAFEEngine.sol';

6: import {ILiquidationEngine} from '@interfaces/ILiquidationEngine.sol';

7: import {IVault721} from '@interfaces/proxies/IVault721.sol';

7: import {IVault721} from '@interfaces/proxies/IVault721.sol';

9: import {Math} from '@libraries/Math.sol';

10: import {EnumerableSet} from '@openzeppelin/utils/structs/EnumerableSet.sol';

10: import {EnumerableSet} from '@openzeppelin/utils/structs/EnumerableSet.sol';

10: import {EnumerableSet} from '@openzeppelin/utils/structs/EnumerableSet.sol';

11: import {Assertions} from '@libraries/Assertions.sol';

13: import {IODSafeManager} from '@interfaces/proxies/IODSafeManager.sol';

13: import {IODSafeManager} from '@interfaces/proxies/IODSafeManager.sol';

31:   uint256 internal _safeId; // Auto incremental

31:   uint256 internal _safeId; // Auto incremental

91:     for (uint256 _i; _i < _safes.length; _i++) {

91:     for (uint256 _i; _i < _safes.length; _i++) {

121:     ++_safeId;

121:     ++_safeId;

```

```solidity
File: src/contracts/proxies/SAFEHandler.sol

4: import {ISAFEEngine} from '@interfaces/ISAFEEngine.sol';

```

```solidity
File: src/contracts/proxies/Vault721.sol

4: import {ERC721} from '@openzeppelin/token/ERC721/ERC721.sol';

4: import {ERC721} from '@openzeppelin/token/ERC721/ERC721.sol';

4: import {ERC721} from '@openzeppelin/token/ERC721/ERC721.sol';

5: import {ERC721Enumerable} from '@openzeppelin/token/ERC721/extensions/ERC721Enumerable.sol';

5: import {ERC721Enumerable} from '@openzeppelin/token/ERC721/extensions/ERC721Enumerable.sol';

5: import {ERC721Enumerable} from '@openzeppelin/token/ERC721/extensions/ERC721Enumerable.sol';

5: import {ERC721Enumerable} from '@openzeppelin/token/ERC721/extensions/ERC721Enumerable.sol';

6: import {IODSafeManager} from '@interfaces/proxies/IODSafeManager.sol';

6: import {IODSafeManager} from '@interfaces/proxies/IODSafeManager.sol';

7: import {ODProxy} from '@contracts/proxies/ODProxy.sol';

7: import {ODProxy} from '@contracts/proxies/ODProxy.sol';

8: import {NFTRenderer} from '@contracts/proxies/NFTRenderer.sol';

8: import {NFTRenderer} from '@contracts/proxies/NFTRenderer.sol';

23:     '{"name": "Open Dollar Vaults","description": "Tradable Vaults for the Open Dollar stablecoin protocol. Caution! Trading this NFT means trading the ownership of your Vault in the Open Dollar protocol and all of the assets/collateral inside each Vault.","image": "https://app.opendollar.com/collectionImage.png","external_link": "https://opendollar.com"}';

23:     '{"name": "Open Dollar Vaults","description": "Tradable Vaults for the Open Dollar stablecoin protocol. Caution! Trading this NFT means trading the ownership of your Vault in the Open Dollar protocol and all of the assets/collateral inside each Vault.","image": "https://app.opendollar.com/collectionImage.png","external_link": "https://opendollar.com"}';

23:     '{"name": "Open Dollar Vaults","description": "Tradable Vaults for the Open Dollar stablecoin protocol. Caution! Trading this NFT means trading the ownership of your Vault in the Open Dollar protocol and all of the assets/collateral inside each Vault.","image": "https://app.opendollar.com/collectionImage.png","external_link": "https://opendollar.com"}';

23:     '{"name": "Open Dollar Vaults","description": "Tradable Vaults for the Open Dollar stablecoin protocol. Caution! Trading this NFT means trading the ownership of your Vault in the Open Dollar protocol and all of the assets/collateral inside each Vault.","image": "https://app.opendollar.com/collectionImage.png","external_link": "https://opendollar.com"}';

23:     '{"name": "Open Dollar Vaults","description": "Tradable Vaults for the Open Dollar stablecoin protocol. Caution! Trading this NFT means trading the ownership of your Vault in the Open Dollar protocol and all of the assets/collateral inside each Vault.","image": "https://app.opendollar.com/collectionImage.png","external_link": "https://opendollar.com"}';

23:     '{"name": "Open Dollar Vaults","description": "Tradable Vaults for the Open Dollar stablecoin protocol. Caution! Trading this NFT means trading the ownership of your Vault in the Open Dollar protocol and all of the assets/collateral inside each Vault.","image": "https://app.opendollar.com/collectionImage.png","external_link": "https://opendollar.com"}';

96:     require(_proxyRegistry[_proxy] != address(0), 'V721: non-native proxy');

148:     uri = string.concat('data:application/json;utf8,', contractMetaData);

```

```solidity
File: src/contracts/proxies/actions/BasicActions.sol

4: import {ODSafeManager} from '@contracts/proxies/ODSafeManager.sol';

4: import {ODSafeManager} from '@contracts/proxies/ODSafeManager.sol';

5: import {ODProxy} from '@contracts/proxies/ODProxy.sol';

5: import {ODProxy} from '@contracts/proxies/ODProxy.sol';

7: import {ISAFEEngine} from '@interfaces/ISAFEEngine.sol';

8: import {ICoinJoin} from '@interfaces/utils/ICoinJoin.sol';

8: import {ICoinJoin} from '@interfaces/utils/ICoinJoin.sol';

9: import {ITaxCollector} from '@interfaces/ITaxCollector.sol';

10: import {ICollateralJoin} from '@interfaces/utils/ICollateralJoin.sol';

10: import {ICollateralJoin} from '@interfaces/utils/ICollateralJoin.sol';

11: import {IERC20Metadata} from '@openzeppelin/token/ERC20/extensions/IERC20Metadata.sol';

11: import {IERC20Metadata} from '@openzeppelin/token/ERC20/extensions/IERC20Metadata.sol';

11: import {IERC20Metadata} from '@openzeppelin/token/ERC20/extensions/IERC20Metadata.sol';

11: import {IERC20Metadata} from '@openzeppelin/token/ERC20/extensions/IERC20Metadata.sol';

12: import {IBasicActions} from '@interfaces/proxies/actions/IBasicActions.sol';

12: import {IBasicActions} from '@interfaces/proxies/actions/IBasicActions.sol';

12: import {IBasicActions} from '@interfaces/proxies/actions/IBasicActions.sol';

14: import {Math, WAD, RAY, RAD} from '@libraries/Math.sol';

16: import {CommonActions} from '@contracts/proxies/actions/CommonActions.sol';

16: import {CommonActions} from '@contracts/proxies/actions/CommonActions.sol';

16: import {CommonActions} from '@contracts/proxies/actions/CommonActions.sol';

41:     if (_coinAmount < _deltaWad * RAY) {

43:       _deltaDebt = ((_deltaWad * RAY - _coinAmount) / _rate).toInt();

43:       _deltaDebt = ((_deltaWad * RAY - _coinAmount) / _rate).toInt();

43:       _deltaDebt = ((_deltaWad * RAY - _coinAmount) / _rate).toInt();

45:       _deltaDebt = uint256(_deltaDebt) * _rate < _deltaWad * RAY ? _deltaDebt + 1 : _deltaDebt;

45:       _deltaDebt = uint256(_deltaDebt) * _rate < _deltaWad * RAY ? _deltaDebt + 1 : _deltaDebt;

45:       _deltaDebt = uint256(_deltaDebt) * _rate < _deltaWad * RAY ? _deltaDebt + 1 : _deltaDebt;

63:     _deltaDebt = (_coinAmount / _rate).toInt();

65:     _deltaDebt = uint256(_deltaDebt) <= _generatedDebt ? -_deltaDebt : -_generatedDebt.toInt();

65:     _deltaDebt = uint256(_deltaDebt) <= _generatedDebt ? -_deltaDebt : -_generatedDebt.toInt();

83:     uint256 _rad = _generatedDebt * _rate - _coinAmount;

83:     uint256 _rad = _generatedDebt * _rate - _coinAmount;

85:     _deltaWad = _rad / RAY;

87:     _deltaWad = _deltaWad * RAY < _rad ? _deltaWad + 1 : _deltaWad;

87:     _deltaWad = _deltaWad * RAY < _rad ? _deltaWad + 1 : _deltaWad;

203:     _transferInternalCoins(_manager, _safeId, address(this), _deltaWad * RAY);

205:     _exitSystemCoins(_coinJoin, _deltaWad * RAY);

276:     _modifySAFECollateralization(_manager, _safeId, -_deltaWad.toInt(), 0);

308:       _deltaDebt: -int256(_safeData.generatedDebt)

365:       -_collateralWad.toInt(),

396:     _modifySAFECollateralization(_manager, _safeId, -_collateralWad.toInt(), -_safeData.generatedDebt.toInt());

396:     _modifySAFECollateralization(_manager, _safeId, -_collateralWad.toInt(), -_safeData.generatedDebt.toInt());

```

### <a name="GAS-3"></a>[GAS-3] Functions guaranteed to revert when called by normal users can be marked `payable`
If a function modifier such as `onlyOwner` is used, the function will revert if a normal user tries to pay the function. Marking the function as `payable` will lower the gas cost for legitimate callers because the compiler will not include checks for whether a payment was provided.

*Instances (3)*:
```solidity
File: src/contracts/proxies/Vault721.sol

119:   function updateContractURI(string memory _metaData) external onlyGovernor {

126:   function setSafeManager(address _safeManager) external onlyGovernor {

133:   function setNftRenderer(address _nftRenderer) external onlyGovernor {

```

### <a name="GAS-4"></a>[GAS-4] `++i` costs less gas than `i++`, especially when it's used in `for`-loops (`--i`/`i--` too)
*Saves 5 gas per loop*

*Instances (1)*:
```solidity
File: src/contracts/proxies/ODSafeManager.sol

91:     for (uint256 _i; _i < _safes.length; _i++) {

```

### <a name="GAS-5"></a>[GAS-5] Use != 0 instead of > 0 for unsigned integer comparison

*Instances (2)*:
```solidity
File: src/contracts/AccountingEngine.sol

224:     if (_params.surplusTransferPercentage > 0) {

269:     if (_coinBalance > 0) {

```


## Low Issues


| |Issue|Instances|
|-|:-|:-:|
| [L-1](#L-1) | Empty Function Body - Consider commenting why | 3 |
### <a name="L-1"></a>[L-1] Empty Function Body - Consider commenting why

*Instances (3)*:
```solidity
File: src/contracts/factories/CamelotRelayerChild.sol

20:   ) CamelotRelayer(_baseToken, _quoteToken, _quotePeriod) {}

```

```solidity
File: src/contracts/factories/CamelotRelayerFactory.sol

20:   constructor() Authorizable(msg.sender) {}

```

```solidity
File: src/contracts/gov/ODGovernor.sol

45:   {}

```


## Medium Issues


| |Issue|Instances|
|-|:-|:-:|
| [M-1](#M-1) | Centralization Risk for trusted owners | 1 |
### <a name="M-1"></a>[M-1] Centralization Risk for trusted owners

#### Impact:
Contracts have owners with privileged rights to perform admin tasks and need to be trusted to not perform malicious updates or drain funds.

*Instances (1)*:
```solidity
File: src/contracts/proxies/ODProxy.sol

26:   function execute(address _target, bytes memory _data) external payable onlyOwner returns (bytes memory _response) {

```

