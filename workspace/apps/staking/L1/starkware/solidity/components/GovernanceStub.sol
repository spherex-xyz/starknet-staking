// SPDX-License-Identifier: Apache-2.0.
pragma solidity ^0.8.0;

import "starkware/solidity/interfaces/MGovernance.sol"; 
import {SphereXProtected} from "@spherex-xyz/contracts/src/SphereXProtected.sol";
 

/*
  Implements Governance stub to inherit correctly from MGovernance for contracts that
  do not implement Governance. (e.g. CallProxy).
*/
abstract contract GovernanceStub is SphereXProtected, MGovernance {
    function initGovernance() internal override sphereXGuardInternal(0x4a9e82ec) {}

    function _isGovernor(
        address /*user*/
    ) internal pure override returns (bool) {
        return false;
    }
}
