// SPDX-License-Identifier: Apache-2.0.
pragma solidity ^0.8.0;

import "starkware/solidity/libraries/AccessControl.sol"; 
import {ISphereXEngine} from "@spherex-xyz/contracts/src/ISphereXEngine.sol";
 

// int.from_bytes(Web3.keccak(text="ROLE_APP_GOVERNOR"), "big") & MASK_250 .
bytes32 constant APP_GOVERNOR = bytes32(
    uint256(0xd2ead78c620e94b02d0a996e99298c59ddccfa1d8a0149080ac3a20de06068)
);

// int.from_bytes(Web3.keccak(text="ROLE_APP_ROLE_ADMIN"), "big") & MASK_250 .
bytes32 constant APP_ROLE_ADMIN = bytes32(
    uint256(0x03e615638e0b79444a70f8c695bf8f2a47033bf1cf95691ec3130f64939cee99)
);

// int.from_bytes(Web3.keccak(text="ROLE_GOVERNANCE_ADMIN"), "big") & MASK_250 .
bytes32 constant GOVERNANCE_ADMIN = bytes32(
    uint256(0x03711c9d994faf6055172091cb841fd4831aa743e6f3315163b06a122c841846)
);

// int.from_bytes(Web3.keccak(text="ROLE_OPERATOR"), "big") & MASK_250 .
bytes32 constant OPERATOR = bytes32(
    uint256(0x023edb77f7c8cc9e38e8afe78954f703aeeda7fffe014eeb6e56ea84e62f6da7)
);

// int.from_bytes(Web3.keccak(text="ROLE_SECURITY_ADMIN"), "big") & MASK_250 .
bytes32 constant SECURITY_ADMIN = bytes32(
    uint256(0x026bd110619d11cfdfc28e281df893bc24828e89177318e9dbd860cdaedeb6b3)
);

// int.from_bytes(Web3.keccak(text="ROLE_SECURITY_AGENT"), "big") & MASK_250 .
bytes32 constant SECURITY_AGENT = bytes32(
    uint256(0x037693ba312785932d430dccf0f56ffedd0aa7c0f8b6da2cc4530c2717689b96)
);

// int.from_bytes(Web3.keccak(text="ROLE_TOKEN_ADMIN"), "big") & MASK_250 .
bytes32 constant TOKEN_ADMIN = bytes32(
    uint256(0x0128d63adbf6b09002c26caf55c47e2f26635807e3ef1b027218aa74c8d61a3e)
);

// int.from_bytes(Web3.keccak(text="ROLE_UPGRADE_GOVERNOR"), "big") & MASK_250 .
bytes32 constant UPGRADE_GOVERNOR = bytes32(
    uint256(0x0251e864ca2a080f55bce5da2452e8cfcafdbc951a3e7fff5023d558452ec228)
);

/*
  Role                |   Role Admin
  ----------------------------------------
  GOVERNANCE_ADMIN    |   GOVERNANCE_ADMIN
  UPGRADE_GOVERNOR    |   GOVERNANCE_ADMIN
  APP_ROLE_ADMIN      |   GOVERNANCE_ADMIN
  APP_GOVERNOR        |   APP_ROLE_ADMIN
  OPERATOR            |   APP_ROLE_ADMIN
  TOKEN_ADMIN         |   APP_ROLE_ADMIN
  SECURITY_ADMIN      |   SECURITY_ADMIN
  SECURITY_AGENT      |   SECURITY_ADMIN .
*/
library RolesLib { 
    bytes32 private constant SPHEREX_ADMIN_STORAGE_SLOT = bytes32(uint256(keccak256("eip1967.spherex.spherex")) - 1);
    bytes32 private constant SPHEREX_OPERATOR_STORAGE_SLOT =
        bytes32(uint256(keccak256("eip1967.spherex.operator")) - 1);
    bytes32 private constant SPHEREX_ENGINE_STORAGE_SLOT =
        bytes32(uint256(keccak256("eip1967.spherex.spherex_engine")) - 1);

    struct ModifierLocals {
        bytes32[] storageSlots;
        bytes32[] valuesBefore;
        uint256 gas;
    }

    function _sphereXEngine() private view returns (ISphereXEngine) {
        return ISphereXEngine(_getAddress(SPHEREX_ENGINE_STORAGE_SLOT));
    }

    function _getAddress(bytes32 slot) private view returns (address addr) {
        // solhint-disable-next-line no-inline-assembly
        // slither-disable-next-line assembly
        assembly {
            addr := sload(slot)
        }
    }

    modifier returnsIfNotActivated() {
        if (address(_sphereXEngine()) == address(0)) {
            return;
        }

        _;
    }

    // ============ Hooks ============

    /**
     * @dev internal function for engine communication. We use it to reduce contract size.
     *  Should be called before the code of a function.
     * @param num function identifier
     * @param isExternalCall set to true if this was called externally
     *  or a 'public' function from another address
     */
    function _sphereXValidatePre(
        int256 num,
        bool isExternalCall
    ) private sphereXGuardInternal(0xe70954ea) returnsIfNotActivated returns (ModifierLocals memory locals) {
        ISphereXEngine sphereXEngine = _sphereXEngine();
        if (isExternalCall) {
            locals.storageSlots = sphereXEngine.sphereXValidatePre(num, msg.sender, msg.data);
        } else {
            locals.storageSlots = sphereXEngine.sphereXValidateInternalPre(num);
        }
        locals.valuesBefore = _readStorage(locals.storageSlots);
        locals.gas = gasleft();
        return locals;
    }

    /**
     * @dev internal function for engine communication. We use it to reduce contract size.
     *  Should be called after the code of a function.
     * @param num function identifier
     * @param isExternalCall set to true if this was called externally
     *  or a 'public' function from another address
     */
    function _sphereXValidatePost(
        int256 num,
        bool isExternalCall,
        ModifierLocals memory locals
    ) private sphereXGuardInternal(0xe3fa5663) returnsIfNotActivated {
        uint256 gas = locals.gas - gasleft();

        ISphereXEngine sphereXEngine = _sphereXEngine();

        bytes32[] memory valuesAfter;
        valuesAfter = _readStorage(locals.storageSlots);

        if (isExternalCall) {
            sphereXEngine.sphereXValidatePost(num, gas, locals.valuesBefore, valuesAfter);
        } else {
            sphereXEngine.sphereXValidateInternalPost(num, gas, locals.valuesBefore, valuesAfter);
        }
    }

    /**
     * @dev internal function for engine communication. We use it to reduce contract size.
     *  Should be called before the code of a function.
     * @param num function identifier
     * @return locals ModifierLocals
     */
    function _sphereXValidateInternalPre(
        int256 num
    ) internal sphereXGuardInternal(0x56f42621) returnsIfNotActivated returns (ModifierLocals memory locals) {
        locals.storageSlots = _sphereXEngine().sphereXValidateInternalPre(num);
        locals.valuesBefore = _readStorage(locals.storageSlots);
        locals.gas = gasleft();
        return locals;
    }

    /**
     * @dev internal function for engine communication. We use it to reduce contract size.
     *  Should be called after the code of a function.
     * @param num function identifier
     * @param locals ModifierLocals
     */
    function _sphereXValidateInternalPost(int256 num, ModifierLocals memory locals) internal sphereXGuardInternal(0xf92853af) returnsIfNotActivated {
        bytes32[] memory valuesAfter;
        valuesAfter = _readStorage(locals.storageSlots);
        _sphereXEngine().sphereXValidateInternalPost(num, locals.gas - gasleft(), locals.valuesBefore, valuesAfter);
    }

    /**
     *  @dev Modifier to be incorporated in all internal protected non-view functions
     */
    modifier sphereXGuardInternal(int256 num) {
        ModifierLocals memory locals = _sphereXValidateInternalPre(num);
        _;
        _sphereXValidateInternalPost(-num, locals);
    }

    /**
     *  @dev Modifier to be incorporated in all external protected non-view functions
     */
    modifier sphereXGuardExternal(int256 num) {
        ModifierLocals memory locals = _sphereXValidatePre(num, true);
        _;
        _sphereXValidatePost(-num, true, locals);
    }

    /**
     *  @dev Modifier to be incorporated in all public protected non-view functions
     */
    modifier sphereXGuardPublic(int256 num, bytes4 selector) {
        ModifierLocals memory locals = _sphereXValidatePre(num, msg.sig == selector);
        _;
        _sphereXValidatePost(-num, msg.sig == selector, locals);
    }

    // ============ Internal Storage logic ============

    /**
     * Internal function that reads values from given storage slots and returns them
     * @param storageSlots list of storage slots to read
     * @return list of values read from the various storage slots
     */
    function _readStorage(bytes32[] memory storageSlots) internal view returns (bytes32[] memory) {
        uint256 arrayLength = storageSlots.length;
        bytes32[] memory values = new bytes32[](arrayLength);
        // create the return array data

        for (uint256 i = 0; i < arrayLength; i++) {
            bytes32 slot = storageSlots[i];
            bytes32 temp_value;
            // solhint-disable-next-line no-inline-assembly
            // slither-disable-next-line assembly
            assembly {
                temp_value := sload(slot)
            }

            values[i] = temp_value;
        }
        return values;
    }
 
    // INITIALIZERS.
    function governanceRolesInitialized() internal view returns (bool) {
        return AccessControl.getRoleAdmin(GOVERNANCE_ADMIN) != bytes32(0x00);
    }

    function securityRolesInitialized() internal view returns (bool) {
        return AccessControl.getRoleAdmin(SECURITY_ADMIN) != bytes32(0x00);
    }

    function initialize() internal sphereXGuardInternal(0x43ad7fbd) {
        address provisional = AccessControl._msgSender();
        initialize(provisional, provisional);
    }

    function initialize(address provisionalGovernor, address provisionalSecAdmin) internal sphereXGuardInternal(0x8fb3cdbe) {
        initialize(provisionalGovernor, provisionalSecAdmin, false);
    }

    function initialize(
        address provisionalGovernor,
        address provisionalSecAdmin,
        bool subGovernors
    ) internal sphereXGuardInternal(0xe649984b) {
        if (governanceRolesInitialized()) {
            // Support Proxied contract initialization.
            // In case the Proxy already initialized the roles,
            // init will succeed IFF the provisionalGovernor is already `GovernanceAdmin`.
            require(
                AccessControl.hasRole(GOVERNANCE_ADMIN, provisionalGovernor),
                "ROLES_ALREADY_INITIALIZED"
            );
        } else {
            initGovernanceRoles(provisionalGovernor, subGovernors);
        }

        if (securityRolesInitialized()) {
            // If SecurityAdmin initialized,
            // then provisionalSecAdmin must already be a `SecurityAdmin`.
            // If it's not initilized - initialize it.
            require(
                AccessControl.hasRole(SECURITY_ADMIN, provisionalSecAdmin),
                "SECURITY_ROLES_ALREADY_INITIALIZED"
            );
        } else {
            initSecurityRoles(provisionalSecAdmin);
        }
    }

    function initSecurityRoles(address provisionalSecAdmin) private sphereXGuardInternal(0xa17ede9f) {
        AccessControl._setRoleAdmin(SECURITY_ADMIN, SECURITY_ADMIN);
        AccessControl._setRoleAdmin(SECURITY_AGENT, SECURITY_ADMIN);
        AccessControl._grantRole(SECURITY_ADMIN, provisionalSecAdmin);
    }

    function initGovernanceRoles(address provisionalGovernor, bool subGovernors) private sphereXGuardInternal(0x3aef04c3) {
        AccessControl._grantRole(GOVERNANCE_ADMIN, provisionalGovernor);
        AccessControl._setRoleAdmin(APP_GOVERNOR, APP_ROLE_ADMIN);
        AccessControl._setRoleAdmin(APP_ROLE_ADMIN, GOVERNANCE_ADMIN);
        AccessControl._setRoleAdmin(GOVERNANCE_ADMIN, GOVERNANCE_ADMIN);
        AccessControl._setRoleAdmin(OPERATOR, APP_ROLE_ADMIN);
        AccessControl._setRoleAdmin(TOKEN_ADMIN, APP_ROLE_ADMIN);
        AccessControl._setRoleAdmin(UPGRADE_GOVERNOR, GOVERNANCE_ADMIN);
        if (subGovernors) {
            AccessControl._grantRole(APP_ROLE_ADMIN, provisionalGovernor);
            AccessControl._grantRole(GOVERNANCE_ADMIN, provisionalGovernor);
            AccessControl._grantRole(UPGRADE_GOVERNOR, provisionalGovernor);
        }
    }
}
