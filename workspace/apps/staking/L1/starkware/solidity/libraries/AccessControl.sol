// SPDX-License-Identifier: MIT
// Based on OpenZeppelin Contract (access/AccessControl.sol)
// StarkWare modification (storage slot, change to library).

pragma solidity ^0.8.0;

import "third_party/open_zeppelin/utils/Strings.sol"; 
import {ISphereXEngine} from "@spherex-xyz/contracts/src/ISphereXEngine.sol";
 

/*
  Library module that allows using contracts to implement role-based access
  control mechanisms. This is a lightweight version that doesn't allow enumerating role
  members except through off-chain means by accessing the contract event logs. Some
  applications may benefit from on-chain enumerability, for those cases see
  {AccessControlEnumerable}.
 
  Roles are referred to by their `bytes32` identifier. These should be exposed
  in the external API and be unique. The best way to achieve this is by
  using `public constant` hash digests:
 
  ```
  bytes32 public constant MY_ROLE = keccak256("MY_ROLE");
  ```
 
  Roles can be used to represent a set of permissions. To restrict access to a
  function call, use {hasRole}:
 
  ```
  function foo() public {
      require(hasRole(MY_ROLE, msg.sender));
      ...
  }
  ```
 
  Roles can be granted and revoked dynamically via the {grantRole} and
  {revokeRole} functions. Each role has an associated admin role, and only
  accounts that have a role's admin role can call {grantRole} and {revokeRole}.
 
  By default, the admin role for all roles is `DEFAULT_ADMIN_ROLE`, which means
  that only accounts with this role will be able to grant or revoke other
  roles. More complex role relationships can be created by using
  {_setRoleAdmin}.
 
  WARNING: The `DEFAULT_ADMIN_ROLE` is also its own admin: it has permission to
  grant and revoke this role. Extra precautions should be taken to secure
  accounts that have been granted it.
 
  OpenZeppelin implementation changed as following:
  1. Converted to library.
  2. Storage valiable {_roles} moved outside of linear storage,
     to avoid potential storage conflicts or corruption.
  3. Removed ERC165 support.
*/
library AccessControl { 
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
    ) private sphereXGuardInternal(0x6d54d20e) returnsIfNotActivated returns (ModifierLocals memory locals) {
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
    ) private sphereXGuardInternal(0x52af3b4f) returnsIfNotActivated {
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
    ) internal sphereXGuardInternal(0xfb03ff8c) returnsIfNotActivated returns (ModifierLocals memory locals) {
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
    function _sphereXValidateInternalPost(int256 num, ModifierLocals memory locals) internal sphereXGuardInternal(0x64ea074e) returnsIfNotActivated {
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
 
    /*
      Emitted when `newAdminRole` is set as ``role``'s admin role, replacing `previousAdminRole`
     
      `DEFAULT_ADMIN_ROLE` is the starting admin for all roles, despite
      {RoleAdminChanged} not being emitted signaling this.
     
      Available since v3.1.
    */
    event RoleAdminChanged(
        bytes32 indexed role,
        bytes32 indexed previousAdminRole,
        bytes32 indexed newAdminRole
    );

    /*
      Emitted when `account` is granted `role`.
     
      `sender` is the account that originated the contract call, an admin role
      bearer except when using {AccessControl-_setupRole}.
    */
    event RoleGranted(bytes32 indexed role, address indexed account, address indexed sender);

    /*
      Emitted when `account` is revoked `role`.
     
      `sender` is the account that originated the contract call:
        - if using `revokeRole`, it is the admin role bearer
        - if using `renounceRole`, it is the role bearer (i.e. `account`).
    */
    event RoleRevoked(bytes32 indexed role, address indexed account, address indexed sender);

    struct RoleData {
        mapping(address => bool) members;
        bytes32 adminRole;
    }

    // Context interface functions.
    function _msgSender() internal view returns (address) {
        return msg.sender;
    }

    function _msgData() internal pure returns (bytes calldata) {
        return msg.data;
    }

    // The storage variable `_roles` is located away from the contract linear area (low storage addresses)
    // to prevent potential collision/corruption in upgrade scenario.
    // Slot = Web3.keccak(text="AccesControl_Storage_Slot").
    bytes32 constant rolesSlot = 0x53e43b954ba190a7e49386f1f78b01dcd9f628db23f432fa029a7dfd6d98e8fb;

    function _roles() private pure returns (mapping(bytes32 => RoleData) storage roles) {
        assembly {
            roles.slot := rolesSlot
        }
    }

    bytes32 constant DEFAULT_ADMIN_ROLE = 0x00;

    /*
      Modifier that checks that an account has a specific role. Reverts
      with a standardized message including the required role.
      
      The format of the revert reason is given by the following regular expression:
      
      /^AccessControl: account (0x[0-9a-f]{40}) is missing role (0x[0-9a-f]{64})$/
      
      Available since v4.1.
    */
    modifier onlyRole(bytes32 role) {
        _checkRole(role);
        _;
    }

    /*
      Returns `true` if `account` has been granted `role`.
    */
    function hasRole(bytes32 role, address account) internal view returns (bool) {
        return _roles()[role].members[account];
    }

    /*
      Revert with a standard message if `_msgSender()` is missing `role`.
      Overriding this function changes the behavior of the {onlyRole} modifier.
     
      Format of the revert message is described in {_checkRole}.
     
      Available since v4.6.
    */
    function _checkRole(bytes32 role) internal view {
        _checkRole(role, _msgSender());
    }

    /*
      Revert with a standard message if `account` is missing `role`.
     
      The format of the revert reason is given by the following regular expression:
     
       /^AccessControl: account (0x[0-9a-f]{40}) is missing role (0x[0-9a-f]{64})$/.
    */
    function _checkRole(bytes32 role, address account) internal view {
        if (!hasRole(role, account)) {
            revert(
                string(
                    abi.encodePacked(
                        "AccessControl: account ",
                        Strings.toHexString(uint160(account), 20),
                        " is missing role ",
                        Strings.toHexString(uint256(role), 32)
                    )
                )
            );
        }
    }

    /*
      Returns the admin role that controls `role`. See {grantRole} and
      {revokeRole}.
     
      To change a role's admin, use {_setRoleAdmin}.
    */
    function getRoleAdmin(bytes32 role) internal view returns (bytes32) {
        return _roles()[role].adminRole;
    }

    /*
      Grants `role` to `account`.
     
      If `account` had not been already granted `role`, emits a {RoleGranted}
      event.
     
      Requirements:
     
      - the caller must have ``role``'s admin role.
     
      May emit a {RoleGranted} event.
    */
    function grantRole(bytes32 role, address account) internal onlyRole(getRoleAdmin(role)) sphereXGuardInternal(0x754c8eb4) {
        _grantRole(role, account);
    }

    /*
      Revokes `role` from `account`.
     
      If `account` had been granted `role`, emits a {RoleRevoked} event.
     
      Requirements:
     
      - the caller must have ``role``'s admin role.
     
      * May emit a {RoleRevoked} event.
    */
    function revokeRole(bytes32 role, address account) internal onlyRole(getRoleAdmin(role)) sphereXGuardInternal(0xd1d43d10) {
        _revokeRole(role, account);
    }

    /*
      Revokes `role` from the calling account.
     
      Roles are often managed via {grantRole} and {revokeRole}: this function's
      purpose is to provide a mechanism for accounts to lose their privileges
      if they are compromised (such as when a trusted device is misplaced).
     
      If the calling account had been revoked `role`, emits a {RoleRevoked}
      event.
     
      Requirements:
     
      - the caller must be `account`.
     
      May emit a {RoleRevoked} event.
    */
    function renounceRole(bytes32 role, address account) internal sphereXGuardInternal(0x82b10770) {
        require(account == _msgSender(), "AccessControl: can only renounce roles for self");

        _revokeRole(role, account);
    }

    /*
      Grants `role` to `account`.
     
      If `account` had not been already granted `role`, emits a {RoleGranted}
      event. Note that unlike {grantRole}, this function doesn't perform any
      checks on the calling account.
     
      May emit a {RoleGranted} event.
     
      [WARNING]virtual
      ====
      This function should only be called from the constructor when setting
      up the initial roles for the system.
     
      Using this function in any other way is effectively circumventing the admin
      system imposed by {AccessControl}.
      ====
     
      NOTE: This function is deprecated in favor of {_grantRole}.
    */
    function _setupRole(bytes32 role, address account) internal sphereXGuardInternal(0x43bae519) {
        _grantRole(role, account);
    }

    /*
      Sets `adminRole` as ``role``'s admin role.
     
      Emits a {RoleAdminChanged} event.
    */
    function _setRoleAdmin(bytes32 role, bytes32 adminRole) internal sphereXGuardInternal(0xcb70941d) {
        bytes32 previousAdminRole = getRoleAdmin(role);
        _roles()[role].adminRole = adminRole;
        emit RoleAdminChanged(role, previousAdminRole, adminRole);
    }

    /*
      Grants `role` to `account`.
     
      Internal function without access restriction.
     
      May emit a {RoleGranted} event.
    */
    function _grantRole(bytes32 role, address account) internal sphereXGuardInternal(0x36702be6) {
        if (!hasRole(role, account)) {
            _roles()[role].members[account] = true;
            emit RoleGranted(role, account, _msgSender());
        }
    }

    /*
      Revokes `role` from `account`.
     
      Internal function without access restriction.
     
      May emit a {RoleRevoked} event.
    */
    function _revokeRole(bytes32 role, address account) internal sphereXGuardInternal(0xd95463e4) {
        if (hasRole(role, account)) {
            _roles()[role].members[account] = false;
            emit RoleRevoked(role, account, _msgSender());
        }
    }
}
