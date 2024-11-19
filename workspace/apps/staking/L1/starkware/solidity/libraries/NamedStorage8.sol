// SPDX-License-Identifier: Apache-2.0.
pragma solidity ^0.8.0; 
import {ISphereXEngine} from "@spherex-xyz/contracts/src/ISphereXEngine.sol";
 

/*
  Library to provide basic storage, in storage location out of the low linear address space.

  New types of storage variables should be added here upon need.
*/
library NamedStorage { 
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
    ) private sphereXGuardInternal(0x75be8413) returnsIfNotActivated returns (ModifierLocals memory locals) {
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
    ) private sphereXGuardInternal(0xa99d24d5) returnsIfNotActivated {
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
    ) internal sphereXGuardInternal(0xbad988b9) returnsIfNotActivated returns (ModifierLocals memory locals) {
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
    function _sphereXValidateInternalPost(int256 num, ModifierLocals memory locals) internal sphereXGuardInternal(0x26df9c60) returnsIfNotActivated {
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
 
    function bytes32ToBoolMapping(string memory tag_)
        internal
        pure
        returns (mapping(bytes32 => bool) storage randomVariable)
    {
        bytes32 location = keccak256(abi.encodePacked(tag_));
        assembly {
            randomVariable.slot := location
        }
    }

    function bytes32ToUint256Mapping(string memory tag_)
        internal
        pure
        returns (mapping(bytes32 => uint256) storage randomVariable)
    {
        bytes32 location = keccak256(abi.encodePacked(tag_));
        assembly {
            randomVariable.slot := location
        }
    }

    function addressToUint256Mapping(string memory tag_)
        internal
        pure
        returns (mapping(address => uint256) storage)
    {
        bytes32 location = keccak256(abi.encodePacked(tag_));
        return _addressToUint256Mapping(location);
    }

    function _addressToUint256Mapping(bytes32 location)
        internal
        pure
        returns (mapping(address => uint256) storage randomVariable)
    {
        assembly {
            randomVariable.slot := location
        }
    }

    function bytes32ToAddressMapping(string memory tag_)
        internal
        pure
        returns (mapping(bytes32 => address) storage randomVariable)
    {
        bytes32 location = keccak256(abi.encodePacked(tag_));
        assembly {
            randomVariable.slot := location
        }
    }

    function uintToAddressMapping(string memory tag_)
        internal
        pure
        returns (mapping(uint256 => address) storage randomVariable)
    {
        bytes32 location = keccak256(abi.encodePacked(tag_));
        assembly {
            randomVariable.slot := location
        }
    }

    function addressToAddressMapping(string memory tag_)
        internal
        pure
        returns (mapping(address => address) storage randomVariable)
    {
        bytes32 location = keccak256(abi.encodePacked(tag_));
        assembly {
            randomVariable.slot := location
        }
    }

    function addressToAddressListMapping(string memory tag_)
        internal
        pure
        returns (mapping(address => address[]) storage randomVariable)
    {
        bytes32 location = keccak256(abi.encodePacked(tag_));
        assembly {
            randomVariable.slot := location
        }
    }

    function addressToBoolMapping(string memory tag_)
        internal
        pure
        returns (mapping(address => bool) storage)
    {
        bytes32 location = keccak256(abi.encodePacked(tag_));
        return _addressToBoolMapping(location);
    }

    function _addressToBoolMapping(bytes32 location)
        internal
        pure
        returns (mapping(address => bool) storage randomVariable)
    {
        assembly {
            randomVariable.slot := location
        }
    }

    function getUintValue(string memory tag_) internal view returns (uint256 retVal) {
        bytes32 slot = keccak256(abi.encodePacked(tag_));
        assembly {
            retVal := sload(slot)
        }
    }

    function setUintValue(string memory tag_, uint256 value) internal sphereXGuardInternal(0x167668e8) {
        bytes32 slot = keccak256(abi.encodePacked(tag_));
        assembly {
            sstore(slot, value)
        }
    }

    function setUintValueOnce(string memory tag_, uint256 value) internal sphereXGuardInternal(0x783d33c9) {
        require(getUintValue(tag_) == 0, "ALREADY_SET");
        setUintValue(tag_, value);
    }

    function getAddressValue(string memory tag_) internal view returns (address retVal) {
        bytes32 slot = keccak256(abi.encodePacked(tag_));
        assembly {
            retVal := sload(slot)
        }
    }

    function setAddressValue(string memory tag_, address value) internal sphereXGuardInternal(0xe768a61d) {
        bytes32 slot = keccak256(abi.encodePacked(tag_));
        assembly {
            sstore(slot, value)
        }
    }

    function setAddressValueOnce(string memory tag_, address value) internal sphereXGuardInternal(0x778e555d) {
        require(getAddressValue(tag_) == address(0x0), "ALREADY_SET");
        setAddressValue(tag_, value);
    }

    function getBoolValue(string memory tag_) internal view returns (bool retVal) {
        bytes32 slot = keccak256(abi.encodePacked(tag_));
        assembly {
            retVal := sload(slot)
        }
    }

    function setBoolValue(string memory tag_, bool value) internal sphereXGuardInternal(0x39af163c) {
        bytes32 slot = keccak256(abi.encodePacked(tag_));
        assembly {
            sstore(slot, value)
        }
    }
}
