// SPDX-License-Identifier: Apache-2.0.
pragma solidity 0.8.24;

import "starkware/solidity/libraries/NamedStorage8.sol";
import "starkware/solidity/stake/RewardSupplierExternalInterfaces.sol"; 
import {SphereXProtected} from "@spherex-xyz/contracts/src/SphereXProtected.sol";
 

abstract contract RewardSupplierStorage is SphereXProtected {
    // Named storage slot tags.

    // L1 contract addresses.
    // The bridge contract address.
    string internal constant BRIDGE_TAG = "REWARD_SUPPLIER_BRIDGE_CONTRACT_SLOT_TAG";
    // The token contract address.
    string internal constant TOKEN_TAG = "REWARD_SUPPLIER_TOKEN_SLOT_TAG";
    // The mint manager contract address. this contract is responsible for minting the tokens.
    string internal constant MINT_MANAGER_TAG = "REWARD_SUPPLIER_MINT_MANAGER_SLOT_TAG";
    // Starknet messaging contract address.
    string internal constant MESSAGING_CONTRACT_TAG = "REWARD_SUPPLIER_MESSAGING_CONTRACT_SLOT_TAG";

    // L2 contract addresses.
    // The address from which reward requests are received.
    string internal constant L2_MINT_REQUEST_SOURCE_TAG =
        "REWARD_SUPPLIER_L2_MINT_REQUEST_SOURCE_SLOT_TAG";
    // The contract address that receives the minted reward tokens.
    string internal constant L2_MINT_DESTINATION_TAG =
        "REWARD_SUPPLIER_L2_MINT_DESTINATION_SLOT_TAG";
    // The contract address that determines the minting curve.
    string internal constant L2_MINTING_CURVE_TAG = "REWARD_SUPPLIER_L2_MINTING_CURVE_SLOT_TAG";

    // Storage Getters.
    function bridge() internal view returns (IBridge) {
        return IBridge(NamedStorage.getAddressValue(BRIDGE_TAG));
    }

    function token() internal view returns (address) {
        return NamedStorage.getAddressValue(TOKEN_TAG);
    }

    function mintManager() internal view returns (IMintManager) {
        return IMintManager(NamedStorage.getAddressValue(MINT_MANAGER_TAG));
    }

    function messagingContract() internal view returns (IStarknetMessaging) {
        return IStarknetMessaging(NamedStorage.getAddressValue(MESSAGING_CONTRACT_TAG));
    }

    function mintRequestSource() internal view returns (uint256) {
        return NamedStorage.getUintValue(L2_MINT_REQUEST_SOURCE_TAG);
    }

    function mintDestination() internal view returns (uint256) {
        return NamedStorage.getUintValue(L2_MINT_DESTINATION_TAG);
    }

    function mintingCurve() internal view returns (uint256) {
        return NamedStorage.getUintValue(L2_MINTING_CURVE_TAG);
    }

    // Storage Setters.
    function setBridge(address contract_) internal sphereXGuardInternal(0x112fdc29) {
        NamedStorage.setAddressValueOnce(BRIDGE_TAG, contract_);
    }

    function setToken(address token_) internal sphereXGuardInternal(0x453f88e4) {
        NamedStorage.setAddressValueOnce(TOKEN_TAG, token_);
    }

    function setMintManager(address mintManager_) internal sphereXGuardInternal(0xa6b82faf) {
        NamedStorage.setAddressValueOnce(MINT_MANAGER_TAG, mintManager_);
    }

    function setMessagingContract(address contract_) internal sphereXGuardInternal(0x34bf90f1) {
        NamedStorage.setAddressValueOnce(MESSAGING_CONTRACT_TAG, contract_);
    }

    function setMintRequestSource(uint256 _mintRequestSource) internal sphereXGuardInternal(0xdccca6bc) {
        NamedStorage.setUintValueOnce(L2_MINT_REQUEST_SOURCE_TAG, _mintRequestSource);
    }

    function setMintDestination(uint256 mintDestination_) internal sphereXGuardInternal(0xf4da3a38) {
        NamedStorage.setUintValueOnce(L2_MINT_DESTINATION_TAG, mintDestination_);
    }

    function setMintingCurve(uint256 mintingCurve_) internal sphereXGuardInternal(0xe4852917) {
        NamedStorage.setUintValueOnce(L2_MINTING_CURVE_TAG, mintingCurve_);
    }
}
