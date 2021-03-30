pragma solidity ^0.5.12;

import "./Owned.sol";
import "./EndorsementStore.sol";

/// @title Verifier
/// @notice Reference implementation of a verifier for a TLS certificate-based authentication framework
/// @dev Reference implementation of a verifier for a TLS certificate-based authentication framework
contract Verifier is Owned {
	/// @notice Pointer to the EndorsementDatabase referred to for decisions
	EndorsementDatabase es;
	/// @notice Index of the trusted root store in EndorsementDatabase which is referred to for decisions
	uint256 endorsementRootStore;

	constructor (address endorsementStore, uint256 rootStore) public{
		es = EndorsementDatabase(endorsementStore);
		endorsementRootStore = rootStore;
	}

	/// @notice Set the EndorsementDatabase contract and index of trusted root store
	/// @dev Set the EndorsementDatabase contract and index of trusted root store
	/// @param endorsementStore Address of the EndorsementDatabase contract
	/// @param rootStore Index of the root store
	function setEndorsementDatabase(address endorsementStore, uint256 rootStore) public onlyOwner{
		es = EndorsementDatabase(endorsementStore);
		endorsementRootStore = rootStore;
	}
}
