pragma solidity ^0.5.12;

import "./Owned.sol";
import "./EndorsementStore.sol";

/// @title InternallyEndorsed
/// @notice Internally endorsed contract
/// @dev Internally endorsed contract
contract InternallyEndorsed is Owned {
	//endorsement information fields
	/// @notice Signature of the current endorsement
	bytes private signature;
	/// @notice Domain name of the current endorsement
	string private domain;
	/// @notice Identifier of the certificate used to create and validate the endorsement
	bytes32 private certID;
	/// @notice Expiration date of the endorsement
	uint256 private expiration;
	/// @notice Mapping containing all certificate identifiers that were used for endosrements
	mapping (bytes32 => bool) private allCertIDs;
	/// @notice Mapping containing all endorsement combinations that were revoked
	mapping (string => mapping(bytes32 => mapping (uint256 => bool))) private revoked;

	/// @notice Link to an endorsement database for the validation of revocations
	EndorsementDatabase private ed;


	/// @dev Deploy an instance of InternallyEndorsed referencing an endorsement database.
	/// @param endorsementDatabase The address of the endorsement database
	constructor (address endorsementDatabase) public{
		ed = EndorsementDatabase(endorsementDatabase);
	}

	/// @notice Can be used by the owner of the contract to update the endorsement
	/// @dev Owner can update the endorsement information, signature is NOT validated
	/// @param _signature Signature of the new endorsement
	/// @param _domain Domain name of the new endorsement
	/// @param _certID Certificate identifer of the new endorsement
	/// @param _expiration Expiration date of the new endorsement
	function updateEndorsement(bytes memory _signature, string memory _domain, bytes32 _certID, uint256 _expiration) public onlyOwner{
		signature = _signature;
		domain = _domain;
		certID = _certID;
		expiration = _expiration;
		allCertIDs[certID] = true;
	}

	/// @notice Revoke an endorsment previously or currently used to endorse the contract
	/// @dev Anyone can mark an endorsment as revoked when they posses a private key corresponding to a certID contained in 'allCertIDs'
	/// @dev 'es' is used to validate the revocation
	/// @param _signature Signature of the revocation
	/// @param _domain Domain name of the endorsement
	/// @param _certID Certificate identifier of the endorsement
	/// @param _expiration Expiration date of the endorsement
	function revokeEndorsement(bytes memory _signature, string memory _domain, bytes32 _certID, uint256 _expiration) public {
		if (allCertIDs[certID]){
			if (ed.verifyInternalEndorsementRevocation(toBytes(address(this)), _domain, _certID, _expiration, _signature)){
				revoked[_domain][_certID][_expiration] = true;
			}
		}
	}

	/// @notice Get the endorsement information of the contract
	/// @dev Get the content of the expiration information fields
	/// @return signature, domain name, certificate identifer, expiration date
	function getEndorsement() public view returns (bytes memory, string memory, bytes32, uint256) {
		return (signature, domain, certID, expiration);
	}

	/// @notice Get the revocation status of an arbitrary endorsement combination
	/// @dev Get the revocation status of the endorsement dentoted by '_domain', '_certID', '_expiration'
	/// @param _domain Domain name of the checked endorsement
	/// @param _certID Certificate identifer of the checked endorsment
	/// @param _expiration Expiration date of the checked endorsement
	/// @return true if revoked, false if not revoked or unknown
	function getRevokedStatus(string memory _domain, bytes32 _certID, uint256 _expiration) public view returns (bool) {
		return revoked[_domain][_certID][_expiration];
	}

	/// @notice Get the revocation status of the current endorsement
	/// @dev Get the revocation status of the combination of the current endorsement information fields
	/// @return True if revoked, false otherwise
	function getCurrentRevoked() public view returns (bool) {
		return revoked[domain][certID][expiration];
	}

	/// @notice
	/// @dev Get the bytes representation of an address
	/// @param a address to be converted
	/// @return address representation in bytes
	function toBytes(address a) private pure returns (bytes memory b){
	    assembly {
	        let m := mload(0x40)
	        a := and(a, 0xFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFF)
	        mstore(add(m, 20), xor(0x140000000000000000000000000000000000000000, a))
	        mstore(0x40, add(m, 52))
	        b := m
   		}
	}

}
