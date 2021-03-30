pragma solidity ^0.5.12;

import "./RSAVerify.sol";
import "./ASN1DERNode.sol";
import "./BytesUtils.sol";
import "./SHA1.sol";


/// @title SignatureValidation
/// @notice Library for signature validation
/// @dev Library implementing the signature validation with ASN.1 DER public keys
library SignatureValidation {
	using BytesUtils for *;
	using ASN1Parser for *;

	/// @notice Validate the signature of a message produced with any supported signature algorithm
	/// @dev The correct signature algorithm is retrieved and, if supported, the signature is verified
	/// @param message Bytes string that was hashed and signed
	/// @param sigInfo Description of the signature algorithm used
	/// @param signature Signature to be validated
	/// @param signerPubKey Public key used to create the signature
	/// @return true if validation was successful and signature is valid, false otherwise
	function validateSignature(bytes memory message, bytes memory sigInfo, bytes memory signature, bytes memory signerPubKey) public view returns (bool){
        bytes memory oid = ((sigInfo.getRootNode()).getFirstChildNode(sigInfo)).getContentBytes(sigInfo);
        if (oid.equals(hex"2a864886f70d010105")){ //RSA-SHA1
            return validateRSASHA1Signature(message, signature, signerPubKey);
        } else if (oid.equals(hex"2a864886f70d01010b")) { //RSA-SHA256
            return validateRSASHA256Signature(message, signature, signerPubKey);
        } else if (oid.equals(hex"2A8648CE3D040302")) { //ECDSA-SHA256
            revert("Unsupported signature algorithm: ECDSA-SHA256.");
        } else if (oid.equals(hex"2A8648CE3D040303")) { //ECDSA-SHA384
            revert("Unsupported signature algorithm: ECDSA-SHA384.");
        } else if (oid.equals(hex"2A8648CE3D040304")) { //ECDSA-SHA512
            revert("Unsupported signature algorithm: ECDSA-SHA512.");
        } else if (oid.equals(hex"2A864886F70D01010C")) { //sha384WithRSAEncryption
            revert("Unsupported signature algorithm: RSA-SHA384.");
        } else if (oid.equals(hex"2A864886F70D01010D")) { //sha512WithRSAEncryption
            revert("Unsupported signature algorithm: RSA-SHA512.");
        } else {
            revert("Unsupported signature algorithm: OID unkown.");
        }
    }


    /// @notice Validate the signature of a message produced with RSA-SHA-1
    /// @dev Parses publix key, hashes message, and validates signature
    /// @param message Bytes string that was hashed and signed
    /// @param signature Signature to be validated
    /// @param signerPubKey Public key used to create the signature
    /// @return true if validation was successful and signature is valid, false otherwise
    function validateRSASHA1Signature(bytes memory message, bytes memory signature, bytes memory signerPubKey) public view returns (bool){
        bool success = false;

				// get the exponent and the modulus of the private key
        ASN1Parser.Node memory curNode = signerPubKey.getRootNode().getFirstChildNode(signerPubKey);
        curNode = curNode.getNextNode(signerPubKey);
        curNode = curNode.getFirstChildNode(signerPubKey);
        curNode = curNode.getFirstChildNode(signerPubKey);
        bytes memory modulus = curNode.getContentBytes(signerPubKey);
        curNode = curNode.getNextNode(signerPubKey);
        bytes memory exponent = curNode.getContentBytes(signerPubKey);

				//hash 'message' with SHA-1 and validate the signature
        bytes20 hash = SHA1.sha1(message);
        bytes memory result;
        (success, result) = RSAVerify.rsarecover(modulus, exponent, signature);
        for (uint i = 0; i < 20; i++){
        	if(hash[i] != result[result.length-20 + i]){
        		return false;
        	}
        }
        return success;
    }


    /// @notice Validate the signature of a message produced with RSA-SHA-256
		/// @dev Parses publix key, hashes message, and validates signature
    /// @param message Bytes string that was hashed and signed
    /// @param signature Signature to be validated
    /// @param signerPubKey Public key used to create the signature
    /// @return true if validation was successful and signature is valid, false otherwise
    function validateRSASHA256Signature(bytes memory message, bytes memory signature, bytes memory signerPubKey) public view returns (bool){
        bool success = false;

				// get the exponent and the modulus of the private key
        ASN1Parser.Node memory curNode = signerPubKey.getRootNode().getFirstChildNode(signerPubKey);
        curNode = curNode.getNextNode(signerPubKey);
        curNode = curNode.getFirstChildNode(signerPubKey);
        curNode = curNode.getFirstChildNode(signerPubKey);
        bytes memory modulus = curNode.getContentBytes(signerPubKey);
        curNode = curNode.getNextNode(signerPubKey);
        bytes memory exponent = curNode.getContentBytes(signerPubKey);

				//hash 'message' with SHA-256 and validate the signature
        bytes32 hash = sha256(message);
        bytes memory result;
        (success, result) = RSAVerify.rsarecover(modulus, exponent, signature);

        return success && hash == result.readBytes32(result.length - 32);
    }
}
