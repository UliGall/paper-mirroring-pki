pragma solidity ^0.5.12;

import "./BytesUtils.sol";
import "./X509Certificate.sol";

/// @title CertificateStore
/// @dev Database for the validation, storage, and maintanence of TLS certificates
contract CertificateStore {

	event CertificateAdded(bytes32 fingerprint);
	event SelfSignedCertificateAdded(bytes32 fingerprint, uint256 rootIndex);
	event CertificateUpdated(bytes32 certID, uint256 expiration);
	event CertificateRevoked(bytes32 certID);
	event rootRemovedFromStore(uint256 storeIndex, bytes32 fingerprint);
	event rootAddedtoStore(uint256 storeIndex, bytes32 fingerprint);

	/// @notice All certificates stored in the database, includiing self-signed
	mapping (bytes32 => X509Parser.X509certificate) private certificates;

	/// @notice All self-signed certificates stored in the database
	mapping (uint256 => bytes32) private trustAnchors;
	/// @notice Number of self-signed certificates stored
	uint256 rootCounter = 0;

	/// @notice Submit a self-signed certificate to the database
	/// @dev Parses and validates the provided DER, stores certificate if valid
	/// @param der ASN.1 document in DER format
	function addSelfsignedCertificate(bytes memory der) public {
		require(rootCounter < (2^256) -1, "Trust anchor memory is full");
		bytes32 fingerprint = getFingerprint(der);
		require (certificates[fingerprint].version == 0, "Certifcate position already taken");

		//validate the certificate and get its X509certificate representation
		X509Parser.X509certificate memory cert = X509Parser.parseAndValidateSelfSignedCertificate(der);

		//store the certificate
		X509Parser.X509certificate storage storeCert = certificates[fingerprint];
		storeCertificate(storeCert, cert, fingerprint);
		trustAnchors[rootCounter] = fingerprint;
		rootCounter++;

		emit SelfSignedCertificateAdded(fingerprint, rootCounter);
	}

	/// @notice Submit a certificate signed by a certificate already stored
	/// @dev Retrieves issuer, parses and validates cert, stores cert if valid
	/// @param der ASN.1 document in DER format
	/// @param issuerID The SHA-256 hash of an issuing certificate already stored
	function addCertificate(bytes memory der,  bytes32 issuerID) public {
		require (certExists(issuerID), "Issuer certificate not available.");
		//check certID is fresh
		bytes32 fingerprint = getFingerprint(der);
		require (certificates[fingerprint].version == 0, "Certifcate position already taken");

		//retrieve issuer information
		X509Parser.X509certificate memory issuer = certificates[issuerID];

		//get pubKey and name of issuer
		bytes memory issuerKey = issuer.publicKey;
		bytes memory issuerName = issuer.name;
		require(issuer.cA && issuer.pathLen >= 0,
			"Issuer certificate isn't CA certificate or its allowed path length is not enough.");

		//parse and validate the new cert
		X509Parser.X509certificate memory cert = X509Parser.parseAndValidateDERCertificate(der, issuerName, issuerKey);
		if (cert.pathLen >= issuer.pathLen){
			cert.pathLen = issuer.pathLen - 1;
		}

		//store the new cert
		X509Parser.X509certificate storage storeCert = certificates[fingerprint];
		storeCertificate(storeCert, cert, issuerID);

		emit CertificateAdded(fingerprint);
	}

	/// @notice Submit an OCSP response to update the revocation status of a certificate
	/// @dev Parses and validates OCSP response, updates 'ocsp_status' of certificate if appropriate
	/// @param certID SHA-256 hash of the certificate concerned
	/// @param ocsp OCSP response in DER representation
	function refreshCertificateOCSP(bytes32 certID, bytes memory ocsp) public {
		X509Parser.X509certificate memory cert = certificates[certID];
		//status can only be updated if cert is not revoked
		if (cert.ocsp_status != 1){
			//parse and validate OCSP response
			X509Parser.X509certificate memory issuer = certificates[cert.issuerFingerprint];
			(uint8 certStatus, uint256 thisUpdate, uint256 nextUpdate) = X509Parser.parseOcspResponse(ocsp, cert, issuer);

			//store the new status
			certificates[certID].ocsp_status = certStatus;
			certificates[certID].ocsp_lastUpdate = thisUpdate;
			certificates[certID].ocsp_nextUpdate = nextUpdate;

			if (certStatus == 0){
				emit CertificateUpdated(certID, nextUpdate);
			}

			if (certStatus == 1){
				emit CertificateRevoked(certID);
			}
		}
	}

	/// @notice Submit a CRL to update the revocation status of a certificate
	/// @dev Parses and validates CRL, updates 'ocsp_status' of certificate if appropriate
	/// @param certID SHA-256 hash of the certificate concerned
	/// @param crl CRL in DER representation
	function refreshCertificateCRL(bytes32 certID, bytes memory crl) public {
		X509Parser.X509certificate memory cert = certificates[certID];
		//status can only be updated if cert is not revoked
		if (cert.crl_status != 1){
			//parse and validate CRL
			X509Parser.X509certificate memory issuer = certificates[cert.issuerFingerprint];
			(bool contained, uint256 thisUpdate, uint256 nextUpdate) = X509Parser.parseCRL(crl, cert, issuer);

			//store the new status
			if (contained ){
				certificates[certID].crl_status = 1;
				emit CertificateRevoked(certID);
			}
			certificates[certID].crl_lastUpdate = thisUpdate;
			certificates[certID].crl_nextUpdate = nextUpdate;
			emit CertificateUpdated(certID, nextUpdate);
		}
	}


	/// @notice Get the basic information about a certificate
	/// @dev Get the mandatory fields of the X509certificate struct of a stored certificate
	/// @param certID SHA-256 hash of the certificate concerned
	/// @return version, serial number, not valid before, not valid after, name, public key, issuer identifier
	function getCert(bytes32 certID) public view returns (uint8, bytes memory, uint, uint, bytes memory, bytes memory,  bytes32) {
		X509Parser.X509certificate memory cert = certificates[certID];
		return(cert.version, cert.serialNumber, cert.notValidBefore, cert.notValidAfter, cert.name, cert.publicKey, cert.issuerFingerprint);
	}

	/// @notice Get the extension information about a certificate
	/// @dev Get the extension fields of the X509certificate struct of a stored certificate
	/// @param certID SHA-256 hash of the certificate concerned
	/// @return subject alternative names, CA flag, path length, certificate policy,  key usage
	function getCertExtensionFields(bytes32 certID) public view returns (bytes memory, bool, int, bytes memory, byte) {
		X509Parser.X509certificate memory cert = certificates[certID];
		return(cert.san, cert.cA, cert.pathLen, cert.certPolicy, cert.keyUsage);
	}

	/// @notice Get the OCSP status of a stored certificate
	/// @dev Get the OCSP status of a stored certificate
	/// @param certID SHA-256 hash of the certificate concerned
	/// @return revocation status, time of this update, time of expiry of update
	function getOCSPStatus(bytes32 certID) public view returns (uint8, uint, uint) {
		X509Parser.X509certificate memory cert = certificates[certID];
		return(cert.ocsp_status, cert.ocsp_lastUpdate, cert.ocsp_nextUpdate);
	}

	/// @notice Get the CRL status of a stored certificate
	/// @dev Get the CRL status of a stored certificate
	/// @param certID SHA-256 hash of the certificate concerned
	/// @return revocation status, time of this update, time of expiry of update
	function getCRLStatus(bytes32 certID) public view returns (uint8, uint, uint) {
		X509Parser.X509certificate memory cert = certificates[certID];
		return(cert.crl_status, cert.crl_lastUpdate, cert.crl_nextUpdate);
	}

	/// @notice Returns the status of a certificate and its chain
	/// @dev Checks whether certificate is revoked or expired and whether a certificate in its chain is revoked or expired
	/// @param certID SHA-256 hash of the certificate concerned
	/// @return bool contained in the database, bool expired, bool revoked, bool has a valid chain
	function getCertificateStatus(bytes32 certID) public view returns (bool contained, bool expired, bool revoked, bool validChain){
		if (certExists(certID)){
			//set up with positive default values
			contained = true;
			expired = false;
			revoked = false;
			validChain = true;

			//check the certificate expiration and revocation
			X509Parser.X509certificate memory cert = certificates[certID];
			if (cert.notValidAfter < now || cert.notValidBefore > now){
				expired = true;
				}
			if (cert.ocsp_status == 1|| cert.crl_status == 1 ){
				revoked = true;
			}

			//check the certificate's chain
			while (true){
				if (cert.issuerFingerprint == certID){
					return (contained, expired, revoked, validChain);
				}
				certID = cert.issuerFingerprint;
				if (cert.notValidAfter < now || cert.notValidBefore > now || cert.ocsp_status == 1 || cert.crl_status == 1 ){
					validChain = false;
				}

			}
		}
		//if cert does not exist, return negative values
		return(false, true, true, false);
	}



	/// @notice Get the public key and the identifier of the trust anchor of a certificate
	/// @dev Get the public key and the identifier of the trust anchor of a certificate and verify that the cert is authoritve for the given domain
	/// @param certID SHA-256 hash of the certificate concerned
	/// @param domainName Domain name to be checked
	/// @return contained, public key, root identifier
	function getPublicKeyAndRoot(bytes32 certID, string memory domainName) public view returns (bool, bytes memory, bytes32){
		if (certExists(certID)){
			X509Parser.X509certificate memory cert = certificates[certID];
			if (X509Parser.checkNameContained(cert, domainName)){
				return (true, cert.publicKey, getRootIDbyCertID(certID));
			}
		}
		return (false, "0x00", 0);
	}

	/// @notice Get the identifier of the trust anchor stored at index 'index'
	/// @dev Get the identifier of the trust anchor stored at index 'index'
	/// @param index index in 'trustAnchors'
	/// @return identifier of the trust anchor
	function getRootFingerprint(uint256 index) public view returns (bytes32) {
		return trustAnchors[index];
	}

	/// @notice Get the identifier of the trust anchor of a certificate
	/// @dev Get the identifier of the trust anchor of a certificate
	/// @param certID SHA-256 hash of the certificate concerned
	/// @return identifier of the certificate's trust anchor
	function getRootIDbyCertID(bytes32 certID) public view returns (bytes32){
		X509Parser.X509certificate memory cert = certificates[certID];
		while (true){
			if (cert.issuerFingerprint == certID){
				return certID;
			}
			certID = cert.issuerFingerprint;
			cert= certificates[certID];
		}
	}

	/// @notice Returns whether certificate is stored in database
	/// @dev Returns whether certificate is stored in database, i.e. is of version 1 or higher
	/// @param certID SHA-256 hash of the certificate concerned
	/// @return bool exists
	function certExists(bytes32 certID) public view returns (bool){
		return certificates[certID].version > 0;
	}

	/// @notice Store a new certificate in the database
	/// @dev Copy a memory X509certificate to storage X509certificate
	/// @param storeCert X509certificate in storage that is filled
	/// @param cert X509certificate in memory that contains information to be stored
	/// @param issuer Identifier of the certificate's issuer
	function storeCertificate(X509Parser.X509certificate storage storeCert,  X509Parser.X509certificate memory cert, bytes32 issuer) private {
		storeCert.version = cert.version;
		storeCert.serialNumber = cert.serialNumber;
		storeCert.issuerFingerprint = issuer;
		storeCert.notValidBefore = cert.notValidBefore;
		storeCert.notValidAfter = cert.notValidAfter;
		storeCert.name = cert.name;
		storeCert.publicKey = cert.publicKey;
		storeCert.san = cert.san;
		storeCert.cA = cert.cA;
		storeCert.pathLen = cert.pathLen;
		storeCert.keyUsage = cert.keyUsage;

		//set the default revocation status: unkown
		storeCert.ocsp_status = 2;
		storeCert.crl_status = 2;
	}

	/// @dev Get the identifier of a certificate
	/// @param der ASN.1 document in DER format
	/// @return SHA-256 hash of the certificate
	function getFingerprint(bytes memory der) public pure returns (bytes32){
		return sha256(der);
	}

	/// @dev Get the bytes representation of an unsigned integer
	/// @param x integer to be converted
	/// @return integer value represented in bytes
	function toBytes(uint256 x) private pure returns (bytes memory b) {
		b = new bytes(32);
		assembly { mstore(add(b, 32), x)}
	}
}
