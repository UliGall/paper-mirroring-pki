pragma solidity ^0.5.12;

import "./SignatureValidation.sol";
import "./CertStore.sol";
import "./BytesUtils.sol";

/// @title Endorsement Database
/// @notice Central Database for validating and storing external endorsements
contract EndorsementDatabase {
	using BytesUtils for *;

	event EndorsementAdded(bytes accountAddress, string domainName, bytes32 certID, uint256 expiration);
	event EndorsementRevoked(bytes accountAddress, string domainName,  uint256 expiration);
	event rootAddedtoStore(uint256 storeIndex, bytes32 fingerprint);

	/// struct used for accessing enorsements by domain name or account address
	struct EndorsementStore {
		mapping (uint256 => uint256) endorsements;
		uint256 count;
	}

	///struct for storing endorsements
	struct Endorsement {
		bytes accountAddress;
		string domainName;
		bytes32 certID;
		bytes32 rootID;
		uint256 expiration;
		uint256 addedAt;
		bool revoked;
	}

	/// struct for storing and maintaing root stores
	struct RootStore {
		mapping (uint256 => bytes32) roots;
		mapping (bytes32 => bool) contained;
		uint256 count;
		address owner;
	}

	/// @notice Contract that is referenced for the retrieval of X.509 certificates
	CertificateStore private cs;

	/// @notice Mapping that stores all submitted valid endorsements
	mapping (uint256 => Endorsement) private endorsements;
	/// @notice Counter for number of submitted endorsements
	uint256 private endorsementCounter = 0;
	mapping (bytes => mapping (string => mapping(bytes32 => mapping (uint256 => bool)))) private submitted;

	/// @notice Mapping that stores all initialized root stores
	mapping (uint256 => RootStore) private rootStores;
	/// @notice Counter for the number of initialized root stores
	uint256 private rootStoreCount = 0;

	/// @notice Mapping for retrieving endorsement stores by domain
	mapping (string => EndorsementStore) private endorsementsByDomain;
	/// @notice Mapping for retrieving endorsement stores by account address
	mapping (bytes => EndorsementStore) private endorsementsByAddress;

	/// @notice Deploy endorsement database with reference to a certificate database
	/// @dev Deploy endorsement database, pass address of cert database as argument
	/// @param certStore address of referenced certificate database
	constructor (address certStore) public{
		cs = CertificateStore(certStore);
	}

	/// @notice Submit an endorsement to the database
	/// @dev Validates and stores a submitted valid endorsement
	/// @param accountAddress address of account to be endorsed
	/// @param domainName address of domain name to be endorsed
	/// @param certID identifier of the certificate used for signing the endorsement
	/// @param expiration expiration date of the endorsement
	/// @param signature signature confirming the endorsement
	function submitEndorsement(bytes memory accountAddress, string memory domainName, bytes32 certID, uint256 expiration, bytes memory signature) public {
		require(!submitted[accountAddress][domainName][certID][expiration],
			"Endorsement has already been submitted.");
		require(accountAddress.length == 20, "Account address must be 20 bytes long.");
		require(expiration > now, "The endorsement is already expired.");

		//retrieve relevant information from the certificate database
		bool validCert;
		bytes memory pubKey;
		bytes32 rootID;
		(validCert, pubKey, rootID) = cs.getPublicKeyAndRoot(certID, domainName);
		require(validCert,
			"The provided certificate is not stored in the database or does not contain the specified domain.");

		//validate the endorsement signature
		bytes memory message = getPreEndorsement(accountAddress, domainName, certID, expiration);
		require(SignatureValidation.validateRSASHA256Signature(message, signature, pubKey), "Signature not valid.");

		//store endorsement
		addEndorsement(accountAddress, domainName, certID, rootID, expiration);

	}

	/// @notice Revoke an endorsement stored in the database
	/// @dev Validates the revocation of an endorsement and revokes the endorsement if it is valid
	/// @param index Position of the endorsement in 'endorsements'
	/// @param signature Signature confirming the revocation, created with the private key used for the inital endorsement creation
	function revokeEndorsement(uint256 index, bytes memory signature) public {
		Endorsement storage e = endorsements[index];
		bool validCert;
		bytes memory pubKey;
		bytes32 rootID;
		(validCert, pubKey, rootID) = cs.getPublicKeyAndRoot(e.certID, e.domainName);
		bytes memory message = getPreRevocation(e.accountAddress, e.domainName, e.expiration);
		require(SignatureValidation.validateRSASHA256Signature(message, signature, pubKey), "Signature not valid.");
		e.revoked = true;
		emit EndorsementRevoked(e.accountAddress, e.domainName, e.expiration);
	}

	/// @notice Initialize a new root store
	/// @dev Initialize a new root store, message sender becomes its owner
	/// @return The index of the new store in 'endorsements'
	function initializeRootStore() public returns (uint256) {
		RootStore storage store = rootStores[rootStoreCount];
		store.owner = msg.sender;
		store.count = 0;
		return rootStoreCount ++;
	}

	/// @notice Add new roots to a root store
	/// @dev Add roots to store, can be a range of roots determined by the indices in 'trustAnchors' in 'cs'
	/// @dev !!! currently no checks in place that confirm existence of a root !!!
	/// @param storeIndex Index of the concerned store in 'rootStores'
	/// @param startIndex Index of the first root to add
	/// @param endIndex Index of the last root to add
	function addRootstoStore(uint256 storeIndex, uint256 startIndex, uint256 endIndex) public {
		require(rootStoreCount < (2^256) -1, "Root store memory is full");
		RootStore storage store = rootStores[storeIndex];
		require(store.owner == msg.sender);

		//retrieve the root indices on-by-one from 'cs' and add them to the store
		for (uint256 i = startIndex; i <= endIndex; i++){
			bytes32 rootFingerprint = cs.getRootFingerprint(i);
			if (!store.contained[rootFingerprint]){
				store.roots[store.count] = rootFingerprint;
				store.count++;
				store.contained[rootFingerprint] = true;
				emit rootAddedtoStore(storeIndex, rootFingerprint);
			}

		}
	}

	/// @notice Remove a root identifier from a root store
	/// @dev Remove root from store, can only be performed by root store owner
	/// @param storeIndex Index of the root store in 'rootStores'
	/// @param rootIndex Index of the root in 'roots' in the respective root store
	function removeRootFromStore(uint256 storeIndex, uint256 rootIndex) public {
		RootStore storage store = rootStores[storeIndex];
		require(store.owner == msg.sender);

		if (store.count > rootIndex){
			//remove the root
			bytes32 rootFingerprint = store.roots[rootIndex];
			store.contained[rootFingerprint] = false;
			store.count--;
			//fill the empty position in 'roots' either with 0 or the last item
			if (store.count == rootIndex){
				store.roots[rootIndex] = 0;
			} else {
				store.roots[rootIndex] = store.roots[store.count];
				store.roots[store.count] = 0;
			}
		}
	}

	/// @notice Utility function for verifying an internal endorsement
	/// @dev Validation of endorsements that are not stored in the database
 	/// @param rootStore Index of the root store in 'rootStores' that is validated against
 	/// @param account Address of the endorsed account
 	/// @param domainName Endorsed domain name
 	/// @param certID Identifier of the certificate used for the endorsement creation
 	/// @param expiration Expiration data of the endorsement
  /// @param signature Signature confirming the endorsement
	/// @return true if the endorsement is valid, false otherwise
	function verifyInternalEndorsement(uint256 rootStore, bytes memory account, string memory domainName,
		bytes32 certID, uint256 expiration, bytes memory signature) public view returns (bool){
		require(account.length == 20, "Account address must be 20 bytes long.");
		bool validCert;
		bytes memory pubKey;
		bytes32 rootID;

		(validCert, pubKey, rootID) = cs.getPublicKeyAndRoot(certID, domainName);
		bool acceptedRoot = rootStores[rootStore].contained[certID];
		bytes memory message = getPreEndorsement(account, domainName, certID, expiration);
		bool validSignature = SignatureValidation.validateRSASHA256Signature(message, signature, pubKey);
		(bool contained, bool expired, bool revoked, bool validChain) = cs.getCertificateStatus(certID);
		return validCert && validSignature && acceptedRoot && contained && !expired && !revoked && validChain;
	}


	/// @notice Utility function for verifying the revocation an internal endorsement
	/// @dev Validation of the revocation endorsements that are not stored in the database
	/// @param account Address of the endorsed account
	/// @param domain endorsed domain name
	/// @param certID Identifier of the certificate used for the endorsement creation
	/// @param expiration Expiration data of the endorsement
	/// @param signature Signature confirming the revocation
	/// @return true if revocation is valid, false if otherwise
	function verifyInternalEndorsementRevocation(bytes memory account, string memory domain, bytes32 certID,
		uint256 expiration, bytes memory signature) public view returns(bool){
		require(account.length == 20, "Account address must be 20 bytes long.");
		bool validCert;
		bytes memory pubKey;
		bytes32 rootID;
		(validCert, pubKey, rootID) = cs.getPublicKeyAndRoot(certID, domain);
		if (!validCert){
			return false;
		}
		bytes memory message = getPreRevocation(account, domain, expiration);
		return SignatureValidation.validateRSASHA256Signature(message, signature, pubKey);
	}

	/// @notice Get Endorsement by its position index
	/// @dev Get Endorsement by its position in 'endorsements'
	/// @param index Position of the endorsement in 'endorsements'
	/// @return account address, domain name, certificate identifer, expiration, date of submission, root identifer, revoked
	function getEndorsement(uint256 index) public view returns (bytes memory, string memory, bytes32,
		 uint256, uint256, bytes32, bool){
		Endorsement memory e = endorsements[index];
		return (e.accountAddress, e.domainName, e.certID, e.expiration, e.addedAt, e.rootID, e.revoked );
	}

	/// @notice Get an endorsement by its account address and position in its repective account-address store
	/// @dev Get an endorsement by its account address and position in its repective account-address store
	/// @param account Account address of the endorsement
	/// @param index Position in its repective account-address store
	/// @return account address, domain name, certificate identifer, expiration, date of submission, root identifer, revoked
	function getEndorsementByAddress(bytes memory account, uint32 index) public view returns (bytes memory,
		string memory, bytes32, uint256, uint256, bytes32, bool){
		EndorsementStore storage store = endorsementsByAddress[account];
		if (store.count <= index){
			return (hex"", "", 0, 0, 0,0, true);
		}
		uint256 offset = store.endorsements[index];
		return getEndorsement(offset);
	}

	/// @notice Get an endorsement by its domain and position in its repective domain store
	/// @dev Get an endorsement by its domain and position in its repective domain store
	/// @param domain Domain name of the endorsement
	/// @param index Position in its repective domain store
	/// @return account address, domain name, certificate identifer, expiration, date of submission, root identifer, revoked
	function getEndorsementByDomain(string memory domain, uint32 index) public view returns (bytes memory,
		string memory, bytes32,  uint256, uint256, bytes32, bool){
		EndorsementStore storage store = endorsementsByDomain[domain];
		if (store.count <= index){
			return (hex"", "", 0, 0, 0,0, true);
		}
		uint256 offset = store.endorsements[index];
		return getEndorsement(offset);
	}

	/// @notice Get a trusted account address that is linked to 'domain'
	/// @dev Get an account address that is linked to 'domain' and stems from a trusted root
	/// @param domain Domain name looked for
	/// @param rootStoreIndex Index of trusted root store
	/// @return if valid endorsement found: (true, account address), otherwise (false, 0x)
	function getAccountByDomain(string memory domain, uint256 rootStoreIndex) public view returns (bool,
		bytes memory) {
		// retrieve the endorsement store responsible and the root store
		EndorsementStore storage endStore = endorsementsByDomain[domain];
		RootStore  storage rs = rootStores[rootStoreIndex];
		//return the first endorsement that is trusted
		for (uint i = 0; i < endStore.count; i++){
			bytes32 root = endorsements[endStore.endorsements[i]].rootID;
			if (rs.contained[root]){
				return (true, endorsements[endStore.endorsements[i]].accountAddress);
			}
		}
		return (false, hex"");
	}

	/// @notice Get a trusted domain name that is linked to 'account'
	/// @dev Get a domain name that is linked to 'account' and stems from a trusted root
	/// @param account Account address looked for
	/// @param rootStoreIndex Index of trusted root store
	/// @return if valid endorsement found: (true, domain name), otherwise (false, "")
	function getDomainByAccount(bytes memory account, uint256 rootStoreIndex) public view returns (bool,
		string memory) {
		require(account.length == 20, "Account address must be 20 bytes long.");
		// retrieve the endorsement store responsible and the root store
		EndorsementStore storage store = endorsementsByAddress[account];
		RootStore  storage rootStore = rootStores[rootStoreIndex];
		//return the first endorsement that is trusted
		for (uint i = 0; i < store.count; i++){
			if (rootStore.contained[endorsements[store.endorsements[i]].rootID]){
				return (true, endorsements[store.endorsements[i]].domainName);
			}
		}
		return (false, "");
	}

	/// @notice Get a trusted endorsement linking a domain and an account
	/// @dev Get a links 'domain' and 'account' and stems from a trusted root
	/// @param domain Domain name
	/// @param account Account address
	/// @param rootStoreIndex Index of the trusted root store
	/// @return true if found /false if not, index in 'endorsements'
	function getEndorsementByDomainAndAccount(string memory domain, bytes memory account,
		uint256 rootStoreIndex) public view returns (bool, uint256){
		require(account.length == 20, "Account address must be 20 bytes long.");
		// retrieve the domain endorsement store responsible and the root store
		EndorsementStore storage store = endorsementsByDomain[domain];
		RootStore  storage rootStore = rootStores[rootStoreIndex];
		//retrurn the first endorsement that is trusted and is for 'account'
		for(uint i = 0; i < store.count; i++){
			if (rootStore.contained[endorsements[store.endorsements[i]].rootID]
				&& account.equals(endorsements[store.endorsements[i]].accountAddress)){
				return (true, store.endorsements[i]);
			}
		}
		return (false, 0);
	}

	/// @notice Check if a root store contains a certain root
	/// @dev Check if a root store contains a certain root identifier
	/// @param store Index of the store in 'rootStores'
	/// @param rootID Identifier of the root being checked
	/// @return true if contained, false otherwise
	function containsFingerprint(uint256 store, bytes32 rootID) public view returns (bool){
		RootStore storage rs = rootStores[store];
		return rs.contained[rootID];
	}

	/// @notice Get the root at a certain position in a root store
	/// @dev Get the identifer of the root at position 'index' in root store at position 'store'
	/// @param store Position of the root store in 'rootStores'
	/// @param index Position of the root in the root store
	/// @return Roout identifer if found, 0 otherwise
	function getRootAt(uint256 store, uint256 index) public view returns (bytes32) {
		RootStore storage rs = rootStores[store];
		if (rs.count <= index){
			return 0;
		}
		return rs.roots[index];
	}

	/// @notice Get the bytes string that needs to be signed for creating an endorsement
	/// @dev Produces the concatenation of the input variables
	/// @param accountAddress Account address to be endorsed
	/// @param domainName Domain name to be endorsed
	/// @param certificateID Identifier of the certificate that is used to create the endorsement
	/// @param expiration Expiration date of the endorsement
	/// @return The pre-endorsement byte string
	function getPreEndorsement(bytes memory accountAddress, string memory domainName, bytes32 certificateID,
		uint256 expiration) public pure returns (bytes memory){
		require(accountAddress.length == 20, "Account address must be 20 bytes long.");
		//convert everything to bytes and get the lengths of each field
		bytes memory domainBytes = bytes(domainName);
		uint domainlength = domainBytes.length;
		uint bufferLength = 20 + 32+ 32 + domainlength;


		bytes memory buffer = new bytes(bufferLength);
		// add the account address
		for (uint i = 0; i < 20; i++){
			buffer[i] = accountAddress[i];
		}
		//add the domain name
		for (uint i = 0; i < domainlength; i++){
			buffer[i + 20] = domainBytes[i];
		}
		// add the certificate identifier
		for (uint i = 0; i < 32; i++){
			buffer[i  + 20 + domainlength] = certificateID[i];
		}
		//add the expration date
		bytes memory expirationBytes = toBytes(expiration);
		for (uint i = 0; i < expirationBytes.length; i++){
			buffer[i + 20 + domainlength + 32 + 32 - expirationBytes.length] = expirationBytes[i ];
		}
		return buffer;

	}

	/// @notice  Get the bytes string that needs to be signed for revoking an endorsement
	/// @dev  Produces the concatenation of the input variables
	/// @param accountAddress accountAddress Account address to be revoked
	/// @param domainName Domain name to be revoked
	/// @param expiration Expiration date of the endorsement
	/// @return The pre-revocation byte string
	function getPreRevocation(bytes memory accountAddress, string memory domainName, uint256 expiration)
		public pure returns (bytes memory){
		require(accountAddress.length == 20, "Account address must be 20 bytes long.");
		//convert everything to bytes and get the lengths of each field
		bytes memory domainBytes = bytes(domainName);
		uint domainlength = domainBytes.length;
		uint bufferLength = 20 + 32 +  domainlength + 8;
		bytes memory expirationBytes = toBytes(expiration);

		bytes memory buffer = new bytes(bufferLength);
		// add the account address
		for (uint i = 0; i < 20; i++){
			buffer[i] = accountAddress[i];
		}
		//add the domain name
		for (uint i = 0; i < domainlength; i++){
			buffer[i + 20] = domainBytes[i];
		}
		//add the expration date
		for (uint i = 0; i < expirationBytes.length; i++){
			buffer[i + 20 + domainlength + 32 - expirationBytes.length] = expirationBytes[i ];
		}
		//add the revocation flag
		for (uint i = 0; i < 8; i++){
			buffer[i + 20 + domainlength + 32] = 0xFF;
		}
		return buffer;
	}


	/// @notice Store a new valid endorsement in the database
	/// @dev Add a new endorsement to 'endorsements' and the respective endorsement stores
	/// @param accountAddress Account address of the endorsement
	/// @param domainName Domain name of endorsement
	/// @param certID Identifier of certificate used to create endorsement
	/// @param rootID Identifier of root of the endorsement
	/// @param expiration Expiration date of the endorsement
	function addEndorsement(bytes memory accountAddress, string memory domainName, bytes32 certID,
		bytes32 rootID, uint256 expiration) private {
		require(accountAddress.length == 20, "Account address must be 20 bytes long.");
		Endorsement storage e = endorsements[endorsementCounter];
		e.accountAddress = accountAddress;
		e.domainName = domainName;
		e.certID = certID;
		e.rootID = rootID;
		e.addedAt = now;
		e.expiration = expiration;
		e.revoked = false;

		//add endorsement to its account endorsement store
		EndorsementStore storage endorsementStore = endorsementsByAddress[accountAddress];
		endorsementStore.endorsements[endorsementStore.count] = endorsementCounter;
		endorsementStore.count++;

		//add endorsement to its domain endorsement store
		endorsementStore = endorsementsByDomain[domainName];
		endorsementStore.endorsements[endorsementStore.count] = endorsementCounter;
		endorsementStore.count++;

		endorsementCounter++;
		emit EndorsementAdded(accountAddress, domainName, certID, expiration);
	}

	/// @dev Get the bytes representation of an unsigned integer
	/// @param x integer to be converted
	/// @return integer value represented in bytes
	function toBytes(uint256 x) private pure returns (bytes memory b) {
		b = new bytes(32);
		assembly { mstore(add(b, 32), x)}
	}
}
