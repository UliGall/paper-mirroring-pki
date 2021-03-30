pragma solidity ^0.5.12;

import "./ASN1DERNode.sol";
import "./BytesUtils.sol";
import "./SignatureValidation.sol";
import "./TimeConversion.sol";

/// @title X509Parser
/// @notice Parses and validates X.509 certificates, CRLs and OCSP responses
/// @dev Simultaneous parsing and validation of X.509 certificates, self-signed certificates, CRLs and OCSP responeses
library  X509Parser {
    using BytesUtils for *;
    using ASN1Parser for *;

    //DER encoding types of ASN.1 types
    bytes1 constant ASN_BITSTRING = 0x03;
    bytes1 constant ASN_struct = 0x30;
    bytes1 constant ASN_set = 0x31;
    bytes1 constant ASN_x509version = 0xA0;
    bytes1 constant ASN_int = 0x02;
    bytes1 constant ASN_oid = 0x06;
    bytes1 constant ASN_UTCTime = 0x17;
    bytes1 constant ASN_GeneralizedTime = 0x18;

    //datastructure for storing anf maintaing X.509 certificates
    struct X509certificate{
        uint8 version;
        bytes serialNumber;
        //issuer: info not relevant anymore after validation, if necessary, info can be retrieved from chain of trust
        bytes32 issuerFingerprint; //to trace back the chain of trust
        uint notValidBefore;
        uint notValidAfter;
        bytes name;
        bytes publicKey;

        /* Optional: issuer unique identifier, subject unique identifier, extensions */
        bytes san; //subject alternative name
        bool cA;
        int pathLen;
        bytes certPolicy;
        byte keyUsage;

        /* Revocation status fields */
        uint ocsp_lastUpdate; //0 is ok, 1 is revoked, 2 is unkown
        uint ocsp_nextUpdate;
        uint8 ocsp_status;

        uint crl_lastUpdate; //0 is ok, 1 is revoked, 2 is unkown
        uint crl_nextUpdate;
        uint8 crl_status;
    }

    /// @notice Parse and validate an X.509 certificate
    /// @dev Parse and validate an X.509 certificate with the issuer information provided
    /// @param certDer DER-encoded X.509 certificate
    /// @param issuerIdentifier subject name field of the issuer certificate
    /// @param signerPubKey public key of the issuer
    /// @return parsed and validated certificate information
    function parseAndValidateDERCertificate(bytes memory certDer, bytes memory issuerIdentifier, bytes memory signerPubKey) internal view returns (X509certificate memory) {
        require(certDer[0] == ASN_struct, "Not a valid X.509 DER encoding");

        ASN1Parser.Node memory curNode = certDer.getRootNode();
        //extract the TBScertificate
        curNode = curNode.getFirstChildNode(certDer);
        bytes memory tbsDer = curNode.getAllBytes(certDer);
        //extract the signature information
        curNode = curNode.getNextNode(certDer);
        bytes memory sigInfoDer = curNode.getAllBytes(certDer);
        //extract the signature
        curNode = curNode.getNextNode(certDer);
        bytes memory sigDer = curNode.getContentBytes(certDer);

        //1st step: validate the signature: if not valid, reject
        require(SignatureValidation.validateSignature(tbsDer, sigInfoDer, sigDer, signerPubKey), "Signature not valid.");
        //2nd step: go through the content of the tbscert, validate it, and gather the information to be stored
        X509certificate memory cert = parseAndValidateTBSBasic(tbsDer, sigInfoDer, issuerIdentifier);
        return cert;
    }


    /// @notice Parse and validate a self-signed X.509 certificate
    /// @dev Parse and validate a self-signed X.509 certificate
    /// @param certDer DER encoded certificate
    /// @return parsed and validated certificate information
    function parseAndValidateSelfSignedCertificate(bytes memory certDer) internal view returns (X509certificate memory) {
        require(certDer[0] == ASN_struct, "Not a valid X.509 DER encoding");

        ASN1Parser.Node memory curNode = certDer.getRootNode();
        //extract the TBScertificate
        curNode = curNode.getFirstChildNode(certDer);
        bytes memory tbsDer = curNode.getAllBytes(certDer);
        //extract the signature information
        curNode = curNode.getNextNode(certDer);
        bytes memory sigInfoDer = curNode.getAllBytes(certDer);
        //extract the signature
        curNode = curNode.getNextNode(certDer);
        bytes memory sigDer = curNode.getContentBytes(certDer);

        //2nd step: go through the content of the tbscert, validate it, and gather the information to be stored
        X509certificate memory cert = parseAndValidateTBSBasic(tbsDer, sigInfoDer, hex"00");

        //3rd step: ensure that self-signed signature is valid
        require(SignatureValidation.validateSignature(tbsDer, sigInfoDer, sigDer, cert.publicKey), "Signature not valid.");

        return cert;
    }

    /// @notice Checks if a certificate contains a (wildcard) domain in its subject name /SAN fields
    /// @dev Checks if a certificate contains a (wildcard) domain in its subject name /SAN fields
    /// @param cert X509certificate that is to be examined
    /// @param name domain name that is to be found
    /// @return true if the name or a correspondin wildcard domain are contained by the cert
    function checkNameContained(X509Parser.X509certificate memory cert, string memory name) internal pure returns(bool contained){
        contained = false;

        //create the name byte array and the wildcard array
        bytes memory namebytes = bytes(name);
        uint32 startIndex = 0;
        for (uint32 i = 0; i < namebytes.length; i++){
            if (namebytes[i] == '.'){
                startIndex = i;
                break;
            }
        }
        bytes memory wildcardbytes = new bytes(namebytes.length - startIndex + 1);
        wildcardbytes[0] = '*';

        for (uint32 j = startIndex; j < namebytes.length; j++){
                wildcardbytes[j - startIndex + 1] = namebytes[j];
        }

        //search for the domain in subject field
        bytes memory nameDer = cert.name;
        ASN1Parser.Node memory curNode = (nameDer.getRootNode()).getFirstChildNode(nameDer);

        uint i = 0;
        while (i < 50){ i++;
            ASN1Parser.Node memory seqNode = curNode.getFirstChildNode(nameDer);
            ASN1Parser.Node memory oidNode = seqNode.getFirstChildNode(nameDer);
            ASN1Parser.Node memory strNode = oidNode.getNextNode(nameDer);

            bytes memory matchname = strNode.getContentBytes(nameDer);
            if (matchname.equals(namebytes) || matchname.equals(wildcardbytes)){
                return true;
            }
            if (curNode.hasNextNode()){
                curNode = curNode.getNextNode(nameDer);
            } else {
                break;
            }
        }

        //search for domain in SAN field
        nameDer = cert.san;
        curNode = (nameDer.getRootNode()).getFirstChildNode(nameDer);

        while (true){
            bytes memory matchname = curNode.getContentBytes(nameDer);
            if (matchname.equals(namebytes) || matchname.equals(wildcardbytes)){
                return true;
            }
            if (curNode.hasNextNode()){
                curNode = curNode.getNextNode(nameDer);
            } else {
                break;
            }
        }
    }



    /// @notice Parses a CRL and checks whether a specific certificate is contained
    /// @dev Parses and validates a CRL and checks whether a specific certificate serial number is contained
    /// @param der CRL in ASN.1 DER encoding
    /// @param cert X509certificate struct of the certificate that is to be checked
    /// @param issuer X509certificate struct of the issuers of the certificate that is to be checked
    /// @return true if the cert serial number is contained, 'thisUpdate' and 'nextUpdate' fields of the CRL
    function parseCRL(bytes memory der, X509certificate memory cert, X509certificate memory issuer) internal view returns(bool contained, uint256 thisUpdate, uint256 nextUpdate){
        require(der[0] == ASN_struct, "Not a valid X.509 DER encoding");

        ASN1Parser.Node memory curNode = der.getRootNode();
        //extract the TbsCrl
        curNode = curNode.getFirstChildNode(der);
        bytes memory tbsDer = curNode.getAllBytes(der);
        //extract the signature information
        curNode = curNode.getNextNode(der);
        bytes memory sigInfoDer = curNode.getAllBytes(der);
        //extract the signature
        curNode = curNode.getNextNode(der);
        bytes memory sigDer = curNode.getContentBytes(der);

        //validate the signature: if not valid, reject
        require(SignatureValidation.validateSignature(tbsDer, sigInfoDer, sigDer, issuer.publicKey), "Signature not valid.");
        //parse the crl and check whether certificate serial number is contained
        return parseCRLTbs(tbsDer, sigInfoDer, cert, issuer);
    }


    /// @notice Parse and validate an OCSP response
    /// @dev Parse and validate an OCSP response that contains exactly one 'BasicOCSPResponse'
    /// @param der OCSP response in ASN.1 DER encoding
    /// @param cert The certificate for which the OCSP response is validated
    /// @param issuer Issuer of the certificate
    /// @return status of the OCSP response, 'thisUpdate' and 'nextUpdate' fields of the OCSP response
    function parseOcspResponse(bytes memory der, X509Parser.X509certificate memory cert, X509Parser.X509certificate memory issuer) internal view returns(uint8 certStatus, uint256 thisUpdate, uint256 nextUpdate){
        ASN1Parser.Node memory curNode = der.getRootNode();

        //OCSP status
        curNode = curNode.getFirstChildNode(der);
        require((curNode.getContentBytes(der)).equals(hex"00"), "OCSP response status is not successfull.");

        //responsebytes
        require(curNode.hasNextNode(), "OCSP response does not contain information.");
        curNode = curNode.getNextNode(der);
        require(der[curNode.index] == 0xA0, "Malformed OCSP response.");

        //response type
        curNode = curNode.getFirstChildNode(der);
        curNode = curNode.getFirstChildNode(der);
        require((curNode.getContentBytes(der)).equals(hex"2B0601050507300101"), "Only OCSP basic format supported.");

        //response
        curNode = curNode.getNextNode(der);
        //basic ocsp response
        curNode = curNode.getFirstChildNode(der);

        //tbs responseData
        curNode = curNode.getFirstChildNode(der);
        bytes memory tbsDer = curNode.getAllBytes(der);
        curNode = curNode.getNextNode(der);
        bytes memory sigInfoDer = curNode.getAllBytes(der);
        curNode = curNode.getNextNode(der);
        bytes memory sigDer = curNode.getContentBytes(der);

        //1st step: validate the signature: if not valid, reject
        require(SignatureValidation.validateSignature(tbsDer, sigInfoDer, sigDer, issuer.publicKey), "Signature not valid.");

        return parseAndValidateOcspTbs(tbsDer, cert, issuer);

    }

    /// @notice Parses the TBS part of a CRL and checks whether a specific certificate is contained
    /// @dev Parses and validates the TBS parts of a CRL and checks whether a specific certificate serial number is contained
    /// @param der The TBS part of the CRL in ASN.1 DER encoding
    /// @param sigInfo The signature information part of the CRL in ASN.1 DER encoding, necessary for verifying that it matches the info in the TBS
    /// @param issuer X509certificate struct of the issuer of the certificate that is to be checked
    /// @return true if the cert serial number is contained, 'thisUpdate' and 'nextUpdate' fields of the CRL
    function parseCRLTbs(bytes memory der, bytes memory sigInfo, X509certificate memory cert, X509certificate memory issuer) private view returns (bool contained, uint256 thisUpdate, uint256 nextUpdate) {
        ASN1Parser.Node memory curNode = der.getRootNode();

        //version
        curNode = curNode.getFirstChildNode(der);
        require((curNode.getContentBytes(der)).equals(hex"01"), "CRL not version 2.");

        //signature
        curNode = curNode.getNextNode(der);
        require((curNode.getAllBytes(der)).equals(sigInfo), "Signature algorithms do not match.");

        //issuer
        curNode = curNode.getNextNode(der);
        require((curNode.getAllBytes(der)).equals(issuer.name), "Issuer does not match.");

        //this update
        curNode = curNode.getNextNode(der);
        thisUpdate = getTime(curNode, der) ;
        require(thisUpdate < now, "Invalid update time.");

        //next update
        curNode = curNode.getNextNode(der);
        nextUpdate = getTime(curNode, der) ;
        require(nextUpdate > now, "CRL not valid anymore.");

        //revokedCertificate
        curNode = curNode.getNextNode(der);
        contained = false;
        if (curNode.data_length != 0){
            //current entry
            ASN1Parser.Node memory certNode = curNode.getFirstChildNode(der);


            while (true){
                //serial
                if (!((certNode.getFirstChildNode(der)).getContentBytes(der)).equals(cert.serialNumber)){
                    contained = true;
                    return (contained, thisUpdate, nextUpdate);
                }
                //TODO?
                //revoc date
                //extensions

                if (certNode.hasNextNode()){
                    certNode = certNode.getNextNode(der);
                } else {
                    break;
                }
            }
        }
        //TODO extensions
    }

    /// @notice Parse and validate the TBS part of an OCSP response
    /// @dev Parse and validate the TBS part of an OCSP response that contains exactly one 'BasicOCSPResponse'
    /// @param der The TBS part of the OCSP response in ASN.1 DER encoding
    /// @param cert The certificate for which the OCSP response is validated
    /// @param issuer Issuer of the certificate
    /// @return status of the OCSP response, 'thisUpdate' and 'nextUpdate' fields of the OCSP response
    function parseAndValidateOcspTbs(bytes memory der, X509Parser.X509certificate memory cert, X509Parser.X509certificate memory issuer) private pure returns(uint8 certStatus, uint256 thisUpdate, uint256 nextUpdate){
        ASN1Parser.Node memory curNode = der.getRootNode();

        //check if version field is present
        curNode = curNode.getFirstChildNode(der);
        if (der[curNode.index] == 0xA0){
            //version is present and must be 1
            //TODO check how this is actually represented
            require((curNode.getContentBytes(der)).equals(hex"01"), "Must be OCSP version 1");
            curNode = curNode.getNextNode(der);
        }

        //responder id
        if (der[curNode.index] == 0xA1){
            //by name
            //TODO ckeck actual format
            require(curNode.getContentBytes(der).equals(issuer.name), "Issuer name does not match. ");
        } else if (der[curNode.index] == 0xA2){
            //by key

            bytes memory issuerKeyDer = issuer.publicKey;
            ASN1Parser.Node memory keyNode = issuerKeyDer.getRootNode();
            keyNode = keyNode.getFirstChildNode(issuerKeyDer);
            keyNode = keyNode.getNextNode(issuerKeyDer);
            bytes memory bytesToHash = keyNode.getContentBytes(issuerKeyDer);
            //remove the trailing-bits byte that is part of BITSTRING type
            bytesToHash = bytesToHash.substring(1, bytesToHash.length-1);
            bytes20  issuerPubKeyHash2 = SHA1.sha1(bytesToHash);

            bytes memory issuerPubKeyHash = (curNode.getFirstChildNode(der)).getContentBytes(der);
            for (uint i = 0; i < 20; i++){
                require(issuerPubKeyHash[i] == issuerPubKeyHash2[i], "Issuer key hashes do not match.");
            }
        } else {
            require(false, "Responder ID not specified correctly.");
        }

        //produced at
        curNode = curNode.getNextNode(der);

        //responses
        curNode = curNode.getNextNode(der);

        //first response
        //TODO: what if multiple responses?
        curNode = curNode.getFirstChildNode(der);

        //cert ID
        curNode = curNode.getFirstChildNode(der);
        parseAndValidateOcspCertId(curNode, der, cert, issuer);

        //certstatus
        curNode = curNode.getNextNode(der);
        //TODO check which one is correct
       // uint8 certStatus = uint8(getInteger(curNode, der));
        certStatus = uint8(der[curNode.index]) - 0x80;

        //this update
        curNode = curNode.getNextNode(der);
        thisUpdate = getTime(curNode, der);

        //next update
        if (curNode.hasNextNode()){
            curNode = curNode.getNextNode(der);

            if (der[curNode.index] == 0xA0){
                nextUpdate = getTime(curNode.getFirstChildNode(der), der);
            }
            //TODO extensions
        }

    }
    /// @notice Verify that an OCSP response is issued for a certain certificate
    /// @dev Verify that an OCSP response is issued for a certain certificate, revert if not the case
    /// @param curNode2 Pointer to the certificate identifier root node
    /// @param der OCSP response in ASN.1 DER encoding
    /// @param cert The certificate information against which the OCSP response is checked
    /// @param issuer The issuer of the certificate
    function parseAndValidateOcspCertId(ASN1Parser.Node memory curNode2, bytes memory der, X509certificate memory cert, X509certificate memory issuer) private pure {
        //hashAlgorithm
        ASN1Parser.Node memory curNode = curNode2.getFirstChildNode(der);

        //TODO support algorithms different from SHA-1
        require((curNode.getFirstChildNode(der).getContentBytes(der)).equals(hex"2b0e03021a"), "Hash Algorithm for Cert ID not supported.");

        //issuer name hash
        curNode = curNode.getNextNode(der);
        bytes memory issuerHash = curNode.getContentBytes(der);
        bytes20 issuerHash2 = SHA1.sha1(issuer.name);
        for (uint i = 0; i < 20; i++){
            require(issuerHash[i] == issuerHash2[i], "Issuer name hashes do not match.");
        }

        //issuer key hash
        curNode = curNode.getNextNode(der);
        bytes memory issuerKeyDer = issuer.publicKey;
        ASN1Parser.Node memory keyNode = issuerKeyDer.getRootNode();
        keyNode = keyNode.getFirstChildNode(issuerKeyDer);
        keyNode = keyNode.getNextNode(issuerKeyDer);
        bytes memory bytesToHash = keyNode.getContentBytes(issuerKeyDer);
        //remove the trailing-bits byte that is part of BITSTRING type
        bytesToHash = bytesToHash.substring(1, bytesToHash.length-1);
        issuerHash = curNode.getContentBytes(der);
        issuerHash2 = SHA1.sha1(bytesToHash);
        for (uint i = 0; i < 20; i++){
            require(issuerHash[i] == issuerHash2[i], "Issuer key hashes do not match.");
        }

        //serial number
        curNode = curNode.getNextNode(der);
        require(curNode.getContentBytes(der).equals(cert.serialNumber), "Serial numbers do not match.");
    }

    /// @notice Parse and validate an X.509 TBScertificate
    /// @dev Parse and validate an X.509 TBScertificate
    /// @param tbsDer The TBS part of a certificate in ASN.1 DER representation
    /// @param sigInfoDer THe signature information of the processed certificate
    /// @param issuerIdentifier The name of the issuer '0x00' if self-signed
    /// @return An new X509certificate struct filled with the information parsed
    function parseAndValidateTBSBasic( bytes memory tbsDer, bytes memory sigInfoDer, bytes memory issuerIdentifier) private view returns (X509certificate memory){
        ASN1Parser.Node memory curNode = tbsDer.getRootNode();
        X509certificate memory cert;

        //version
        curNode = curNode.getFirstChildNode(tbsDer);
        cert.version = getVersion(curNode, tbsDer);

        //serialNumber
        curNode = curNode.getNextNode(tbsDer);
        cert.serialNumber = curNode.getContentBytes(tbsDer);

        //signature Algorithm, ensure the sigInfo in tbs corresponds to siginfo after tbs
        curNode = curNode.getNextNode(tbsDer);
        bytes memory oid1 = ((sigInfoDer.getRootNode()).getFirstChildNode(sigInfoDer)).getContentBytes(sigInfoDer);
        bytes memory oid2 = (curNode.getFirstChildNode(tbsDer)).getContentBytes(tbsDer);
        require (oid1.equals(oid2), "Certificate not valid: Signature information not consistent.");

        //issuer, ensure that issuerNameHash is the same as in issuing cert
        curNode = curNode.getNextNode(tbsDer);
        if (!issuerIdentifier.equals(hex"00")) {
            require(issuerIdentifier.equals(curNode.getAllBytes(tbsDer)), "Certificate not valid: Issuer name not the same as in issuing certificate.");
        }
        //validity, ensure that certificate is valid now or in the future
        curNode = curNode.getNextNode(tbsDer);
        (cert.notValidBefore, cert.notValidAfter) = getValidity(curNode, tbsDer);
        require(cert.notValidBefore < cert.notValidAfter, "Certificate not valid: Certificate must be valid for a postive amount of time.");
        require(now < cert.notValidAfter, "Certificate not valid: Validity period in the past.");

        //subject
        curNode = curNode.getNextNode(tbsDer);
        cert.name = curNode.getAllBytes(tbsDer);

        //subject public key
        curNode = curNode.getNextNode(tbsDer);
        cert.publicKey = getPublicKey(curNode, tbsDer);

        //TODO handle A1 and A2

        //extensions
        curNode = curNode.getNextNode(tbsDer);
        if (tbsDer.length > curNode.index && tbsDer[curNode.index] == 0xA3){ //extensions exist
           parseAndValidateTBSExtensions(cert, tbsDer, curNode);
        }
        return cert;
    }

    /// @notice Parse and validate the extensions part of an X.509 TBScertificate
    /// @dev Parse and validate the extensions part of an X.509 TBScertificate, reject if invalid or unkown critical extensions
    /// @param cert The certificate structure which is to be updated
    /// @param tbsDer The TBS part of a certificate in ASN.1 DER representation
    /// @param extNode Pointer to the extensions root node in the DER
    function parseAndValidateTBSExtensions(X509certificate memory cert, bytes memory tbsDer, ASN1Parser.Node memory extNode) private pure{
        ASN1Parser.Node memory curExtNode = (extNode.getFirstChildNode(tbsDer)).getFirstChildNode(tbsDer);
        bool keyUsageCA = false;
        bool basicConstraintsCA = false;

        //for (uint i = 0; i < 20; i++) {
        while (true) {
            //parse the extension
            ASN1Parser.Node memory curNode = curExtNode.getFirstChildNode(tbsDer);

            bytes memory oid = curNode.getContentBytes(tbsDer);
            curNode = curNode.getNextNode(tbsDer);

            //critcal flag may or may not be existent, default is false
            bool critical = false;
            if (tbsDer[curNode.index] == 0x01){
                critical = tbsDer[curNode.index + curNode.data_offset] != 0x00;
                curNode = curNode.getNextNode(tbsDer);
            }

            ASN1Parser.Node memory contentNode = curNode.getFirstChildNode(tbsDer);
            bytes memory content = contentNode.getContentBytes(tbsDer);


            if (oid.equals(hex"551D0F")) { //key usage
                cert.keyUsage = content[1];
                keyUsageCA = (cert.keyUsage & 0x04) == 0x04;
            } else if (oid.equals(hex"551D20")) { //certificate policies
                cert.certPolicy = curNode.getContentBytes(tbsDer);
            } else if (oid.equals(hex"551D11")) { // SAN
                cert.san = curNode.getContentBytes(tbsDer);
            }  else if (oid.equals(hex"551D13")) { // basic constraints
                //only relevant when cert is to be added as ca
                if (contentNode.hasChildNode()){
                //get ca flag
                    contentNode = contentNode.getFirstChildNode(tbsDer);
                    basicConstraintsCA = contentNode.getContentBytes(tbsDer)[0] != 0x00;
                    //get path length constraint
                    if (contentNode.hasNextNode()){
                        contentNode = contentNode.getNextNode(tbsDer);
                        cert.pathLen = int256(getInteger(contentNode, tbsDer));
                    } else {
                        cert.pathLen = 1000; //TODO decide on which number
                    }
                }
            }  else {
                require(!critical, "Certificate rejected: Unkown critical extension.");
            }
            if (curExtNode.hasNextNode()){
                curExtNode = curExtNode.getNextNode(tbsDer);
            } else {
                break;
            }
        }
        cert.cA = keyUsageCA && basicConstraintsCA;
    }

    /// @notice Retrieve public key information from a DER document
    /// @dev Retrieve public key information from a DER document
    /// @param keyNode Pointer to the root node of the ASN.1 structure
    /// @param der DER document containing the node
    /// @return The public key ASN.1 structure
    function getPublicKey(ASN1Parser.Node memory keyNode, bytes memory der) private pure returns (bytes memory pubKey){
        require(der[keyNode.index] == ASN_struct, "Not a valid X.509 DER encoding: subject public key not specified correctly.");
        return keyNode.getAllBytes(der);
    }

    /// @notice Get the validity period specified by an ASN.1 structure
    /// @dev Get the 'notValidBefore' and 'notValidAfter' values specified by an ASN.1 structure
    /// @param valNode Pointer to the root node of the ASN.1 structure
    /// @param der DER document containing the node
    /// @return notValidBefore' and 'notValidAfter' values represented as timestamps
    function getValidity (ASN1Parser.Node memory valNode, bytes memory der) private pure returns (uint256 notValidBefore, uint256 notValidAfter){
        require(der[valNode.index] == ASN_struct, "Not a valid X.509 DER encoding: Validity not specified correctly.");

        ASN1Parser.Node memory notBeforeNode;
        ASN1Parser.Node memory notAfterNode;

        notBeforeNode = valNode.getFirstChildNode(der);
        notAfterNode= notBeforeNode.getNextNode(der);

        notValidBefore = getTime(notBeforeNode, der);
        notValidAfter = getTime(notAfterNode, der);
    }

    /// @notice Convert time represented UTCTime or GeneralizedTime ASN.1 struct to timestamp
    /// @dev Convert time represented UTCTime or GeneralizedTime to uint timestamp
    /// @param timeNode Pointer to the root node of the ASN.1 structure
    /// @param der DER document containing the node
    /// @return Time represented as timestamp
    function getTime (ASN1Parser.Node memory timeNode, bytes memory der) private pure returns (uint){
        uint256 i = timeNode.index + timeNode.data_offset;
        uint16 y;
        if (der[timeNode.index] == ASN_UTCTime){
            require(der[timeNode.index + timeNode.data_offset + 12 ] == 0x5a || der[timeNode.index + timeNode.data_offset + 14 ] == 0x5a, "Not a valid X.509 DER encoding: Validity not specified correctly / UTCTime not in format YYMMDDHHMMSS.");
            y = 2000 + ASCIIToPlain(der[i++]) * 10;
            y += ASCIIToPlain(der[i++]);
            //UTCTime is only specified from 1950 to 2049
            if (y > 2049){
                y = y - 100;
            }
        } else if (der[timeNode.index] == ASN_GeneralizedTime){
            require(der[timeNode.index + timeNode.data_offset + 14 ] == 0x5a, "Not a valid X.509 DER encoding: Validity not specified correctly: GeneralizedTime not in format YYYYMMDDHHMMSS.");
            y =  ASCIIToPlain(der[i++]) * 1000;
            y += ASCIIToPlain(der[i++]) *100 ;
            y += ASCIIToPlain(der[i++]) *10;
            y += ASCIIToPlain(der[i++]) ;

        } else {
            revert("Certificate rejected: Validity encoding not supported.");
        }

        uint8 m = ASCIIToPlain(der[i++]) * 10 ;
        m += ASCIIToPlain(der[i++]) ;
        uint8 d = ASCIIToPlain(der[i++]) * 10 ;
        d += ASCIIToPlain(der[i++]) ;
        uint8 h = ASCIIToPlain(der[i++]) * 10 ;
        h += ASCIIToPlain(der[i++]) ;
        uint8 min = ASCIIToPlain(der[i++]) * 10 ;
        min += ASCIIToPlain(der[i++]) ;
        return TimeConversion.toTimestamp(y, m, d, h, min);
    }

    /// @notice Convert a digit represented in ASCII to its integer representation
    /// @dev Convert a digit represented in ASCII to its uint8 representation
    /// @param ascii The ASCII character to be converted
    /// @return The ASCII character's integer value
    function ASCIIToPlain(byte ascii) private pure returns(uint8 plain){
        plain = uint8(ascii) - 0x30;
    }


    /// @notice Retrieve the string specified by an ASN.1 structure
    /// @dev Retrieve the string specified by an ASN.1 structure
    /// @param stringNode Pointer to the root node of the ASN.1 structure
    /// @param der DER document containing the node
    /// @return String converted to string representation
    function getString (ASN1Parser.Node memory stringNode, bytes memory der) private pure returns (string memory ){
        return string(stringNode.getContentBytes(der));
    }

    /// @notice Retrieve the algorithm identifier specified by an ASN.1 structure
    /// @dev Retrieve the algorithm identifier specified by an ASN.1 structure
    /// @param algInfoNode Pointer to the root node of the ASN.1 structure
    /// @param der DER document containing the node
    /// @return Algorithm identifier in bytes representation
    function getlgorithmIdentifier(ASN1Parser.Node memory algInfoNode, bytes memory der) private pure returns (bytes memory){
        return algInfoNode.getAllBytes(der);
    }

    /// @notice Retrieve the OID specified by an ASN.1 structure
    /// @dev Retrieve the OID specified by an ASN.1 structure in bytes representation
    /// @param oidNode Pointer to the root node of the ASN.1 structure
    /// @param der DER document containing the node
    /// @return OID in bytes representation
    function getOID(ASN1Parser.Node memory oidNode, bytes memory der) private pure returns (bytes memory){
        require(der[oidNode.index] == ASN_oid, "Not a valid X.509 DER encoding: Object identifier not specified correctly.");
        bytes memory oid = new bytes(oidNode.data_length);
        oid = oidNode.getContentBytes(der);
        return oid;
    }

    /// @notice Retrieve the verison value from an X.509 version ASN.1 structure
    /// @dev Convert the value of an X.509 version ASN.1 structure to uint8
    /// @param versionNode  Pointer to the root node of the ASN.1 structure
    /// @param der DER document containing the node
    /// @return Returns the integer value incremented by one
    function getVersion(ASN1Parser.Node memory versionNode, bytes memory der) private pure returns (uint8) {
        require(der[versionNode.index] == ASN_x509version, "Not a valid X.509 DER encoding: version not specified correctly.");
        ASN1Parser.Node memory intNode = versionNode.getFirstChildNode(der);

        uint8 version = uint8(getInteger(intNode, der));
        version++;
        return version;
    }

    /// @notice Retrieve the integer value from an integer ASN.1 structure
    /// @dev Convert the value of an integer ASN.1 structure to uin256
    /// @param intNode Pointer to the root node of the ASN.1 structure
    /// @param der DER document containing the node
    /// @return The converted uint256 value
    function getInteger(ASN1Parser.Node memory intNode, bytes memory der) private pure returns (uint256){
        require(der[intNode.index] == ASN_int, "Not a valid X.509 DER encoding: Integer not specified correctly.");
        uint256 result = 0;
        for (uint256 i = 0; i < intNode.data_length; i++){
            result = result << 8;
            result += uint8(der[intNode.index + intNode.data_offset + i]);
        }
        return result;
    }

}
