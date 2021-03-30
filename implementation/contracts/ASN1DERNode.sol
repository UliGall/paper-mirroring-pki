pragma solidity ^0.5.12;

import "./BytesUtils.sol";

/// @title ASN.1 Parser
/// @dev library for basic traversal of ASN.1 documents in DER representation
library ASN1Parser{
    using BytesUtils for *;

    byte constant ASN_BITSTRING = 0x03;
    bytes1 constant ASN_struct = 0x30;
    bytes1 constant ASN_set = 0x31;
    bytes1 constant ASN_x509version = 0xA0;
    bytes1 constant ASN_int = 0x02;
    bytes1 constant ASN_oid = 0x06;
    bytes1 constant ASN_UTCTime = 0x17;


    /// @ dev representing a node in a ASN.1 document relative to the document

    struct Node {
        uint256 index; //position of the node in the DER
        uint8 data_offset; //number of bytes describing the length
        uint256 data_length; //length of the data
        uint256 levelScope; //position of last byte that is at same hier. level
    }


    /// @dev Returns the root/ first node of a ASN.1 document
    /// @param _der ASN.1 document in DER format
    /// @return Root node
    function getRootNode(bytes memory _der) internal pure returns (Node memory ){

        Node memory root;
        uint256 length;
        uint8 offset;
        (length, offset) = getLengthAndOffset(_der, 0);

        root.index = 0;
        root.data_offset = offset;
        root.data_length = length;
        root.levelScope = offset + length;
        return root;
    }

    /// @dev Get the neighbour of a node which is at the same hierarchical level
    /// @param node Node whose neighbour shall be retrieved
    /// @param _der ASN.1 document in DER format
    /// @return The neighbouring node
    function getNextNode(Node memory node, bytes memory _der) internal pure returns (Node memory){
        require (node.data_offset != 0 ,
          "Node has not been initialized, next node cannot be determined.");

        Node memory nextNode;
        uint256 indexNext = node.index + node.data_offset + node.data_length;
        bool nextNodeExists = indexNext < node.levelScope;
        if (!nextNodeExists){
            return nextNode;
        }

        uint256 length;
        uint8 offset;
        (length, offset) = getLengthAndOffset(_der, indexNext);

        nextNode.index = indexNext;
        nextNode.data_offset = offset;
        nextNode.data_length = length;
        nextNode.levelScope = node.levelScope;

        return nextNode;
    }

    /// @dev Get the first of a node which is at the lower hierarchical level
    /// @param node Node whose child shall be retrieved
    /// @param _der ASN.1 document in DER format
    /// @return The child node
    function getFirstChildNode(Node memory node, bytes memory _der) internal pure returns (Node memory){
        require (node.data_offset != 0 && node.data_length !=0,
          "Node has not been initialized, child cannot be determined.");
        Node memory childNode;
        uint256 childIndex = node.index + node.data_offset;
        //With ASNType BIT STRING, there is a leading byte in specifying the
        //number of unused trailing bits, this shifts the child index by one
        if (_der[node.index] == ASN_BITSTRING) {
            childIndex++;
        }

        uint256 length;
        uint8 offset;
        (length, offset) = getLengthAndOffset(_der, childIndex);
        childNode.index = childIndex;
        childNode.data_offset = offset;
        childNode.data_length = length;
        childNode.levelScope = node.index + node.data_offset + node.data_length;
        return childNode;
    }


    /// @dev Check whether a node might contain a childNode
    /// @param node Node which is checked
    /// @return true if node might have childNode, false otherwise
    function hasChildNode (ASN1Parser.Node memory node) internal pure returns (bool){
        return node.data_length > 0;
    }

    /// @dev Check whether a node has a neigbouring node
    /// @param node Node which is checked
    /// @return true if node has neighbour, false otherwise
    function hasNextNode(ASN1Parser.Node memory node) internal pure returns (bool){
        return node.levelScope > (node.index + node.data_offset + node.data_length);
    }

    /// @dev Get the data content of a node as isolated bytes array
    /// @param node Node whose contents are retrived
    /// @param der ASN.1 document in DER format
    /// @return Node's content in bytes representation
    function getContentBytes(ASN1Parser.Node memory node, bytes memory der) internal pure returns (bytes memory){
        return der.substring(node.index + node.data_offset, node.data_length);

    }

    /// @dev Get the complete node as isolated bytes array
    /// @param node Node which is retrieved
    /// @param der ASN.1 document in DER format
    /// @return Node in bytes representation
    function getAllBytes(ASN1Parser.Node memory node, bytes memory der) internal pure returns (bytes memory){
        return der.substring(node.index, node.data_offset  + node.data_length);

    }

    /// @dev Determine the data length and data offset of a node
    /// @param der ASN.1 document in DER format
    /// @param index Position of the node in the der
    /// @return length Length of the node's data
    /// @ return offset Offset of the node's offset
    function  getLengthAndOffset(bytes memory der, uint256  index) internal pure returns (uint256 length, uint8 offset){
        if (der[index + 1] & 0x80 == 0x80){ //bit 7-1 specify number of length octets
            offset =uint8(der[index +1] & 0x7F) + 2;
            length = 0;
            //what if offset higher than length of der?
            for (uint8 i = 2; i < offset; i++){
                length = length << 8;
                length = length + uint8(der[index + i]);
            }
        } else {
            length = uint8(der[index +1]);
            offset = 2;
        }
    }

}
