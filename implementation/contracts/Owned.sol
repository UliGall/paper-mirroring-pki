pragma solidity ^0.5.12;

contract Owned{

	address owner;

	constructor() internal {
		owner = msg.sender;
	}

	modifier onlyOwner {
		require(msg.sender == owner, "Not authorized.");
		_;
	}

	function transferOwnership(address newOwner) public onlyOwner {
		if (newOwner != address(0)){
			owner = newOwner;
		}		
	}
	
}