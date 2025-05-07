// contracts/CryptPicRegistry.sol
// SPDX-License-Identifier: MIT
pragma solidity ^0.8.0;

contract CryptPicRegistry {
    struct Record {
        string timestamp;
        address creator;
    }

    mapping(string => Record) public records;

    function storeHash(string memory hash, string memory timestamp) public {
        require(bytes(records[hash].timestamp).length == 0, "Hash already registered");
        records[hash] = Record(timestamp, msg.sender);
    }

    function verifyHash(string memory hash) public view returns (string memory, address) {
        require(bytes(records[hash].timestamp).length != 0, "Hash not found");
        return (records[hash].timestamp, records[hash].creator);
    }
}
