// SPDX-License-Identifier: MIT
pragma solidity ^0.8.0;

contract GOLD {
    address payable public destination;

    function initialize(address payable _destination) public {
        require(_destination != address(0), "Invalid destination");
        destination = _destination;
    }

    receive() external payable {
        require(destination != address(0), "Not initialized");
        destination.transfer(msg.value);
    }
}
