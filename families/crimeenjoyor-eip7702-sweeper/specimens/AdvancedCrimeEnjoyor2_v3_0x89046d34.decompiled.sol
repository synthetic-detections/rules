// SPDX-License-Identifier: MIT
pragma solidity >=0.8.0;

/// @title            Decompiled Contract
/// @author           Jonathan Becker <jonathan@jbecker.dev>
/// @custom:version   heimdall-rs v0.9.2
///
/// @notice           This contract was decompiled using the heimdall-rs decompiler.
///                     It was generated directly by tracing the EVM opcodes from this contract.
///                     As a result, it may not compile or even be valid solidity code.
///                     Despite this, it should be obvious what each function does. Overall
///                     logic should have been preserved throughout decompiling.
///
/// @custom:github    You can find the open-source decompiler here:
///                       https://heimdall.rs

contract DecompiledContract {
    event Event_de90b0fd();
    event CallExecuted(address, bytes, bool);
    event DecryptionFailed();
    event NativeForwarded(uint256, bool);
    
    /// @custom:selector    0x092a5cce
    /// @custom:signature   destroyContract() public
    function destroyContract() public {
        require(address(msg.sender) == 0x86d9ad92fc3f69cc9c1a83aff7834fea27f1fff2, "Only owner can destroy");
        selfdestruct(0x86d9ad92fc3f69cc9c1a83aff7834fea27f1fff2);
    }
    
    /// @custom:selector    0x0c89a0df
    /// @custom:signature   transferTokens(address arg0) public payable
    /// @param              arg0 ["address", "uint160", "bytes20", "int160"]
    function transferTokens(address arg0) public payable {
        require(arg0 == (address(arg0)));
        require(0x77dd9a93d7a1ab9dd3bdd4a70a51b2e8c9b2350d);
        emit DecryptionFailed();
        address var_b = address(this);
        (bool success, bytes memory ret0) = address(arg0).Unresolved_70a08231(var_b); // staticcall
        uint256 var_c = var_c + (uint248(ret0.length + 0x1f));
        require(!((var_c + ret0.length) - var_c) < 0x20);
        require(var_d == (var_d));
        require(!(var_d) > 0);
        var_f = 0x77dd9a93d7a1ab9dd3bdd4a70a51b2e8c9b2350d;
        (bool success, bytes memory ret0) = address(arg0).Unresolved_a9059cbb(var_f); // call
        var_c = var_c + (uint248(ret0.length + 0x1f));
        require(!((var_c + ret0.length) - var_c) < 0x20);
        require(var_d == (var_d));
        emit Event_de90b0fd(address(arg0), var_d, (var_d));
    }
    
    /// @custom:selector    0x29cd3d04
    /// @custom:signature   transferNative() public payable
    function transferNative() public payable {
        if (0x77dd9a93d7a1ab9dd3bdd4a70a51b2e8c9b2350d) {
            emit DecryptionFailed();
            if (msg.value - 0) {
                (bool success, bytes memory ret0) = address(0x77dd9a93d7a1ab9dd3bdd4a70a51b2e8c9b2350d).transfer(msg.value);
                if (ret0.length == 0) {
                    emit NativeForwarded(msg.value, success);
                    emit NativeForwarded(msg.value, success);
                }
            }
        }
    }
    
    /// @custom:selector    0xab7e4c70
    /// @custom:signature   loserMulticall_3869193990(address[] arg0, bytes[] arg1) public payable
    /// @param              arg0 ["uint256", "bytes32", "int256"]
    /// @param              arg1 ["uint256", "bytes32", "int256"]
    function loserMulticall_3869193990(address[] arg0, bytes[] arg1) public payable {
        require(!arg0 > 0xffffffffffffffff);
        require(!(arg0) > 0xffffffffffffffff);
        require(!arg1 > 0xffffffffffffffff);
        require(!(arg1) > 0xffffffffffffffff);
        require(arg0 == (arg1), "Arrays length mismatch");
        require(!0 < (arg0));
        require(0 < (arg0));
        require(!(((0 + ((0x04 + arg0) + 0x20)) + 0x20) - (0 + ((0x04 + arg0) + 0x20))) < 0x20);
        require(((0 + (arg0 + 0x20)) + 0) == (address((0 + (arg0 + 0x20)) + 0)));
        require(0 < (arg1));
        require(!((arg1 + 0x20) + ((arg1 + 0x20) + 0)) > 0xffffffffffffffff);
        (bool success, bytes memory ret0) = address((0 + (arg0 + 0x20)) + 0).transfer(0);
        require(ret0.length == 0);
        require(0 < (arg0));
        require(!(((0 + ((0x04 + arg0) + 0x20)) + 0x20) - (0 + ((0x04 + arg0) + 0x20))) < 0x20);
        require(((0 + (arg0 + 0x20)) + 0) == (address((0 + (arg0 + 0x20)) + 0)));
        require(0 < (arg1));
        require(!((arg1 + 0x20) + ((arg1 + 0x20) + 0)) > 0xffffffffffffffff);
        require(0x77dd9a93d7a1ab9dd3bdd4a70a51b2e8c9b2350d);
        emit DecryptionFailed();
        require(msg.value - 0);
        (bool success, bytes memory ret0) = address(0x77dd9a93d7a1ab9dd3bdd4a70a51b2e8c9b2350d).transfer(msg.value);
        require(ret0.length == 0);
        emit NativeForwarded(msg.value, success);
        emit NativeForwarded(msg.value, success);
    }
    
    /// @custom:selector    0xbca8c7b5
    /// @custom:signature   Unresolved_bca8c7b5(address arg0, uint256 arg1) public payable
    /// @param              arg0 ["address", "uint160", "bytes20", "int160"]
    /// @param              arg1 ["uint256", "bytes32", "int256"]
    function Unresolved_bca8c7b5(address arg0, uint256 arg1) public payable {
        require(arg0 == (address(arg0)));
        require(!arg1 > 0xffffffffffffffff);
        require(!(arg1) > 0xffffffffffffffff);
        (bool success, bytes memory ret0) = address(arg0).transfer(0);
        require(ret0.length == 0);
        emit CallExecuted(address(arg0), (var_d + 0x60) - var_d, success, (arg1));
        require(0x77dd9a93d7a1ab9dd3bdd4a70a51b2e8c9b2350d);
        emit DecryptionFailed();
        require(msg.value - 0);
        (bool success, bytes memory ret0) = address(0x77dd9a93d7a1ab9dd3bdd4a70a51b2e8c9b2350d).transfer(msg.value);
        require(ret0.length == 0);
        emit NativeForwarded(msg.value, success);
        emit NativeForwarded(msg.value, success);
    }
    
    /// @custom:selector    0x2c7bddf4
    /// @custom:signature   loserSweepETH_11435948882() public
    function loserSweepETH_11435948882() public {
        if (0x77dd9a93d7a1ab9dd3bdd4a70a51b2e8c9b2350d) {
            emit DecryptionFailed();
            if (!address(this).balance > 0) {
                (bool success, bytes memory ret0) = address(0x77dd9a93d7a1ab9dd3bdd4a70a51b2e8c9b2350d).transfer(address(this).balance);
                if (ret0.length == 0) {
                    emit NativeForwarded(address(this).balance, success);
                    emit NativeForwarded(address(this).balance, success);
                }
            }
        }
    }
}