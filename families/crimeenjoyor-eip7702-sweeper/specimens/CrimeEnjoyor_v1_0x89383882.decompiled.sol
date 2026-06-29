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
    address public destination;
    
    
    /// @custom:selector    0xc4d66de8
    /// @custom:signature   initialize(address arg0) public
    /// @param              arg0 ["address", "uint160", "bytes20", "int160"]
    function initialize(address arg0) public {
        require(arg0 == (address(arg0)));
        require(address(arg0) - 0, "Invalid destination");
        destination = (address(arg0) * 0x01) | (uint96(destination));
    }
}