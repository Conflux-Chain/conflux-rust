// SPDX-License-Identifier: MIT
pragma solidity >=0.5.0;

interface CrossSpaceCall {

    function createEVM(bytes calldata init) external payable returns (bytes20);

    function create2EVM(bytes calldata init, bytes32 salt) external payable returns (bytes20);

    function transferEVM(bytes20 to) external payable returns (bytes memory output);

    function callEVM(bytes20 to, bytes calldata data) external payable returns (bytes memory output);

    function staticCallEVM(bytes20 to, bytes calldata data) external view returns (bytes memory output);

    function withdrawFromMapped(uint256 value) external;

    function mappedBalance(address addr) external view returns (uint256);

    function mappedNonce(address addr) external view returns (uint256);
}