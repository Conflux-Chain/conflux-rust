// SPDX-License-Identifier: MIT
pragma solidity >=0.5.0;

interface CrossSpaceCall {

    function create(bytes calldata init) external payable returns (address);

    function create2(bytes calldata init, bytes32 salt) external payable returns (address);

    function call(address to, bytes calldata data) external payable returns (bytes memory output);

    function staticCall(address to, bytes calldata data) external view returns (address);

    function withdraw(uint256 value) external;
}