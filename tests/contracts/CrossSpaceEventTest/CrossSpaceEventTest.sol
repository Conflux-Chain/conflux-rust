// SPDX-License-Identifier: MIT
pragma solidity >=0.8.0;

interface CrossSpaceCall {
    function callEVM(bytes20, bytes calldata) external payable returns (bytes memory output);
}

contract CrossSpaceEventTestConfluxSide {
    CrossSpaceCall constant CROSS_SPACE = CrossSpaceCall(0x0888000000000000000000000000000000000006);

    event TestEvent(uint256);

    function emitConflux(uint256 n) external {
        emit TestEvent(n);
    }

    function emitBoth(uint256 n, bytes20 addr) external {
        emit TestEvent(n);
        CROSS_SPACE.callEVM(addr, abi.encodeWithSelector(CrossSpaceEventTestEVMSide.emitEVM.selector, n));
    }

    function emitComplex(uint256 n, bytes20 addr) external {
        emit TestEvent(n);
        CROSS_SPACE.callEVM(addr, abi.encodeWithSelector(CrossSpaceEventTestEVMSide.emitEVM.selector, n));
        emit TestEvent(n);
        CROSS_SPACE.callEVM(addr, abi.encodeWithSelector(CrossSpaceEventTestEVMSide.emitMultipleEVM.selector, n, 2));
        emit TestEvent(n);
    }
}

contract CrossSpaceEventTestEVMSide {
    event TestEvent(uint256);

    function emitEVM(uint256 n) external {
        emit TestEvent(n);
    }

    function emitMultipleEVM(uint256 n, uint256 times) external {
        for (uint256 ii = 0; ii < times; ++ii) {
            emit TestEvent(n);
        }
    }

    function getBlockNumber() external view returns (uint256) {
        return block.number;
    }
}
