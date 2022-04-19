// SPDX-License-Identifier: MIT
pragma solidity =0.8.12;

interface CrossSpaceCall {
    function createEVM(bytes calldata init) external payable returns (bytes20);

    function transferEVM(bytes20 to) external payable returns (bytes memory output);

    function callEVM(bytes20 to, bytes calldata data) external payable returns (bytes memory output);

    function staticCallEVM(bytes20 to, bytes calldata data) external view returns (bytes memory output);

    // function deployEip1820() external;

    function withdrawFromMapped(uint256 value) external;
}

contract CrossSpaceTraceTestConfluxSide {
    CrossSpaceCall constant CROSS_SPACE = CrossSpaceCall(0x0888000000000000000000000000000000000006);

    function callEVM(bytes20 addr, uint256 depth) external {
        CROSS_SPACE.callEVM(addr, abi.encodeCall(CrossSpaceTraceTestEVMSide.call, depth));
    }

    function callEVMAndSetStorage(bytes20 addr, uint256 depth) external {
        callEVM(addr, depth);

        assembly {
            sstore(0, 1)
        }
    }

    function staticCallEVM(bytes20 addr, uint256 depth) external view {
        CROSS_SPACE.staticCallEVM(addr, abi.encodeCall(CrossSpaceTraceTestEVMSide.call, depth));
    }

    function createEVM(bytes calldata init) external {
        CROSS_SPACE.createEVM(init);
    }

    function transferEVM(bytes20 addr) external payable {
        CROSS_SPACE.transferEVM{ value: msg.value / 2 }(addr);
        CROSS_SPACE.transferEVM{ value: msg.value / 2 }(addr);
    }

    function withdrawFromMapped(uint256 value) external {
        CROSS_SPACE.withdrawFromMapped(value);
    }

    function fail(bytes20 addr) external {
        CROSS_SPACE.callEVM(addr, abi.encodeCall(CrossSpaceTraceTestEVMSide.fail, ()));
    }

    function subcallFail(bytes20 addr) external {
        try CROSS_SPACE.callEVM(addr, abi.encodeCall(CrossSpaceTraceTestEVMSide.fail, ())) {
            revert("Should fail");
        } catch Error (string memory /*reason*/) {
            // EMPTY
        }
    }
}

contract CrossSpaceTraceTestEVMSide {
    function call(uint256 depth) external returns (uint256) {
        if (depth == 0) return 0;
        this.call(depth - 1);
        return depth;
    }

    function fail() external pure {
        revert("Oh no!");
    }
}
