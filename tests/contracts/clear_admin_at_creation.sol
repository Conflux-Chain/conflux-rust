pragma solidity >=0.7.0;

import "internal/AdminControl.sol";

contract AdminTestContract {
    address public constant EVIL_ADDR = 0x1000000000000000000000000000000000000000;
    address constant ADMIN_CONTROL_ADDR = 0x0888000000000000000000000000000000000000;

    constructor() {
        AdminControl ac = AdminControl(ADMIN_CONTROL_ADDR);
        // This should fail
        hijackAdmin();
        require(ac.getAdmin(address(this)) != EVIL_ADDR, "require admin != evil");
        // This should fail
        address(this).call(abi.encodeWithSignature("clearAdmin()"));
        require(ac.getAdmin(address(this)) != address(0), "require admin != null");
        // This should succeed
        ac.setAdmin(address(this), address(0));
        require(ac.getAdmin(address(this)) == address(0), "require admin == null");
    }

    function deployAndHijackAdmin(bytes memory code) external payable returns (address) {
        address addr;
        bool success = true;
        uint value = msg.value;
        assembly {
            addr := create(value, add(code, 0x20), mload(code))
            if iszero(extcodesize(addr)) {
              success := 0
            }
        }
        require(success, "create failed");

        // Hijack the admin to an evil party.
        AdminControl ac = AdminControl(ADMIN_CONTROL_ADDR);
        ac.setAdmin(addr, EVIL_ADDR);
        // Hijack the admin to null.
        ac.setAdmin(addr, address(0));
        return addr;
    }

    function clearAdmin() public {
        AdminControl ac = AdminControl(ADMIN_CONTROL_ADDR);
        ac.setAdmin(address(this), address(0));
    }

    function hijackAdmin() public payable {
        // Hijack the admin to an evil party.
        AdminControl ac = AdminControl(ADMIN_CONTROL_ADDR);
        ac.setAdmin(msg.sender, EVIL_ADDR);
    }
}
