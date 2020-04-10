pragma solidity >=0.4.15;

import "https://github.com/Conflux-Chain/conflux-rust/blob/master/internal_contract/contracts/AdminControl.sol";

contract AdminControlProxy {
    function set_admin(address cont, address admin) public payable {
        AdminControl ac = AdminControl(
            0x8060dE9e1568e69811C4a398f92c3D10949dC891
        );
        ac.set_admin(cont, admin);
    }

    function destroy(address cont) public payable {
        AdminControl ac = AdminControl(
            0x8060dE9e1568e69811C4a398f92c3D10949dC891
        );
        ac.destroy(cont);
    }
}
