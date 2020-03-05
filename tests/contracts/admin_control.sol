pragma solidity >=0.4.15;
contract AdminControl {
    function set_admin(address, address) public {}

    function destroy(address) public {}
}

contract AdminControlProxy {
    function set_admin(address cont, address admin) public payable {
        AdminControl ac = AdminControl(0x6060dE9e1568e69811C4A398F92c3d10949dc891);
        ac.set_admin(cont, admin);
    }

    function destroy(address cont) public payable {
        AdminControl ac = AdminControl(0x6060dE9e1568e69811C4A398F92c3d10949dc891);
        ac.destroy(cont);
    }
}
