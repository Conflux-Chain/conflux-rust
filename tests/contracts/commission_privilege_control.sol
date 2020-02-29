pragma solidity >=0.4.15;
contract CommissionPrivilegeControl {
    // ------------------------------------------------------------------------
    // Set the commission balance to `balance` for some contract.
    // ------------------------------------------------------------------------
    function commission_balance(uint balance) public;

    // ------------------------------------------------------------------------
    // Add commission privilege for address `user` to some contract.
    // ------------------------------------------------------------------------
    function add_privilege(address[] memory) public;

    // ------------------------------------------------------------------------
    // Remove commission privilege for address `user` from some contract.
    // ------------------------------------------------------------------------
    function remove_privilege(address[] memory) public;
}

contract CommissionPrivilegeTest {
    function set() public payable {
        CommissionPrivilegeControl cpc = CommissionPrivilegeControl(0x8ad036480160591706c831f0DA19D1a424e39469);
        cpc.commission_balance(10 ** 18);
        address[] memory a = new address[](1);
        a[0] = address(0x1BE45681aC6C53D5A40475f7526baC1Fe7590fb8);
        cpc.add_privilege(a);
    }

    function remove() public payable {
        CommissionPrivilegeControl cpc = CommissionPrivilegeControl(0x8ad036480160591706c831f0DA19D1a424e39469);
        address[] memory a = new address[](1);
        a[0] = address(0x1BE45681aC6C53D5A40475f7526baC1Fe7590fb8);
        cpc.remove_privilege(a);
    }

    function foo() public payable {
    }
}
