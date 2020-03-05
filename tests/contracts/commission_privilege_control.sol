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
        CommissionPrivilegeControl cpc = CommissionPrivilegeControl(0x5ad036480160591706c831f0da19D1a424e39469);
        cpc.commission_balance(10 ** 18);
        address[] memory a = new address[](1);
        a[0] = address(0xfbe45681Ac6C53D5a40475F7526baC1FE7590fb8);
        cpc.add_privilege(a);
    }

    function remove() public payable {
        CommissionPrivilegeControl cpc = CommissionPrivilegeControl(0x5ad036480160591706c831f0da19D1a424e39469);
        address[] memory a = new address[](1);
        a[0] = address(0xfbe45681Ac6C53D5a40475F7526baC1FE7590fb8);
        cpc.remove_privilege(a);
    }

    function foo() public payable {
    }
}