pragma solidity >=0.4.15;
contract CommissionPrivilegeControl {
    // ------------------------------------------------------------------------
    // Someone will sponsor the gas cost for contract `contract_addr` with an
    // `upper_bound` for a single transaction.
    // ------------------------------------------------------------------------
    function set_sponsor_for_gas(address contract_addr, uint upper_bound) public {
    }

    // ------------------------------------------------------------------------
    // Someone will sponsor the storage collateral for contract `contract_addr`.
    // ------------------------------------------------------------------------
    function set_sponsor_for_collateral(address contract_addr) public {
    }

    // ------------------------------------------------------------------------
    // Add commission privilege for address `user` to some contract.
    // ------------------------------------------------------------------------
    function add_privilege(address[] memory) public {
    }

    // ------------------------------------------------------------------------
    // Remove commission privilege for address `user` from some contract.
    // ------------------------------------------------------------------------
    function remove_privilege(address[] memory) public {
    }
}

contract CommissionPrivilegeTest {
    mapping(uint => uint) public ss;

    function add(address account) public payable {
        CommissionPrivilegeControl cpc = CommissionPrivilegeControl(0x8ad036480160591706c831f0DA19D1a424e39469);
        address[] memory a = new address[](1);
        a[0] = account;
        cpc.add_privilege(a);
    }

    function remove(address account) public payable {
        CommissionPrivilegeControl cpc = CommissionPrivilegeControl(0x8ad036480160591706c831f0DA19D1a424e39469);
        address[] memory a = new address[](1);
        a[0] = account;
        cpc.remove_privilege(a);
    }

    function foo() public payable {
    }

    function par_add(uint start, uint end) public payable {
        for (uint i = start; i < end; i++) {
            ss[i] = 1;
        }
    }
    function par_del(uint start, uint end) public payable {
        for (uint i = start; i < end; i++) {
            ss[i] = 0;
        }
    }
}