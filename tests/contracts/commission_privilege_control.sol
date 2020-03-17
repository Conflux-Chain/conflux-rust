pragma solidity >=0.4.15;

import "https://github.com/Conflux-Chain/conflux-rust/blob/master/internal_contract/contracts/SponsorWhitelistControl.sol";

contract CommissionPrivilegeTest {
    mapping(uint => uint) public ss;

    function add(address account) public payable {
        SponsorWhitelistControl cpc = SponsorWhitelistControl(0x8ad036480160591706c831f0DA19D1a424e39469);
        address[] memory a = new address[](1);
        a[0] = account;
        cpc.add_privilege(a);
    }

    function remove(address account) public payable {
        SponsorWhitelistControl cpc = SponsorWhitelistControl(0x8ad036480160591706c831f0DA19D1a424e39469);
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