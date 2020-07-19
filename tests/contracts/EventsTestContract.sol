pragma solidity >=0.4.22 <0.6.0;
contract EventsTestContract {

    uint32 counter_foo;
    uint32 counter_bar;

    event Constructed(address indexed by, address data);
    event Foo(address indexed by, uint32 indexed num);
    event Bar(address indexed by, uint32 indexed num);

    constructor() public {
        emit Constructed(msg.sender, msg.sender);
    }

    function foo() public {
        counter_foo += 1;
        emit Foo(msg.sender, counter_foo);
    }

    function bar() public {
        emit Bar(msg.sender, counter_bar);
        counter_bar += 1;

        emit Bar(msg.sender, counter_bar);
        counter_bar += 1;
    }
}
