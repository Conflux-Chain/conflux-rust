
pragma solidity >=0.5.0;


contract Dai{
    event Log(address indexed addr, uint indexed value);
    mapping (address => uint) public wards;
    function set1(address guy) external { 
      emit Log(guy, wards[guy]);
      emit Log(msg.sender, wards[msg.sender]);
      wards[guy] = 1; 
      emit Log(guy, wards[guy]);
      emit Log(msg.sender, wards[msg.sender]);
    }
    function set0(address guy) external { 
      emit Log(guy, wards[guy]);
      emit Log(msg.sender, wards[msg.sender]);
      wards[guy] = 0; 
      emit Log(guy, wards[guy]);
      emit Log(msg.sender, wards[msg.sender]);
    }
    function set2(address guy) external { 
      emit Log(guy, wards[guy]);
      emit Log(msg.sender, wards[msg.sender]);
      wards[guy] = 2; 
      emit Log(guy, wards[guy]);
      emit Log(msg.sender, wards[msg.sender]);
    }
    constructor(uint256 chainId_) public {
        wards[msg.sender] = 2;
    }
}

