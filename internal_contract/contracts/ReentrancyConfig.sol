pragma solidity >=0.4.15;

contract ReentrancyConfig {

    function allowReentrancy(bool allowance) public {}

    function allowReentrancyByAdmin(address contractAddr, bool allowance) public {}

    function isReentrancyAllowed(address contractAddr) public view returns (bool){}
}
