pragma solidity >=0.4.15;

contract ReentrancyConfig {

    /**
     * @dev set contract reentrancy config from contract
     * @param allowance True or false to configure the config
     */
    function allowReentrancy(bool allowance) public {}

    /**
     * @dev set contract reentrancy through contract admin
     * @param allowance True or false to configure the config
     */
    function allowReentrancyByAdmin(address contractAddr, bool allowance) public {}

    /**
     * @dev check whether contract is allowed reentrancy
     * @param contractAddr The contract address to check
     * @return boolean
     */
    function isReentrancyAllowed(address contractAddr) public view returns (bool){}
}
