pragma solidity >=0.4.15;

contract AdminControl {
    /*** Query Functions ***/
    /**
     * @dev get admin of specific contract
     * @param contractAddr The address of specific contract
     */
    function getAdmin(address contractAddr) public view returns (address) {}
    
    /**
     * @dev Contract admin set the administrator of contract `contractAddr` to `newAdmin`.
     * @param contractAddr The address of the contract
     * @param newAdmin The new admin address
     */
    function setAdmin(address contractAddr, address newAdmin) public {}

   /**
     * @dev Contract admin destroy contract `contractAddr`.
     * @param contractAddr The contract to be destroied
     */
    function destroy(address contractAddr) public {}
}
