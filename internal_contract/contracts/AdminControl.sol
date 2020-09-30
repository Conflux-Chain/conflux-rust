pragma solidity >=0.4.15;

contract AdminControl {
    /*** Query Functions ***/
    /**
     * @dev get admin of specific contract
     * @param contractAddr The address of specific contract
     */
    function getAdmin(address contractAddr) public returns (address) {}

    function setAdmin(address, address) public {}
    function destroy(address) public {}
}