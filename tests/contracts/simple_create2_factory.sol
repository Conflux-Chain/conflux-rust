pragma solidity 0.5.1;


/**
 * @title Create2 factory contract
 * @author 0age
 * @notice This contract provides a callCreate2 function that takes a salt value
 * and a block of initialization code as arguments and passes them into inline
 * assembly. There is also a view function that computes the address of the
 * contract that will be created when submitting a given salt or nonce along
 * with a given block of initialization code.
 * @dev Deployed on Ropsten at 0xa779284f095ef2eBb8ee26cd8384e49C57b26996 but
 * CREATE2 will not be available on mainnet until (at least) block
 * 7,080,000. This contract has not yet been fully tested or audited - proceed
 * with caution and please share any exploits or optimizations you discover.
 */
contract SimpleCreate2Factory {
  /**
   * @dev Create a contract using CREATE2 by submitting a given salt or nonce 
   * along with the initialization code for the contract. Note that the first 20
   * bytes of the salt must match those of the calling address, which prevents
   * contract creation events from being submitted by unintended parties.
   * @param salt bytes32 The nonce that will be passed into the CREATE2 call.
   * @param initializationCode bytes The initialization code that will be passed
   * into the CREATE2 call.
   * @return Address of the contract that will be created, or the null address
   * if a contract already exists at that address.
   */
  function callCreate2(
    uint256 salt,
    bytes calldata initializationCode
  ) external payable returns (address deploymentAddress) {
    // move the initialization code from calldata to memory. (use calldataload?)
    bytes memory initCode = initializationCode;

    // using inline assembly: load data and length of data, then call CREATE2.
    assembly { // solhint-disable-line
      let encoded_data := add(0x20, initCode) // load initialization code.
      let encoded_size := mload(initCode)     // load the init code's length.
      
      deploymentAddress := create2(           // call CREATE2 with 4 arguments.
        callvalue,                            // forward any attached value.
        encoded_data,                         // pass in initialization code.
        encoded_size,                         // pass in init code's length.
        salt                                  // pass in the salt value.
      )
    }

    // ensure that the contract address is not equal to the null address.
    require(
      deploymentAddress != address(0),
      "Failed to deploy contract using provided salt and initialization code."
    );
  }
}