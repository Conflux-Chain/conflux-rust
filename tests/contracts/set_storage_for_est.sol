pragma solidity >=0.7.0 <0.9.0;

contract SetStorage {

    uint256[10] data;

    function inc_prefix(uint256 n) external {
        require(n<10);
        for(uint i=0; i<n; i++){
            data[i]+=1;
        }
    }

    function reset() public {
        for(uint i=0; i<10; i++){
            data[i]=0;
        }
    }
}