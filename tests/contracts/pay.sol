pragma solidity ^0.5.0;

contract CheckPay {
    
    function recharge()
        external
        payable
    {
    }
    
    function withdraw(address payable receiver)
        external
    {
        receiver.transfer(address(this).balance);
    }

}

