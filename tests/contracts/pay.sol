pragma solidity ^0.5.0;

contract CheckPay {
    
    event transferMark(address indexed addr, uint val);
    
    function recharge()
        external
        payable
    {
    }
    
    function withdraw(address payable receiver)
        external
    {
        emit transferMark(receiver, address(this).balance);
        receiver.transfer(address(this).balance);
        emit transferMark(receiver, address(this).balance);
    }

}

