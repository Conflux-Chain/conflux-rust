use cfx_types::{Address, U256};

pub trait InterpreterInfo {
    fn gas_remainning(&self) -> U256;

    fn program_counter(&self) -> u64;

    fn current_opcode(&self) -> u8;

    fn opcode(&self, pc: u64) -> Option<u8>;

    fn mem(&self) -> &Vec<u8>;

    fn stack(&self) -> &Vec<U256>;

    fn return_stack(&self) -> &Vec<usize>;

    fn contract_address(&self) -> Address;
}
