// Copyright 2021 Conflux Foundation. All rights reserved.
// Conflux is free software and distributed under GNU General Public License.
// See http://www.gnu.org/licenses/

use std::marker::PhantomData;

use cfx_parameters::internal_contract_addresses::CROSS_SPACE_CONTRACT_ADDRESS;
use cfx_types::{Address, AddressSpaceUtil, AddressWithSpace, H160, U256};
use primitives::storage::STORAGE_LAYOUT_REGULAR_V0;

use cfx_vm_types::CallType;

use super::{super::impls::cross_space::*, preludes::*};

type Bytes = Vec<u8>;
type Bytes20 = [u8; 20];

make_solidity_contract! {
    pub struct CrossSpaceCall(CROSS_SPACE_CONTRACT_ADDRESS, generate_fn_table, initialize: |params: &CommonParams| params.transition_numbers.cip90b, is_active: |spec: &Spec| spec.cip90);
}

fn generate_fn_table() -> SolFnTable {
    make_function_table!(
        CreateToEVM,
        TransferToEVM,
        CallToEVM,
        StaticCallToEVM,
        Withdraw,
        MappedBalance,
        MappedNonce,
        DeployEip1820
    )
}

group_impl_is_active!(
    |spec: &Spec| spec.cip90,
    CreateToEVM,
    TransferToEVM,
    CallToEVM,
    StaticCallToEVM,
    Withdraw,
    MappedBalance,
    MappedNonce,
    DeployEip1820,
);

make_solidity_event! {
    pub struct CallEvent("Call(bytes20,bytes20,uint256,uint256,bytes)", indexed: (Bytes20, Bytes20), non_indexed: (U256, U256, Bytes));
}

make_solidity_event! {
    pub struct CreateEvent("Create(bytes20,bytes20,uint256,uint256,bytes)", indexed: (Bytes20, Bytes20), non_indexed: (U256, U256, Bytes));
}

make_solidity_event! {
    pub struct WithdrawEvent("Withdraw(bytes20,address,uint256,uint256)", indexed: (Bytes20, Address), non_indexed: (U256,U256));
}

make_solidity_event! {
    pub struct ReturnEvent("Outcome(bool)", indexed: (), non_indexed: bool);
}

pub mod events {
    pub use super::{CallEvent, CreateEvent, ReturnEvent, WithdrawEvent};
}

make_solidity_function! {
    pub struct CreateToEVM(Bytes, "createEVM(bytes)", Bytes20);
}

impl_function_type!(CreateToEVM, "payable_write");

impl UpfrontPaymentTrait for CreateToEVM {
    fn upfront_gas_payment(
        &self, init: &Bytes, _params: &ActionParams,
        context: &InternalRefContext,
    ) -> DbResult<U256> {
        create_gas(context, init.as_ref())
    }
}

impl ExecutionTrait for CreateToEVM {
    fn execute_inner(
        &self, init: Bytes, params: &ActionParams, gas_left: U256,
        context: &mut InternalRefContext,
    ) -> InternalTrapResult<Bytes20> {
        let trap = create_to_evmcore(init, None, params, gas_left, context);
        process_trap(trap, PhantomData)
    }
}

make_solidity_function! {
    pub struct TransferToEVM(Bytes20, "transferEVM(bytes20)", Bytes);
}

impl_function_type!(TransferToEVM, "payable_write");

impl UpfrontPaymentTrait for TransferToEVM {
    fn upfront_gas_payment(
        &self, receiver: &Bytes20, params: &ActionParams,
        context: &InternalRefContext,
    ) -> DbResult<U256> {
        call_gas(H160(*receiver), params, context, &vec![])
    }
}

impl ExecutionTrait for TransferToEVM {
    fn execute_inner(
        &self, to: Bytes20, params: &ActionParams, gas_left: U256,
        context: &mut InternalRefContext,
    ) -> InternalTrapResult<Bytes> {
        let trap = call_to_evmcore(
            H160(to),
            vec![],
            CallType::Call,
            params,
            gas_left,
            context,
        );
        process_trap(trap, PhantomData)
    }
}

make_solidity_function! {
    pub struct CallToEVM((Bytes20,Bytes), "callEVM(bytes20,bytes)", Bytes);
}

impl_function_type!(CallToEVM, "payable_write");

impl UpfrontPaymentTrait for CallToEVM {
    fn upfront_gas_payment(
        &self, (ref receiver, ref data): &(Bytes20, Bytes),
        params: &ActionParams, context: &InternalRefContext,
    ) -> DbResult<U256> {
        call_gas(H160(*receiver), params, context, data)
    }
}

impl ExecutionTrait for CallToEVM {
    fn execute_inner(
        &self, (to, data): (Bytes20, Bytes), params: &ActionParams,
        gas_left: U256, context: &mut InternalRefContext,
    ) -> InternalTrapResult<Bytes> {
        let trap = call_to_evmcore(
            H160(to),
            data,
            CallType::Call,
            params,
            gas_left,
            context,
        );
        process_trap(trap, PhantomData)
    }
}

make_solidity_function! {
    struct StaticCallToEVM((Bytes20,Bytes), "staticCallEVM(bytes20,bytes)", Bytes);
}

impl_function_type!(StaticCallToEVM, "query");

impl UpfrontPaymentTrait for StaticCallToEVM {
    fn upfront_gas_payment(
        &self, _: &(Bytes20, Bytes), _params: &ActionParams,
        context: &InternalRefContext,
    ) -> DbResult<U256> {
        Ok(static_call_gas(context.spec))
    }
}

impl ExecutionTrait for StaticCallToEVM {
    fn execute_inner(
        &self, (to, data): (Bytes20, Bytes), params: &ActionParams,
        gas_left: U256, context: &mut InternalRefContext,
    ) -> InternalTrapResult<Bytes> {
        let trap = call_to_evmcore(
            H160(to),
            data,
            CallType::StaticCall,
            params,
            gas_left,
            context,
        );
        process_trap(trap, PhantomData)
    }
}

make_solidity_function! {
    pub struct Withdraw(U256, "withdrawFromMapped(uint256)");
}

impl_function_type!(Withdraw, "non_payable_write");

impl UpfrontPaymentTrait for Withdraw {
    fn upfront_gas_payment(
        &self, _: &U256, _params: &ActionParams, context: &InternalRefContext,
    ) -> DbResult<U256> {
        Ok(withdraw_gas(context.spec))
    }
}

impl SimpleExecutionTrait for Withdraw {
    fn execute_inner(
        &self, value: U256, params: &ActionParams,
        context: &mut InternalRefContext,
    ) -> vm::Result<()> {
        withdraw_from_evmcore(params.sender, value, params, context)
    }
}

make_solidity_function! {
    struct MappedBalance(Address, "mappedBalance(address)", U256);
}

impl_function_type!(MappedBalance, "query", gas: |spec: &Spec| spec.balance_gas + spec.sha3_gas);

impl SimpleExecutionTrait for MappedBalance {
    fn execute_inner(
        &self, addr: Address, _params: &ActionParams,
        context: &mut InternalRefContext,
    ) -> vm::Result<U256> {
        mapped_balance(addr, context)
    }
}

make_solidity_function! {
    struct MappedNonce(Address, "mappedNonce(address)", U256);
}

impl_function_type!(MappedNonce, "query", gas: |spec: &Spec| spec.balance_gas + spec.sha3_gas);

impl SimpleExecutionTrait for MappedNonce {
    fn execute_inner(
        &self, addr: Address, _params: &ActionParams,
        context: &mut InternalRefContext,
    ) -> vm::Result<U256> {
        mapped_nonce(addr, context)
    }
}

make_solidity_function! {
    struct DeployEip1820((), "deployEip1820()");
}

impl_function_type!(DeployEip1820, "non_payable_write", gas: |spec:&Spec| spec.eip1820_gas);

impl SimpleExecutionTrait for DeployEip1820 {
    fn execute_inner(
        &self, _: (), _params: &ActionParams, context: &mut InternalRefContext,
    ) -> vm::Result<()> {
        let address: AddressWithSpace = eip_1820::ADDRESS.with_evm_space();
        if context.state.is_contract_with_code(&address)? {
            return Err(vm::Error::InternalContract(
                "eip-1820 contract has been deployed.".to_string(),
            ));
        }
        context.state.new_contract_with_admin(
            &address,
            /* admin */ &Address::zero(),
            /* balance */ U256::zero(),
            Some(STORAGE_LAYOUT_REGULAR_V0),
            context.spec.cip107,
        )?;
        context.state.init_code(
            &address,
            eip_1820::BYTE_CODE.clone(),
            Address::zero(),
        )?;
        context.substate.contracts_created.push(address);
        Ok(())
    }
}

pub fn is_call_create_sig(data: &[u8]) -> bool {
    data == TransferToEVM::FUNC_SIG
        || data == CreateToEVM::FUNC_SIG
        || data == CallToEVM::FUNC_SIG
}

pub fn is_withdraw_sig(data: &[u8]) -> bool { data == Withdraw::FUNC_SIG }

#[test]
fn test_cross_space_contract_sig() {
    check_func_signature!(CreateToEVM, "ff311601");
    check_func_signature!(TransferToEVM, "da8d5daf");
    check_func_signature!(CallToEVM, "bea05ee3");
    check_func_signature!(StaticCallToEVM, "30b4ef7d");
    check_func_signature!(Withdraw, "c23ef031");
    check_func_signature!(MappedBalance, "142b37c7");
    check_func_signature!(MappedNonce, "b5914944");
    check_func_signature!(DeployEip1820, "36201722");

    check_event_signature!(
        CallEvent,
        "124d1efd3ac32fa6aadb7a06e066c113471e0411fb56a5079cedbc3cdf7796e4"
    );
    check_event_signature!(
        CreateEvent,
        "d4f6dc315981682d51417b7092f1a151bfc6ebc3f637532f97ac479b86c4076d"
    );
    check_event_signature!(
        WithdrawEvent,
        "31328e08abcc622b23d8be96d45b371b10e42989dafc8ac56c85b33bb3584b92"
    );
    check_event_signature!(
        ReturnEvent,
        "bc11eabb6efd378a0a489b58a574c6e0d0403060e8a8c7b8eab45db47900edfe"
    );
}

mod eip_1820 {
    pub use rustc_hex::FromHex;

    use super::Address;

    const HEX_ADDRESS: &'static str =
        "1820a4b7618bde71dce8cdc73aab6c95905fad24";
    const HEX_BYTE_CODE: &'static str = "608060405234801561001057600080fd5b50600436106100a5576000357c010000000000000000000000000000000000000000000000000000000090048063a41e7d5111610078578063a41e7d51146101d4578063aabbb8ca1461020a578063b705676514610236578063f712f3e814610280576100a5565b806329965a1d146100aa5780633d584063146100e25780635df8122f1461012457806365ba36c114610152575b600080fd5b6100e0600480360360608110156100c057600080fd5b50600160a060020a038135811691602081013591604090910135166102b6565b005b610108600480360360208110156100f857600080fd5b5035600160a060020a0316610570565b60408051600160a060020a039092168252519081900360200190f35b6100e06004803603604081101561013a57600080fd5b50600160a060020a03813581169160200135166105bc565b6101c26004803603602081101561016857600080fd5b81019060208101813564010000000081111561018357600080fd5b82018360208201111561019557600080fd5b803590602001918460018302840111640100000000831117156101b757600080fd5b5090925090506106b3565b60408051918252519081900360200190f35b6100e0600480360360408110156101ea57600080fd5b508035600160a060020a03169060200135600160e060020a0319166106ee565b6101086004803603604081101561022057600080fd5b50600160a060020a038135169060200135610778565b61026c6004803603604081101561024c57600080fd5b508035600160a060020a03169060200135600160e060020a0319166107ef565b604080519115158252519081900360200190f35b61026c6004803603604081101561029657600080fd5b508035600160a060020a03169060200135600160e060020a0319166108aa565b6000600160a060020a038416156102cd57836102cf565b335b9050336102db82610570565b600160a060020a031614610339576040805160e560020a62461bcd02815260206004820152600f60248201527f4e6f7420746865206d616e616765720000000000000000000000000000000000604482015290519081900360640190fd5b6103428361092a565b15610397576040805160e560020a62461bcd02815260206004820152601a60248201527f4d757374206e6f7420626520616e204552433136352068617368000000000000604482015290519081900360640190fd5b600160a060020a038216158015906103b85750600160a060020a0382163314155b156104ff5760405160200180807f455243313832305f4143434550545f4d4147494300000000000000000000000081525060140190506040516020818303038152906040528051906020012082600160a060020a031663249cb3fa85846040518363ffffffff167c01000000000000000000000000000000000000000000000000000000000281526004018083815260200182600160a060020a0316600160a060020a031681526020019250505060206040518083038186803b15801561047e57600080fd5b505afa158015610492573d6000803e3d6000fd5b505050506040513d60208110156104a857600080fd5b5051146104ff576040805160e560020a62461bcd02815260206004820181905260248201527f446f6573206e6f7420696d706c656d656e742074686520696e74657266616365604482015290519081900360640190fd5b600160a060020a03818116600081815260208181526040808320888452909152808220805473ffffffffffffffffffffffffffffffffffffffff19169487169485179055518692917f93baa6efbd2244243bfee6ce4cfdd1d04fc4c0e9a786abd3a41313bd352db15391a450505050565b600160a060020a03818116600090815260016020526040812054909116151561059a5750806105b7565b50600160a060020a03808216600090815260016020526040902054165b919050565b336105c683610570565b600160a060020a031614610624576040805160e560020a62461bcd02815260206004820152600f60248201527f4e6f7420746865206d616e616765720000000000000000000000000000000000604482015290519081900360640190fd5b81600160a060020a031681600160a060020a0316146106435780610646565b60005b600160a060020a03838116600081815260016020526040808220805473ffffffffffffffffffffffffffffffffffffffff19169585169590951790945592519184169290917f605c2dbf762e5f7d60a546d42e7205dcb1b011ebc62a61736a57c9089d3a43509190a35050565b600082826040516020018083838082843780830192505050925050506040516020818303038152906040528051906020012090505b92915050565b6106f882826107ef565b610703576000610705565b815b600160a060020a03928316600081815260208181526040808320600160e060020a031996909616808452958252808320805473ffffffffffffffffffffffffffffffffffffffff19169590971694909417909555908152600284528181209281529190925220805460ff19166001179055565b600080600160a060020a038416156107905783610792565b335b905061079d8361092a565b156107c357826107ad82826108aa565b6107b85760006107ba565b815b925050506106e8565b600160a060020a0390811660009081526020818152604080832086845290915290205416905092915050565b6000808061081d857f01ffc9a70000000000000000000000000000000000000000000000000000000061094c565b909250905081158061082d575080155b1561083d576000925050506106e8565b61084f85600160e060020a031961094c565b909250905081158061086057508015155b15610870576000925050506106e8565b61087a858561094c565b909250905060018214801561088f5750806001145b1561089f576001925050506106e8565b506000949350505050565b600160a060020a0382166000908152600260209081526040808320600160e060020a03198516845290915281205460ff1615156108f2576108eb83836107ef565b90506106e8565b50600160a060020a03808316600081815260208181526040808320600160e060020a0319871684529091529020549091161492915050565b7bffffffffffffffffffffffffffffffffffffffffffffffffffffffff161590565b6040517f01ffc9a7000000000000000000000000000000000000000000000000000000008082526004820183905260009182919060208160248189617530fa90519096909550935050505056fea165627a7a72305820377f4a2d4301ede9949f163f319021a6e9c687c292a5e2b2c4734c126b524e6c0029";

    lazy_static! {
        pub static ref ADDRESS: Address = HEX_ADDRESS.parse().unwrap();
        pub static ref BYTE_CODE: Vec<u8> = HEX_BYTE_CODE.from_hex().unwrap();
    }
}
