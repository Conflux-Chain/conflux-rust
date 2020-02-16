mod errors;

heapsize::known_heap_size!(
    0,
    ArcEthBlock,
    EthTxVerifierWIPBlockInfo,
    RealizedEthTx,
    TxMakerTx
);

#[derive(Clone)]
pub struct ArcEthTxExtractor<EthTxType: EthTxTypeTrait>(
    Arc<EthTxExtractor<EthTxType>>,
);

impl<EthTxType: EthTxTypeTrait> HeapSizeOf for ArcEthTxExtractor<EthTxType> {
    fn heap_size_of_children(&self) -> usize { 0 }
}

impl<EthTxType: EthTxTypeTrait> HeapSizeOf
    for EthTxNonceVerifierRequest<EthTxType>
{
    fn heap_size_of_children(&self) -> usize { 0 }
}

#[repr(u32)]
#[derive(Clone, Debug)]
pub enum EthTxType {
    BlockRewardAndTxFee,
    UncleReward,
    Transaction,
    Dao,
    GenesisAccount,
}

const SYSTEM_ACCOUNT_SECRET_BYTES: &str =
    "46b9e861b63d3509c88b7817275a30d22d62c8cd8fa6486ddee35ef0d8e0495f";
lazy_static! {
    static ref SYSTEM_ACCOUNT_SECRET: Secret = {
        Secret::from_slice(
            hexstr_to_h256(&SYSTEM_ACCOUNT_SECRET_BYTES).as_ref(),
        )
        .unwrap()
    };
}

#[derive(Clone, Debug)]
pub struct RealizedEthTx {
    // Sender spends fee + amount.
    // Receiver receives amount.
    sender: Option<H160>,
    // None for conotract creation.
    receiver: Option<H160>,
    tx_fee_wei: U256,
    amount_wei: U256,
    types: EthTxType,
}

impl Encodable for RealizedEthTx {
    fn rlp_append(&self, s: &mut RlpStream) {
        s.begin_list(5)
            .append(&self.sender)
            .append(&self.receiver)
            .append(&self.tx_fee_wei)
            .append(&self.amount_wei)
            .append(&(self.types.clone() as u32));
    }
}

impl Decodable for RealizedEthTx {
    fn decode(rlp: &Rlp) -> Result<Self, DecoderError> {
        Ok(RealizedEthTx {
            sender: rlp.val_at(0)?,
            receiver: rlp.val_at(1)?,
            tx_fee_wei: rlp.val_at(2)?,
            amount_wei: rlp.val_at(3)?,
            types: unsafe { mem::transmute(rlp.val_at::<u32>(4)?) },
        })
    }
}

#[derive(Clone, Default)]
pub struct DaoHardforkInfo {
    dao_hardfork_accounts: Vec<Address>,
    dao_hardfork_beneficiary: Address,
    dao_hardfork_transition: u64,
}

#[derive(Clone)]
pub struct EthTxBasicVerifierRequest<EthTxType: EthTxTypeTrait> {
    basic_verification_index: usize,
    base_transaction_number: u64,
    transaction_index: usize,
    block: Arc<EthBlock>,

    check_low_s: bool,
    chain_id: Option<u64>,
    allow_empty_signature: bool,

    /// To issue transaction verification call afterwards.
    tx_extractor: Arc<EthTxExtractor<EthTxType>>,
}

#[derive(Clone)]
pub struct EthTxNonceVerifierRequest<EthTxType: EthTxTypeTrait> {
    block_number: u64,
    base_transaction_number: u64,
    transaction_index: usize,
    block: Arc<EthBlock>,
    sender: Address,

    /// To issue transaction verification call afterwards.
    tx_extractor: Arc<EthTxExtractor<EthTxType>>,
}

pub struct EthTxVerifierWorkerThread<EthTxT: EthTxTypeTrait> {
    current_nonce_map: BTreeMap<H160, U256>,

    n_contract_creation: u64,
    n_nonce_error: u64,

    tx_sender: Mutex<mpsc::Sender<Option<EthTxNonceVerifierRequest<EthTxT>>>>,

    tx_maker: Arc<Box<dyn TxMaker<TxType = EthTxT> + Send + Sync>>,

    out_streamer: Arc<Mutex<EthTxOutStreamer<EthTxT>>>,

    thread_handle: Option<JoinHandle<Option<()>>>,
}

struct AddressNonceKV(Address, U256);

impl Decodable for AddressNonceKV {
    fn decode(rlp: &Rlp) -> Result<Self, DecoderError> {
        Ok(AddressNonceKV(rlp.val_at(0)?, rlp.val_at(1)?))
    }
}

struct AddressNonceRefKV<'a>(&'a Address, &'a U256);

impl<'a> Encodable for AddressNonceRefKV<'a> {
    fn rlp_append(&self, s: &mut RlpStream) {
        s.begin_list(2).append(self.0).append(self.1);
    }
}

impl<EthTxT: EthTxTypeTrait> EthTxVerifierWorkerThread<EthTxT> {
    pub fn nonce_file_path(
        nonce_dir: &str, block_number: u64, shard_index: usize,
    ) -> String {
        String::from(nonce_dir)
            + "/"
            + &block_number.to_string()
            + "."
            + &shard_index.to_string()
    }

    pub fn load_nonce_map(path: &str) -> BTreeMap<Address, U256> {
        let file_open_result = File::open(&path);
        match file_open_result {
            Ok(mut file) => {
                println!("load nonce file {}", path);
                let mut rlp_bytes = vec![];
                file.read_to_end(&mut rlp_bytes).unwrap();
                let rlp = Rlp::new(&rlp_bytes);
                let list = rlp.as_list::<AddressNonceKV>().unwrap();

                let mut nonce_map: BTreeMap<Address, U256> = Default::default();
                for kv in list {
                    nonce_map.insert(kv.0, kv.1);
                }
                nonce_map
            }
            Err(_) => {
                panic!("Error: nonce file {} not found!", path);
            }
        }
    }

    pub fn save_nonce_map(
        &self, nonce_dir: &str, block_number: u64, shard_index: usize,
    ) {
        let nonce_file_path =
            Self::nonce_file_path(nonce_dir, block_number, shard_index);
        let mut file = File::create(&nonce_file_path).unwrap();

        let mut list = vec![];
        for (key, value) in &self.current_nonce_map {
            list.push(AddressNonceRefKV(key, value));
        }
        let mut rlp_stream = RlpStream::new();
        rlp_stream.append_list(&list);
        let rlp = rlp_stream.drain();

        file.write_all(&rlp).unwrap();
    }

    pub fn new(
        nonce_dir: &str, block_number: u64, thread_index: usize,
        out_streamer: Arc<Mutex<EthTxOutStreamer<EthTxT>>>,
        tx_maker: Arc<Box<dyn TxMaker<TxType = EthTxT> + Send + Sync>>,
    ) -> Arc<Mutex<EthTxVerifierWorkerThread<EthTxT>>>
    {
        let nonce_init_file =
            Self::nonce_file_path(nonce_dir, block_number, thread_index);
        let nonce_map = if block_number == 0 {
            Default::default()
        } else {
            Self::load_nonce_map(&nonce_init_file)
        };

        let (sender, receiver) = mpsc::channel();

        let worker = Arc::new(Mutex::new(EthTxVerifierWorkerThread {
            current_nonce_map: nonce_map,
            n_contract_creation: 0,
            n_nonce_error: 0,
            tx_sender: Mutex::new(sender),
            tx_maker,
            out_streamer,
            thread_handle: None,
        }));

        let weak = Arc::downgrade(&worker);
        let join_handle = thread::spawn(move || -> Option<()> {
            loop {
                let maybe_tx = receiver.recv().ok()?;

                if maybe_tx.is_none() {
                    // An empty request is signal for exit,
                    return Some(());
                } else {
                    let worker = match weak.upgrade() {
                        Some(worker) => worker,
                        None => {
                            println!("tx verifier worker thread exits.");
                            return None;
                        }
                    };
                    let mut worker_mut = worker.lock();
                    let result =
                        worker_mut.verify_tx(maybe_tx.as_ref().unwrap());
                    worker_mut
                        .out_streamer
                        .lock()
                        .set_result(maybe_tx.unwrap(), result);
                }
            }
        });

        worker.lock().thread_handle = Some(join_handle);

        worker
    }

    pub fn finalize(
        &mut self, nonce_dir_path: &str, block_number: u64, shard_index: usize,
    ) {
        println!("stopping verifier worker thread.");

        self.tx_sender.lock().send(None).ok();

        println!(
            "heapsize {}\tEthTxVerifierWorkerThread#current_nonce_map.",
            self.current_nonce_map.heap_size_of_children()
        );

        self.thread_handle.take().unwrap().join().ok();

        self.save_nonce_map(nonce_dir_path, block_number, shard_index);
    }

    pub fn n_contract_creation(&self) -> u64 { self.n_contract_creation }

    pub fn n_nonce_error(&self) -> u64 { self.n_nonce_error }

    pub fn n_accounts(&self) -> usize { self.current_nonce_map.len() }

    pub fn send_request(&self, req: EthTxNonceVerifierRequest<EthTxT>) {
        self.tx_sender.lock().send(Some(req)).unwrap();
    }

    fn check_nonce(&mut self, sender: &Address, nonce: &U256) -> bool {
        let zero_nonce = 0.into();
        let current_nonce =
            self.current_nonce_map.get(sender).unwrap_or(&zero_nonce);
        let result = current_nonce.eq(nonce);
        if !result {
            info!("nonce error: current {}, expected {}", current_nonce, nonce);
        }
        result
    }

    fn verify_tx(
        &mut self, tx_req: &EthTxNonceVerifierRequest<EthTxT>,
    ) -> Option<EthTxT> {
        let tx = unsafe {
            tx_req
                .block
                .transactions
                .get_unchecked(tx_req.transaction_index)
        };

        // Verify and update nonce.
        if !self.check_nonce(&tx_req.sender, &tx.nonce) {
            self.n_nonce_error += 1;
            return None;
        } else {
            self.current_nonce_map
                .insert(tx_req.sender.clone(), tx.nonce + 1);
        }

        // We do not verify the balance. Instead, we allow the balance to go
        // negative, because we are only testing the tps capability of
        // Conflux.

        match tx.action {
            ethcore_types::transaction::Action::Create => {
                // Create a contract.
                // we do not admit creation of contract in verifier
                // simulation.
                self.n_contract_creation += 1;
            }
            _ => {}
        }

        self.tx_maker.convert_tx(&tx, Some(tx_req.sender))
    }

    pub fn exec_reward(&mut self, _tx: &EthTxT) {
        // TODO: it's no-op for the moment because we don't current do anything
        // about account balance.
        unimplemented!()
    }
}

pub struct EthTxVerifier<EthTxType: EthTxTypeTrait> {
    workers: Vec<Arc<Mutex<EthTxVerifierWorkerThread<EthTxType>>>>,
    pub out_streamer: Arc<Mutex<EthTxOutStreamer<EthTxType>>>,
}

impl<EthTxT: EthTxTypeTrait> EthTxVerifier<EthTxT> {
    const N_TX_VERIFIERS: usize = 8;

    pub fn new(
        path_to_tx_file: &str, nonce_dir_path: String, start_block_number: u64,
        tx_maker: Arc<Box<dyn TxMaker<TxType = EthTxT> + Send + Sync>>,
    ) -> errors::Result<EthTxVerifier<EthTxT>>
    {
        let out_streamer = Arc::new(Mutex::new(EthTxOutStreamer {
            transactions_to_write: Default::default(),
            wip_block_info: Default::default(),
            next_block_number: start_block_number,
            transaction_number: 0,
            tx_rlp_file: File::create(path_to_tx_file)?,
            total_verified_tx_rlp_length: 0,
            n_txs: 0,
            tx_maker: tx_maker.clone(),
        }));

        let mut workers = Vec::with_capacity(Self::N_TX_VERIFIERS);
        for i in 0..Self::N_TX_VERIFIERS {
            workers.push(EthTxVerifierWorkerThread::new(
                &nonce_dir_path,
                start_block_number,
                i,
                out_streamer.clone(),
                tx_maker.clone(),
            ));
        }

        Ok(EthTxVerifier {
            workers,
            out_streamer,
        })
    }

    pub fn total_verified_tx_rlp_length(&self) -> usize {
        self.out_streamer.lock().total_verified_tx_rlp_length
    }
}

#[derive(Default, Clone)]
pub struct EthTxVerifierWIPBlockInfo {
    chain_id: Option<u64>,

    total_transaction_fee: U256,
    total_transactions_before_block_reward: u32,
    // This field is 0 iff uninitialized WIPBlockInfo.
    total_transactions: u32,
    remaining_transactions: u32,
}

pub struct EthTxOutStreamer<EthTxType: EthTxTypeTrait> {
    // For a 10 million blocks, the information consumes only about 300MB.
    wip_block_info: VecDeque<EthTxVerifierWIPBlockInfo>,
    pub next_block_number: u64,

    /// For transaction insertion.
    pub transaction_number: u64,
    pub transactions_to_write: VecDeque<Option<EthTxType>>,

    tx_maker: Arc<Box<dyn TxMaker<TxType = EthTxType> + Send + Sync>>,

    // how to know if a tx is ready to be checked? For each sender it must be
    // processed sequentially.
    tx_rlp_file: File,
    total_verified_tx_rlp_length: usize,
    n_txs: u64,
}

impl<EthTxType: EthTxTypeTrait> Drop for EthTxOutStreamer<EthTxType> {
    fn drop(&mut self) {
        println!(
            "{} heapsize\tEthTxOutStreamer#wip_block_info.",
            self.wip_block_info.heap_size_of_children()
        );
        println!(
            "{} heapsize\tEthTxOutStreamer#transactions_to_write.",
            self.transactions_to_write.heap_size_of_children()
        );
    }
}

impl<EthTxType: EthTxTypeTrait> EthTxOutStreamer<EthTxType> {
    /// Return the total base transaction number for the next block.
    ///
    /// This method should be called after adding the block reward txs.
    fn initialize_for_block(
        &mut self, block_number: u64, adhoc_txs: u32, unverified_txs: u32,
        block_reward_txs: u32, base_transaction_number: u64,
        chain_id: Option<u64>,
    ) -> u64
    {
        let block_dequeue_index =
            self.get_block_dequeue_index_for(block_number);

        let total_txs = adhoc_txs + unverified_txs + block_reward_txs;
        if block_dequeue_index >= self.wip_block_info.len() {
            self.wip_block_info
                .resize(block_dequeue_index + 1, Default::default());
        }
        self.wip_block_info[block_dequeue_index] = EthTxVerifierWIPBlockInfo {
            chain_id,
            total_transaction_fee: 0.into(),
            total_transactions_before_block_reward: adhoc_txs + unverified_txs,
            total_transactions: total_txs,
            remaining_transactions: total_txs,
        };

        let next_base_transaction_number =
            base_transaction_number + total_txs as u64;
        let tx_result_index_limit = self
            .get_transaction_dequeue_index_for(next_base_transaction_number);
        if tx_result_index_limit > self.transactions_to_write.len() {
            self.transactions_to_write
                .resize(tx_result_index_limit, None);
        }

        next_base_transaction_number
    }

    pub fn set_transaction(
        &mut self, block_number: u64, base_transaction_number: u64,
        transaction_index: u64, maybe_result: Option<EthTxType>,
        has_tx_fee: bool,
    )
    {
        let block_dequeue_index =
            self.get_block_dequeue_index_for(block_number);
        match has_tx_fee {
            true => {
                self.wip_block_info[block_dequeue_index]
                    .total_transaction_fee +=
                    self.tx_maker.tx_fee(maybe_result.as_ref().unwrap())
            }
            false => {}
        }

        self.wip_block_info[block_dequeue_index].remaining_transactions -= 1;

        let tx_dequeue_index = self.get_transaction_dequeue_index_for(
            base_transaction_number + transaction_index,
        );
        self.transactions_to_write[tx_dequeue_index] = maybe_result;
    }

    fn set_result(
        &mut self, request: EthTxNonceVerifierRequest<EthTxType>,
        maybe_result: Option<EthTxType>,
    )
    {
        let is_valid_tx = maybe_result.is_some();
        self.set_transaction(
            request.block_number,
            request.base_transaction_number,
            request.transaction_index as u64,
            maybe_result,
            is_valid_tx,
        );
        let block_dequeue_index =
            self.get_block_dequeue_index_for(request.block_number);

        if self.wip_block_info[block_dequeue_index].remaining_transactions == 0
        {
            // Credit the total tx fee into the block reward.
            let block_reward_tx_dequeue_index = self
                .get_transaction_dequeue_index_for(
                    request.base_transaction_number
                        + self.wip_block_info[block_dequeue_index]
                            .total_transactions_before_block_reward
                            as u64,
                );
            *self.tx_maker.modify_amount(
                self.transactions_to_write[block_reward_tx_dequeue_index]
                    .as_mut()
                    .unwrap(),
            ) += self.wip_block_info[block_dequeue_index].total_transaction_fee;
        }

        self.stream_out();
    }

    fn stream_tx(&mut self, tx: &EthTxType) {
        let tx_rlp = tx.rlp_bytes();
        self.tx_rlp_file.write_all(&tx_rlp).unwrap();
        self.total_verified_tx_rlp_length += tx_rlp.len();
        self.n_txs += 1;
    }

    fn stream_genesis_accounts(&mut self, tx: &EthTxType) { self.stream_tx(tx) }

    fn stream_out(&mut self) {
        while self.wip_block_info.len() > 0
            && self.wip_block_info[0].remaining_transactions == 0
            && self.wip_block_info[0].total_transactions > 0
        {
            let wip_block_info = self.wip_block_info.pop_front();
            let wip_block_info_ref = wip_block_info.as_ref().unwrap();
            self.next_block_number += 1;

            // Log some block reward.
            if self.next_block_number % 1000 == 0 {
                let block_reward_tx_dequeue_index =
                    wip_block_info_ref.total_transactions_before_block_reward;

                warn!(
                    "block reward of {}: {:?}",
                    self.next_block_number,
                    self.transactions_to_write
                        [block_reward_tx_dequeue_index as usize]
                );
            }

            // loop through transactions.
            let n_txs = wip_block_info_ref.total_transactions;
            for _i in 0..n_txs {
                // Pop a tx and process.
                let maybe_tx = self.transactions_to_write.pop_front().unwrap();
                match maybe_tx {
                    Some(mut tx) => {
                        self.tx_maker
                            .sign(&mut tx, wip_block_info_ref.chain_id);
                        self.stream_tx(&tx)
                    }
                    None => {}
                }
            }
            self.transaction_number += n_txs as u64;
        }
    }

    fn get_block_dequeue_index_for(&self, block_number: u64) -> usize {
        (block_number - self.next_block_number) as usize
    }

    fn get_transaction_dequeue_index_for(
        &self, transaction_number: u64,
    ) -> usize {
        (transaction_number - self.transaction_number) as usize
    }
}

pub trait ResultTrait: Clone + Send + Sync + HeapSizeOf + 'static {}

#[derive(Clone)]
struct ArcEthBlock(Arc<EthBlock>);

impl ResultTrait for ArcEthBlock {}

impl<EthTxT: EthTxTypeTrait> ResultTrait
    for std::result::Result<
        EthTxNonceVerifierRequest<EthTxT>,
        ArcEthTxExtractor<EthTxT>,
    >
{
}

pub struct FIFOConsumerResult<T: ResultTrait> {
    task_id: usize,
    results: VecDeque<Option<T>>,
    result_processor: Box<dyn FnMut(T) -> () + Send + Sync>,
}

impl<T: ResultTrait> Drop for FIFOConsumerResult<T> {
    fn drop(&mut self) {
        assert_eq!(self.results.len(), 0);
        println!(
            "heapsize {}\tFIFOConsumerResult",
            self.results.heap_size_of_children()
        );
    }
}

impl<T: ResultTrait> FIFOConsumerResult<T> {
    fn save_result(&mut self, task_id: usize, result: T) {
        let waiting_for_result = None;
        let index = task_id - self.task_id;
        if index >= self.results.len() {
            self.results.resize(index + 1, waiting_for_result);
        }
        self.results[index] = Some(result);

        if index == 0 {
            self.process_results();
        }
    }

    fn process_results(&mut self) {
        while self.results.len() > 0 && self.results[0].is_some() {
            let result = self.results.pop_front().unwrap().unwrap();
            self.task_id += 1;
            (self.result_processor)(result);
        }
    }
}

pub trait FIFOConsumerRequestTrait: Send + Sync + 'static {}

impl FIFOConsumerRequestTrait for (usize, std::vec::Vec<u8>) {}

pub struct FIFOConsumerThread<RequestT: FIFOConsumerRequestTrait> {
    task_sender: mpsc::SyncSender<Option<RequestT>>,
    thread_handle: Option<JoinHandle<Option<()>>>,
}

impl<RequestT: FIFOConsumerRequestTrait> Drop for FIFOConsumerThread<RequestT> {
    fn drop(&mut self) {
        self.task_sender.send(None).ok();
        println!("stopping FIFOConsumer thread.");

        self.thread_handle.take().unwrap().join().ok();
        println!("FIFOConsumer thread exits.");
    }
}

impl<RequestT: FIFOConsumerRequestTrait> FIFOConsumerThread<RequestT> {
    pub fn new_consumers<
        ResultT: ResultTrait,
        F: FnMut(RequestT) -> (usize, ResultT) + Send + Sync + Clone + 'static,
    >(
        n_threads: usize,
        result_processor: Box<dyn FnMut(ResultT) -> () + Send + Sync>,
        processor: F,
    ) -> Vec<Arc<Mutex<FIFOConsumerThread<RequestT>>>>
    {
        let consumer_results =
            Arc::new(Mutex::new(FIFOConsumerResult::<ResultT> {
                task_id: 0,
                results: Default::default(),
                result_processor,
            }));

        let mut threads = Vec::with_capacity(n_threads);
        for _i in 0..n_threads {
            threads.push(Self::new_arc(
                consumer_results.clone(),
                Box::new(processor.clone()),
            ));
        }

        threads
    }

    pub fn new_arc<ResultT: ResultTrait>(
        consumer_results: Arc<Mutex<FIFOConsumerResult<ResultT>>>,
        mut processor: Box<
            dyn FnMut(RequestT) -> (usize, ResultT) + Send + Sync,
        >,
    ) -> Arc<Mutex<FIFOConsumerThread<RequestT>>>
    {
        let (sender, receiver) = mpsc::sync_channel(10_000);
        let verifier = Arc::new(Mutex::new(FIFOConsumerThread {
            task_sender: sender,
            thread_handle: None,
        }));

        let results = consumer_results.clone();
        let join_handle = thread::spawn(move || -> Option<()> {
            loop {
                let receive_result = receiver.recv();
                match receive_result {
                    Err(e) => {
                        println!("receive failure {}", e);
                    }
                    Ok(maybe_task) => {
                        match maybe_task {
                            Some(task) => {
                                let result = processor(task);
                                results.lock().save_result(result.0, result.1);
                            }
                            None => {
                                println!("FIFOConsumerThread received None, exitting.");
                                return Some(());
                            }
                        }
                    }
                }
            }
        });
        verifier.lock().thread_handle = Some(join_handle);

        verifier
    }
}

impl<EthTxT: EthTxTypeTrait> FIFOConsumerRequestTrait
    for EthTxBasicVerifierRequest<EthTxT>
{
}

#[derive(Default)]
pub struct EthTxExtractorCounters {
    n_blocks: u64,
    /// Absolute block number.
    block_number: u64,

    /// Relative transaction number since the start block number.
    base_transaction_number: u64,
    /// Relative.
    n_tx_seen: usize,

    n_tx_verification_error: u64,
}

pub trait TxExtractor {
    fn add_block(&self, block: Arc<EthBlock>);
}

pub trait TxMaker {
    type TxType;

    fn make_sys_award(
        &self, receiver: &Address, amount: U256, tx_type: EthTxType,
    ) -> Option<Self::TxType>;

    fn make_force_transfer(
        &self, sender: &Address, receiver: &Address, amount: U256,
        tx_type: EthTxType,
    ) -> Option<Self::TxType>;

    fn sign(&self, x: &mut Self::TxType, chain_id: Option<u64>);

    fn modify_amount<'a>(&self, x: &'a mut Self::TxType) -> &'a mut U256;

    fn tx_fee(&self, x: &Self::TxType) -> U256;

    fn convert_tx(
        &self, tx: &UnverifiedTransaction, maybe_sender: Option<Address>,
    ) -> Option<Self::TxType>;
}

pub trait EthTxTypeTrait:
    Encodable + Send + Sync + Clone + Debug + HeapSizeOf + 'static
{
}

#[derive(Debug)]
enum TxMakerTx {
    Raw(UnverifiedTransaction),
    Generated(EthJsonTransaction),
}

impl TxMakerTx {
    fn clone_ethjsontx(g: &EthJsonTransaction) -> EthJsonTransaction {
        EthJsonTransaction {
            nonce: g.nonce,
            to: g.to.clone(),
            value: g.value,
            gas_limit: g.gas_limit,
            gas_price: g.gas_price,
            data: g.data.clone(),
            r: g.r,
            s: g.s,
            v: g.v,
        }
    }
}

impl Clone for TxMakerTx {
    fn clone(&self) -> Self {
        match self {
            TxMakerTx::Raw(r) => TxMakerTx::Raw(r.clone()),
            TxMakerTx::Generated(g) => {
                TxMakerTx::Generated(Self::clone_ethjsontx(g))
            }
        }
    }
}

impl Encodable for TxMakerTx {
    fn rlp_append(&self, s: &mut RlpStream) {
        match self {
            TxMakerTx::Raw(ref r) => {
                s.append_internal(r);
            }
            _ => {
                unreachable!();
            }
        }
    }
}

impl EthTxTypeTrait for TxMakerTx {}
impl EthTxTypeTrait for RealizedEthTx {}

#[derive(Default)]
struct EthTxMaker {
    system_account_nonce: AtomicUsize,
}

impl TxMaker for EthTxMaker {
    type TxType = TxMakerTx;

    fn make_sys_award(
        &self, receiver: &H160, amount: U256, _tx_type: EthTxType,
    ) -> Option<Self::TxType> {
        Some(TxMakerTx::Generated(EthJsonTransaction {
            nonce: ethjson::uint::Uint(
                self.system_account_nonce
                    .fetch_add(1, Ordering::Relaxed)
                    .into(),
            ),
            gas_price: ethjson::uint::Uint(1.into()),
            gas_limit: ethjson::uint::Uint(21000.into()),
            to: ethjson::maybe::MaybeEmpty::Some(ethjson::hash::Address(
                receiver.clone(),
            )),
            value: ethjson::uint::Uint(amount),
            data: Default::default(),
            r: ethjson::uint::Uint(0.into()),
            s: ethjson::uint::Uint(0.into()),
            v: ethjson::uint::Uint(0.into()),
        }))
    }

    fn make_force_transfer(
        &self, _sender: &H160, _receiver: &H160, _amount: U256,
        _tx_type: EthTxType,
    ) -> Option<Self::TxType>
    {
        None
    }

    fn sign(&self, x: &mut Self::TxType, chain_id: Option<u64>) {
        match x {
            TxMakerTx::Generated(ref mut g) => {
                let mut signed = TxMakerTx::Raw(
                    Into::<UnverifiedTransaction>::into(
                        TxMakerTx::clone_ethjsontx(g),
                    )
                    .deref()
                    .clone()
                    .sign(&SYSTEM_ACCOUNT_SECRET, chain_id)
                    .deref()
                    .clone(),
                );
                mem::swap(x, &mut signed);
            }
            _ => {}
        }
    }

    fn modify_amount<'a>(&self, x: &'a mut Self::TxType) -> &'a mut U256 {
        match x {
            TxMakerTx::Generated(ref mut g) => &mut g.value.0,
            _ => {
                unreachable!();
            }
        }
    }

    fn tx_fee(&self, x: &Self::TxType) -> U256 {
        match x {
            TxMakerTx::Raw(ref r) => r.gas * r.gas_price,
            _ => unreachable!(),
        }
    }

    fn convert_tx(
        &self, tx: &UnverifiedTransaction, _maybe_sender: Option<Address>,
    ) -> Option<Self::TxType> {
        Some(TxMakerTx::Raw(tx.clone()))
    }
}

struct RealizedEthTxMaker {}

impl TxMaker for RealizedEthTxMaker {
    type TxType = RealizedEthTx;

    fn make_sys_award(
        &self, receiver: &H160, amount: U256, tx_type: EthTxType,
    ) -> Option<Self::TxType> {
        Some(RealizedEthTx {
            sender: None,
            receiver: Some(receiver.clone()),
            amount_wei: amount,
            tx_fee_wei: 0.into(),
            types: tx_type,
        })
    }

    fn make_force_transfer(
        &self, sender: &H160, receiver: &H160, amount: U256, tx_type: EthTxType,
    ) -> Option<Self::TxType> {
        Some(RealizedEthTx {
            sender: Some(sender.clone()),
            receiver: Some(receiver.clone()),
            amount_wei: amount,
            tx_fee_wei: 0.into(),
            types: tx_type,
        })
    }

    fn sign(&self, _: &mut Self::TxType, _chain_id: Option<u64>) {
        // No-op
    }

    fn modify_amount<'a>(&self, x: &'a mut Self::TxType) -> &'a mut U256 {
        &mut x.amount_wei
    }

    fn tx_fee(&self, x: &Self::TxType) -> U256 { x.tx_fee_wei.clone() }

    fn convert_tx(
        &self, tx: &UnverifiedTransaction, maybe_sender: Option<Address>,
    ) -> Option<Self::TxType> {
        let receiver;
        let tx_fee = tx.gas * tx.gas_price;

        match tx.action {
            ethcore_types::transaction::Action::Call(ref to) => {
                receiver = Some(*to);
            }
            _ => {
                // Create a contract.
                // We should credit transaction fee to the miner.
                // and advance nonce for sender.
                receiver = None;
            }
        }

        Some(RealizedEthTx {
            sender: maybe_sender,
            receiver,
            amount_wei: tx.value,
            tx_fee_wei: tx_fee,
            types: EthTxType::Transaction,
        })
    }
}

//unsafe impl<EthTxT: EthTxTypeTrait> Sync for (dyn TxMaker<TxType=EthTxT> +
// 'static){}

pub struct EthTxExtractor<EthTxT: EthTxTypeTrait> {
    tx_basic_verifiers:
        Vec<Arc<Mutex<FIFOConsumerThread<EthTxBasicVerifierRequest<EthTxT>>>>>,
    ethash_params: EthashParams,
    params: EthCommonParams,
    dao_hardfork_info: Option<Arc<DaoHardforkInfo>>,

    /// Not verifying balance at the moment.
    nonce_verifier: EthTxVerifier<EthTxT>,
    nonce_dir_path: String,
    counters: Arc<Mutex<EthTxExtractorCounters>>,

    shared_self: Option<Arc<EthTxExtractor<EthTxT>>>,

    tx_maker: Arc<Box<dyn TxMaker<TxType = EthTxT> + Send + Sync>>,
}

pub struct EthTxExtractorStopper<EthTxT: EthTxTypeTrait>(
    Arc<EthTxExtractor<EthTxT>>,
);

impl<EthTxT: EthTxTypeTrait> Drop for EthTxExtractorStopper<EthTxT> {
    fn drop(&mut self) {
        println!("stopping eth tx extractor.");

        let mut tx_basic_verifiers = self.0.stop_from_ref();
        tx_basic_verifiers.drain(..);

        for i in 0..EthTxVerifier::<EthTxT>::N_TX_VERIFIERS {
            self.0.nonce_verifier.workers[i].lock().finalize(
                &self.0.nonce_dir_path,
                self.0.counters.lock().block_number,
                i,
            );
        }

        let tx_extractor = &self.0;
        println!("loaded {} blocks {} txs {} nonce error {} contract creation {} accounts",
                 tx_extractor.n_blocks(), tx_extractor.n_txs(),
                 tx_extractor.n_nonce_error(), tx_extractor.n_contract_creation(),
                 tx_extractor.n_accounts());
    }
}

impl<EthTxT: EthTxTypeTrait> EthTxExtractor<EthTxT> {
    const N_TX_BASIC_VERIFIERS: usize = 8;

    pub fn stop_from_ref(
        &self,
    ) -> Vec<Arc<Mutex<FIFOConsumerThread<EthTxBasicVerifierRequest<EthTxT>>>>>
    {
        unsafe {
            EthTxExtractor::stop(
                &mut *(self as *const EthTxExtractor<EthTxT>
                    as *mut EthTxExtractor<EthTxT>),
            )
        }
    }

    pub fn stop(
        &mut self,
    ) -> Vec<Arc<Mutex<FIFOConsumerThread<EthTxBasicVerifierRequest<EthTxT>>>>>
    {
        self.shared_self.take();
        mem::replace(&mut self.tx_basic_verifiers, vec![])
    }

    pub fn new_from_spec(
        path: &str, path_to_tx_file: &str, nonce_dir_path: String,
        start_block_number: u64,
        tx_maker: Arc<Box<dyn TxMaker<TxType = EthTxT> + Send + Sync>>,
    ) -> errors::Result<Arc<EthTxExtractor<EthTxT>>>
    {
        let ethash: ethjson::spec::Ethash;
        match EthSpec::load(File::open(path)?)?.engine {
            ethjson::spec::engine::Engine::Ethash(ethash_engine) => {
                ethash = ethash_engine;
            }
            _ => {
                panic!();
            }
        }

        let dao_hardfork_info = match ethash.params.dao_hardfork_transition {
            Some(transition) => Some(Arc::new(DaoHardforkInfo {
                dao_hardfork_transition: transition.0.as_u64(),
                dao_hardfork_accounts: vec![],
                dao_hardfork_beneficiary: ethash
                    .params
                    .dao_hardfork_beneficiary
                    .as_ref()
                    .unwrap()
                    .0,
            })),
            None => None,
        };

        let tx_basic_verifiers = FIFOConsumerThread::new_consumers(
            Self::N_TX_BASIC_VERIFIERS,
            Box::new(
                |maybe_request: Result<
                    EthTxNonceVerifierRequest<EthTxT>,
                    ArcEthTxExtractor<EthTxT>,
                >| {
                    match maybe_request {
                        Ok(request) => {
                            request
                                .tx_extractor
                                .clone()
                                .verify_tx_then_stream_out(request);
                        }
                        Err(tx_extractor) => {
                            tx_extractor
                                .0
                                .counters
                                .lock()
                                .n_tx_verification_error += 1;
                        }
                    }
                },
            ),
            |task: EthTxBasicVerifierRequest<EthTxT>| {
                let block = task.block;
                let block_number = block.header.number();
                let tx = unsafe {
                    block.transactions.get_unchecked(task.transaction_index)
                };
                let maybe_sender = tx
                    .verify_basic(
                        task.check_low_s,
                        task.chain_id,
                        task.allow_empty_signature,
                    )
                    .ok()
                    .map(|_| public_to_address(&tx.recover_public().unwrap()));
                match maybe_sender {
                    Some(sender) => (
                        task.basic_verification_index,
                        Ok(EthTxNonceVerifierRequest {
                            block,
                            block_number,
                            transaction_index: task.transaction_index,
                            base_transaction_number: task
                                .base_transaction_number,
                            sender: sender.clone(),
                            tx_extractor: task.tx_extractor,
                        }),
                    ),
                    None => (
                        task.basic_verification_index,
                        Err(ArcEthTxExtractor(task.tx_extractor)),
                    ),
                }
            },
        );

        let result = Ok(Arc::new(EthTxExtractor {
            tx_basic_verifiers,
            ethash_params: ethash.params.into(),
            params: EthSpec::load(File::open(path)?)?.params.into(),
            dao_hardfork_info,
            counters: Default::default(),
            nonce_verifier: EthTxVerifier::new(
                path_to_tx_file,
                nonce_dir_path.clone(),
                start_block_number,
                tx_maker.clone(),
            )?,
            nonce_dir_path: nonce_dir_path.clone(),
            shared_self: None,
            tx_maker: tx_maker.clone(),
        }));

        let extractor_arc = result.as_ref().unwrap().clone();
        // FIXME: remove unsafes.
        unsafe {
            (&mut *(extractor_arc.as_ref() as *const EthTxExtractor<EthTxT>
                as *mut EthTxExtractor<EthTxT>))
        }
        .shared_self = Some(extractor_arc.clone());

        if start_block_number == 0 {
            let spec = EthSpec::load(File::open(path)?)?;

            // Add genesis accounts.
            // WTF, the spec is consumed and there is no way around.
            let mut genesis_account_counts = 0;
            for (address, account) in spec.accounts {
                match extractor_arc.tx_maker.make_sys_award(
                    &address.0,
                    account.balance.map_or(0.into(), |v| v.0),
                    EthTxType::GenesisAccount,
                ) {
                    Some(ref mut genesis_award_tx) => {
                        tx_maker.sign(
                            genesis_award_tx,
                            spec.params.chain_id.map(|x| x.0.low_u64()),
                        );
                        extractor_arc
                            .get_out_streamer()
                            .lock()
                            .stream_genesis_accounts(genesis_award_tx);
                        genesis_account_counts += 1;
                    }
                    None => {}
                }
            }

            // Set base transaction number at all places.
            extractor_arc.counters.lock().base_transaction_number =
                genesis_account_counts;
            extractor_arc.get_out_streamer().lock().transaction_number =
                genesis_account_counts;
        }

        result
    }

    fn get_out_streamer(&self) -> &Mutex<EthTxOutStreamer<EthTxT>> {
        self.nonce_verifier.out_streamer.as_ref()
    }

    fn verify_tx_then_stream_out(
        &self, tx_verify_request: EthTxNonceVerifierRequest<EthTxT>,
    ) {
        let thread = (tx_verify_request.sender.low_u64() & 7) as usize;

        self.nonce_verifier.workers[thread]
            .lock()
            .send_request(tx_verify_request);
    }

    pub fn get_balance(&self, _address: &H160) -> Option<&U256> { None }

    pub fn add_tx_from_system(
        &self, maybe_tx: Option<EthTxT>, block_number: u64,
        base_transaction_number: u64, tx_number_in_block: u32,
    )
    {
        self.get_out_streamer().lock().set_transaction(
            block_number,
            base_transaction_number,
            tx_number_in_block.into(),
            maybe_tx,
            false,
        );
    }

    pub fn get_block_reward_base(&self, block_number: u64) -> U256 {
        let (_, reward) = self.ethash_params.block_reward.iter()
            .rev()
            .find(|&(block, _)| *block <= block_number)
            .expect("Current block's reward is not found; verifier indicates a chain config error; qed");
        *reward
    }

    pub fn n_blocks(&self) -> u64 { self.counters.lock().n_blocks }

    pub fn n_tx_seen(&self) -> usize { self.counters.lock().n_tx_seen }

    pub fn n_txs(&self) -> u64 { self.get_out_streamer().lock().n_txs }

    pub fn n_contract_creation(&self) -> u64 {
        let mut sum = 0;
        for verifier in &self.nonce_verifier.workers {
            sum += verifier.lock().n_contract_creation();
        }
        sum
    }

    pub fn n_tx_verification_error(&self) -> u64 {
        self.counters.lock().n_tx_verification_error
    }

    pub fn n_nonce_error(&self) -> u64 {
        let mut sum = 0;
        for verifier in &self.nonce_verifier.workers {
            sum += verifier.lock().n_nonce_error();
        }
        sum
    }

    pub fn n_accounts(&self) -> usize {
        let mut sum = 0;
        for verifier in &self.nonce_verifier.workers {
            sum += verifier.lock().n_accounts();
        }
        sum
    }

    pub fn total_verified_tx_rlp_length(&self) -> usize {
        self.get_out_streamer().lock().total_verified_tx_rlp_length
    }

    pub fn tx_verify(
        &self, check_low_s: bool, chain_id: Option<u64>,
        allow_empty_signature: bool, block: Arc<EthBlock>, base_tx_number: u64,
        transaction_index: usize, worker: usize,
        basic_verification_index: usize,
    )
    {
        // FIXME: move it outside;
        let request = EthTxBasicVerifierRequest {
            basic_verification_index,
            base_transaction_number: base_tx_number,
            block,
            transaction_index,

            check_low_s,
            chain_id,
            allow_empty_signature,

            tx_extractor: self.shared_self.as_ref().unwrap().clone(),
        };
        self.tx_basic_verifiers[worker]
            .lock()
            .task_sender
            .send(Some(request))
            .unwrap();
    }
}

impl<EthTxT: EthTxTypeTrait> TxExtractor for EthTxExtractor<EthTxT> {
    fn add_block(&self, block: Arc<EthBlock>) {
        let block_number = block.header.number();
        let base_transaction_number =
            self.counters.lock().base_transaction_number;
        let dao_hardfork = self.dao_hardfork_info.is_some()
            && block_number
                == self
                    .dao_hardfork_info
                    .as_ref()
                    .unwrap()
                    .dao_hardfork_transition;

        let mut ad_hoc_tx_numbers = 0;
        if dao_hardfork {
            ad_hoc_tx_numbers = self
                .dao_hardfork_info
                .as_ref()
                .unwrap()
                .dao_hardfork_accounts
                .len() as u32;
        }

        let use_tx_chain_id =
            block_number < self.params.validate_chain_id_transition;
        let chain_id =
            if block_number < self.params.validate_chain_id_transition {
                None
            } else if block_number >= self.params.eip155_transition {
                Some(self.params.chain_id)
            } else {
                None
            };

        let new_base_transaction_number =
            self.get_out_streamer().lock().initialize_for_block(
                block_number,
                ad_hoc_tx_numbers,
                block.transactions.len() as u32,
                1 + block.uncles.len() as u32,
                base_transaction_number,
                chain_id,
            );

        // Dao
        if dao_hardfork {
            let mut ad_hoc_tx_index = 0;

            let dao_hardfork_info =
                self.dao_hardfork_info.as_ref().unwrap().clone();

            let beneficiary = &dao_hardfork_info.dao_hardfork_beneficiary;
            let accounts = &dao_hardfork_info.dao_hardfork_accounts;

            for account in accounts {
                // TODO: we don't support updating loading the balance because
                // it's extremely slow. and it make parallelism
                // hard.
                let balance =
                    self.get_balance(&account).map_or(0.into(), |x| *x);

                self.add_tx_from_system(
                    self.tx_maker.make_force_transfer(
                        &account,
                        &beneficiary,
                        balance,
                        EthTxType::Dao,
                    ),
                    block_number,
                    base_transaction_number,
                    ad_hoc_tx_index,
                );

                ad_hoc_tx_index += 1;
            }
        }

        // verify txs
        let check_low_s =
            block_number >= self.ethash_params.homestead_transition;

        // Apply block rewards.
        let block_reward_tx_offset =
            ad_hoc_tx_numbers + block.transactions.len() as u32;
        let mut block_reward_txs = 0;
        let block_reward_base = self.get_block_reward_base(block_number);

        let block_reward = block_reward_base
            + block_reward_base.shr(5) * U256::from(block.uncles.len());
        self.add_tx_from_system(
            self.tx_maker.make_sys_award(
                &block.header.author(),
                // The amount will be updated when the last unverified tx in
                // the block is finished.
                block_reward,
                EthTxType::BlockRewardAndTxFee,
            ),
            block_number,
            base_transaction_number,
            block_reward_tx_offset + block_reward_txs,
        );
        block_reward_txs += 1;

        for uncle_header in &block.uncles {
            let uncle_reward = (block_reward_base
                * U256::from(8 + uncle_header.number() - block_number))
            .shr(3);
            self.add_tx_from_system(
                self.tx_maker.make_sys_award(
                    &uncle_header.author(),
                    uncle_reward,
                    EthTxType::UncleReward,
                ),
                block_number,
                base_transaction_number,
                block_reward_tx_offset + block_reward_txs,
            );
            block_reward_txs += 1;
        }

        let mut basic_verification_index = self.counters.lock().n_tx_seen;
        let mut thread = basic_verification_index % Self::N_TX_BASIC_VERIFIERS;
        for i in 0..block.transactions.len() {
            unsafe {
                let tx = block.transactions.get_unchecked(i);
                self.tx_verify(
                    check_low_s,
                    if !use_tx_chain_id {
                        chain_id
                    } else {
                        tx.chain_id()
                    },
                    false,
                    block.clone(),
                    base_transaction_number,
                    i,
                    thread,
                    basic_verification_index,
                );
            }
            thread = (thread + 1) % Self::N_TX_BASIC_VERIFIERS;
            basic_verification_index += 1;
        }

        {
            let mut counters_mut = self.counters.lock();
            counters_mut.n_blocks += 1;
            counters_mut.block_number = block_number;
            counters_mut.n_tx_seen += block.transactions.len();
            counters_mut.base_transaction_number = new_base_transaction_number;
        }

        // Some progress log.
        if block_number % 5000 == 4999 {
            println!(
                "Block {}, block number = {}, #tx seen {}, #accounts {}, #contract creation {}, \
                #valid txs + awards {}, #total tx rlp len {}, \
                #nonce error {}, #basic verification error {}",
                self.n_blocks(),
                block.header.number(),
                self.n_tx_seen(),
                self.n_accounts(),
                self.n_contract_creation(),
                self.n_txs(),
                self.total_verified_tx_rlp_length(),
                self.n_nonce_error(),
                self.n_tx_verification_error(),
            );
        }
    }
}

fn tx_extract<U: TxExtractor, T: Deref<Target = U> + Sync + Send + 'static>(
    matches: ArgMatches, tx_extractor: T,
) -> errors::Result<()> {
    const N_BLOCK_DECODERS: usize = 8;
    let block_decoders = FIFOConsumerThread::new_consumers(
        N_BLOCK_DECODERS,
        Box::new(move |block: ArcEthBlock| {
            tx_extractor.add_block(block.0);
        }),
        |task: (usize, Vec<u8>)| {
            (
                task.0,
                ArcEthBlock(Arc::new(
                    EthBlock::decode(&Rlp::new(&task.1)).unwrap(),
                )),
            )
        },
    );
    let mut block_seq_number = 0;
    let mut thread_number = 0;

    // Load block RLP from file.
    let mut rlp_file = File::open(matches.value_of("import_eth").unwrap())?;
    const BUFFER_SIZE: usize = 10000000;
    let mut buffer = Vec::<u8>::with_capacity(BUFFER_SIZE);

    'read: loop {
        let buffer_ptr = buffer.as_mut_ptr();
        let buffer_rest = unsafe {
            slice::from_raw_parts_mut(
                buffer_ptr.offset(buffer.len() as isize),
                buffer.capacity() - buffer.len(),
            )
        };
        info!(
            "buffer rest len {}, buffer len {}",
            buffer_rest.len(),
            buffer.len()
        );
        let read_result = rlp_file.read(buffer_rest);
        match read_result {
            Ok(bytes_read) => {
                // EOF
                if bytes_read == 0 {
                    info!("eof");
                    break 'read;
                }

                unsafe {
                    buffer.set_len(buffer.len() + bytes_read);
                }
                if buffer.len() == buffer.capacity() {
                    buffer.reserve_exact(buffer.capacity());
                }

                let mut to_parse = buffer.as_slice();
                '_parse: loop {
                    // Try to parse rlp.
                    let payload_info_result = Rlp::new(to_parse).payload_info();
                    if payload_info_result.is_err() {
                        if *payload_info_result.as_ref().unwrap_err()
                            == DecoderError::RlpIsTooShort
                        {
                            let mut buffer_new =
                                Vec::<u8>::with_capacity(BUFFER_SIZE);
                            buffer_new.extend_from_slice(to_parse);
                            drop(to_parse);
                            buffer = buffer_new;
                            // Reset the buffer.
                            if buffer.len() == buffer.capacity() {
                                buffer.reserve_exact(buffer.capacity());
                            }
                            continue 'read;
                        }
                    }
                    let payload_info = payload_info_result?;

                    // Now the buffer has sufficient length for an Rlp.
                    let rlp_len = payload_info.total();
                    // Finally we have a block.

                    let rlpbytes_cloned = to_parse[0..rlp_len].to_vec();
                    block_decoders[thread_number]
                        .lock()
                        .task_sender
                        .send(Some((block_seq_number, rlpbytes_cloned)))
                        .unwrap();
                    block_seq_number += 1;
                    thread_number = (thread_number + 1) % N_BLOCK_DECODERS;
                    to_parse = &to_parse[rlp_len..];
                }
            }
            Err(err) => {
                if err.kind() == io::ErrorKind::Interrupted
                    || err.kind() == io::ErrorKind::WouldBlock
                {
                    // Retry
                    continue;
                }
                eprintln!("{}", err);
                bail!(err);
            }
        }
    }
    Ok(())
}

struct TxReplayer {
    storage_manager: Arc<StorageManager>,
    tx_counts: Cell<u64>,
    ops_counts: Cell<u64>,
    block_height: Cell<i64>,
    commit_log: KvdbSqlite<Box<[u8]>>,
    commit_log_vec: Mutex<Vec<StateRootWithAuxInfo>>,
    state_availability_boundary: RwLock<StateAvailabilityBoundary>,

    exit: Arc<(Mutex<bool>, Condvar)>,
}

impl Drop for TxReplayer {
    fn drop(&mut self) {
        *self.exit.0.lock() = true;
        self.exit.1.notify_all();
    }
}

impl TxReplayer {
    const EPOCH_TXS: u64 = 20000;
    const SNAPSHOT_EPOCHS_CAPACITY: u32 = 400;

    pub fn new(
        conflux_data_dir: &str, reset_db: bool,
    ) -> errors::Result<TxReplayer> {
        if reset_db {
            match fs::remove_dir_all(conflux_data_dir) {
                Ok(_) => {}
                Err(ref e) if e.kind() == io::ErrorKind::NotFound => {}
                e @ Err(_) => e.unwrap(),
            }
        }

        let mut storage_configuration = StorageConfiguration::new_default(
            conflux_data_dir.to_string() + "/",
        );
        storage_configuration.consensus_param.snapshot_epoch_count =
            Self::SNAPSHOT_EPOCHS_CAPACITY;
        let storage_manager =
            Arc::new(StorageManager::new(storage_configuration)?);

        let exit: Arc<(Mutex<bool>, Condvar)> = Default::default();

        let storage_manager_log_weak_ptr = Arc::downgrade(&storage_manager);
        let exit_clone = exit.clone();
        thread::spawn(move || loop {
            let mut exit_lock = exit_clone.0.lock();
            if exit_clone
                .1
                .wait_for(&mut exit_lock, Duration::from_millis(5000))
                .timed_out()
            {
                let manager = storage_manager_log_weak_ptr.upgrade();
                match manager {
                    None => return,
                    Some(manager) => manager.log_usage(),
                };
            } else {
            }
        });

        let commit_log_path = conflux_data_dir.to_string() + "/commit_log";

        Ok(TxReplayer {
            storage_manager,
            tx_counts: Cell::new(0),
            ops_counts: Cell::new(0),
            block_height: Cell::new(0),
            commit_log: KvdbSqlite::open_or_create(
                commit_log_path,
                Arc::new(KvdbSqliteStatements::make_statements(
                    &["state_root_with_aux_info"],
                    &["BLOB"],
                    "commit_log",
                    true,
                )?),
            )?
            .1,
            commit_log_vec: Default::default(),
            state_availability_boundary: RwLock::new(
                StateAvailabilityBoundary {
                    pivot_chain: vec![],
                    synced_state_height: 0,
                    lower_bound: 0,
                    upper_bound: 0,
                    optimistic_executed_height: None,
                },
            ),
            exit,
        })
    }

    pub fn commit(
        &self, latest_state: &mut StateDb, txs: u64, ops: u64,
    ) -> errors::Result<StateRootWithAuxInfo> {
        warn!("Committing epoch at tx {}, ops {}.", txs, ops);

        let storage = latest_state.get_storage_mut();
        let state_root_with_aux = storage.compute_state_root().unwrap();
        let epoch_id = state_root_with_aux.state_root.delta_root;
        storage.commit(epoch_id).unwrap();
        let block_height = self.block_height.get();
        {
            let mut state_availability_boundary_mut =
                self.state_availability_boundary.write();
            state_availability_boundary_mut.upper_bound = block_height as u64;
            state_availability_boundary_mut.pivot_chain.push(epoch_id);
        }
        let confirmation_lag = 20;
        if block_height > confirmation_lag {
            let confirmed_height = (block_height - confirmation_lag) as u64;
            let commit_log_vec_locked = self.commit_log_vec.lock();
            let confirmed_epoch_state_root =
                &commit_log_vec_locked[(confirmed_height - 1) as usize];
            let confirmed_epoch_hash =
                &confirmed_epoch_state_root.state_root.delta_root;
            self.storage_manager
                .get_storage_manager()
                .maintain_snapshots_pivot_chain_confirmed(
                    confirmed_height,
                    confirmed_epoch_hash,
                    confirmed_epoch_state_root,
                    &self.state_availability_boundary,
                )?;
        }
        self.block_height.set(block_height + 1);
        self.commit_log.put_with_number_key(
            block_height,
            &state_root_with_aux.to_rlp_bytes(),
        )?;
        self.commit_log_vec.lock().push(state_root_with_aux.clone());

        Ok(state_root_with_aux)
    }

    pub fn add_tx(
        &self, tx: RealizedEthTx, latest_state: &mut StateDb,
        last_state_root: &mut StateRootWithAuxInfo,
    ) -> errors::Result<()>
    {
        if let Some(sender) = tx.sender {
            let maybe_account = latest_state
                .get_account(
                    // Transmute between different version of ethereum-types
                    // because conflux use a newer version
                    unsafe { std::mem::transmute(&sender) },
                )
                .unwrap();
            self.ops_counts.set(self.ops_counts.get() + 2);
            match maybe_account {
                Some(mut account) => {
                    account.balance = account
                        .balance
                        .overflowing_sub(
                            // Transmute between different version of
                            // ethereum-types because conflux use a newer
                            // version
                            unsafe {
                                std::mem::transmute(
                                    tx.amount_wei + tx.tx_fee_wei,
                                )
                            },
                        )
                        .0;
                    latest_state
                        .set::<Account>(
                            StorageKey::new_account_key(
                                // Transmute between different version of
                                // ethereum-types because conflux use a newer
                                // version
                                unsafe { std::mem::transmute(&sender) },
                            ),
                            &account,
                        )
                        .unwrap();
                }
                _ => {
                    // FIXME: check why this happens.
                    debug!("send from non-existing account!");
                }
            }
        }
        if let Some(receiver) = tx.receiver {
            let maybe_account = latest_state
                .get_account(
                    // Transmute between different version of
                    // ethereum-types because conflux use a newer
                    // version
                    unsafe { std::mem::transmute(&receiver) },
                )
                .unwrap();
            let mut account;
            match maybe_account {
                Some(account_) => {
                    account = account_;
                    account.balance = account
                        .balance
                        .overflowing_add(
                            // Transmute between different version of
                            // ethereum-types because conflux use a newer
                            // version
                            unsafe { std::mem::transmute(tx.amount_wei) },
                        )
                        .0;
                }
                _ => {
                    account = Account::new_empty_with_balance(
                        // Transmute between different version of
                        // ethereum-types because conflux use a newer
                        // version
                        unsafe { std::mem::transmute(&receiver) },
                        // Transmute between different version of
                        // ethereum-types because conflux use a newer
                        // version
                        unsafe { std::mem::transmute(&tx.amount_wei) }, /* balance */
                        &0.into(), /* nonce */
                    );
                }
            }
            latest_state
                .set::<Account>(
                    StorageKey::new_account_key(
                        // Transmute between different version of
                        // ethereum-types because conflux use a newer
                        // version
                        unsafe { std::mem::transmute(&receiver) },
                    ),
                    &account,
                )
                .unwrap();
            self.ops_counts.set(self.ops_counts.get() + 2);
        }

        self.tx_counts.set(self.tx_counts.get() + 1);
        if self.tx_counts.get() % Self::EPOCH_TXS == 0 {
            *last_state_root = self.commit(
                latest_state,
                self.tx_counts.get(),
                self.ops_counts.get(),
            )?;
            *latest_state = StateDb::new(
                self.storage_manager
                    .get_state_for_next_epoch(StateIndex::new_for_next_epoch(
                        &last_state_root.state_root.delta_root,
                        &last_state_root,
                        self.block_height.get() as u64,
                        self.storage_manager
                            .get_storage_manager()
                            .get_snapshot_epoch_count(),
                    ))
                    .unwrap()
                    .unwrap(),
            );
        }

        Ok(())
    }
}

fn tx_replay(matches: ArgMatches) -> errors::Result<()> {
    let tx_replayer = TxReplayer::new(
        matches.value_of("conflux_data_dir").unwrap(),
        matches.occurrences_of("reset_db") > 0,
    )?;

    let txs_to_process = match matches.value_of("txs_to_process") {
        None => None,
        Some(value) => Some(value.parse::<u64>().unwrap()),
    };

    let replay_bytes_skip = match matches.value_of("replay_bytes_skip") {
        None => None,
        Some(value) => Some(value.parse::<usize>().unwrap()),
    };

    let mut latest_state;
    let mut last_state_root;

    if matches.occurrences_of("reset_db") > 0 {
        last_state_root = StateRootWithAuxInfo::genesis(&MERKLE_NULL_NODE);
        latest_state = StateDb::new(
            tx_replayer.storage_manager.get_state_for_genesis_write(),
        );
    } else {
        match matches.value_of("last_epoch_number") {
            None => {
                last_state_root =
                    StateRootWithAuxInfo::genesis(&MERKLE_NULL_NODE);
                latest_state = StateDb::new(
                    tx_replayer.storage_manager.get_state_for_genesis_write(),
                );
            }
            Some(state_to_load) => {
                let block_height = state_to_load.parse::<i64>()?;
                tx_replayer.block_height.set(block_height);
                last_state_root = StateRootWithAuxInfo::from_rlp_bytes(
                    &tx_replayer
                        .commit_log
                        .get_with_number_key(block_height)?
                        .unwrap(),
                )?;
                latest_state = StateDb::new(
                    tx_replayer
                        .storage_manager
                        .get_state_for_next_epoch(
                            StateIndex::new_for_next_epoch(
                                &last_state_root.state_root.delta_root,
                                &last_state_root,
                                block_height as u64,
                                tx_replayer
                                    .storage_manager
                                    .get_storage_manager()
                                    .get_snapshot_epoch_count(),
                            ),
                        )
                        .unwrap()
                        .unwrap(),
                );
            }
        }
    }

    // Load block RLP from file.
    let mut rlp_file = File::open(matches.value_of("txs").unwrap())?;
    const BUFFER_SIZE: usize = 10000000;
    let mut buffer = Vec::<u8>::with_capacity(BUFFER_SIZE);

    match replay_bytes_skip {
        Some(mut value) => {
            let buffer_ptr = buffer.as_mut_ptr();
            let buffer = unsafe {
                slice::from_raw_parts_mut(buffer_ptr.offset(0), BUFFER_SIZE)
            };
            while value != 0 {
                let buf_size = if value > BUFFER_SIZE {
                    BUFFER_SIZE
                } else {
                    value
                };

                value -= rlp_file.read(&mut buffer[0..buf_size])?;
            }
        }
        None => {}
    }
    let mut num_txs_read = 0;
    let mut total_bytes_read = 0;
    'read: loop {
        let buffer_ptr = buffer.as_mut_ptr();
        let buffer_rest = unsafe {
            slice::from_raw_parts_mut(
                buffer_ptr.offset(buffer.len() as isize),
                buffer.capacity() - buffer.len(),
            )
        };
        debug!(
            "buffer rest len {}, buffer len {}",
            buffer_rest.len(),
            buffer.len()
        );
        let read_result = rlp_file.read(buffer_rest);
        match read_result {
            Ok(bytes_read) => {
                // EOF
                if bytes_read == 0 {
                    info!("eof");
                    break 'read;
                }

                unsafe {
                    buffer.set_len(buffer.len() + bytes_read);
                }
                if buffer.len() == buffer.capacity() {
                    buffer.reserve_exact(buffer.capacity());
                }

                let mut to_parse = buffer.as_slice();
                '_parse: loop {
                    // Try to parse rlp.
                    let payload_info_result = Rlp::new(to_parse).payload_info();
                    if payload_info_result.is_err() {
                        if *payload_info_result.as_ref().unwrap_err()
                            == DecoderError::RlpIsTooShort
                        {
                            let mut buffer_new =
                                Vec::<u8>::with_capacity(BUFFER_SIZE);
                            buffer_new.extend_from_slice(to_parse);
                            drop(to_parse);
                            buffer = buffer_new;
                            // Reset the buffer.
                            if buffer.len() == buffer.capacity() {
                                buffer.reserve_exact(buffer.capacity());
                            }
                            continue 'read;
                        }
                    }
                    let payload_info = payload_info_result?;

                    // Now the buffer has sufficient length for an Rlp.
                    let rlp_len = payload_info.total();
                    // Finally we have a tx.
                    num_txs_read += 1;
                    total_bytes_read += rlp_len;
                    if txs_to_process.is_some()
                        && num_txs_read > txs_to_process.unwrap()
                    {
                        println!("Already read {} transactions. total bytes read = {}. exiting...",
                                 num_txs_read, total_bytes_read);
                        break 'read;
                    }
                    let tx =
                        RealizedEthTx::decode(&Rlp::new(&to_parse[0..rlp_len]))
                            .unwrap();
                    to_parse = &to_parse[rlp_len..];

                    tx_replayer.add_tx(
                        tx,
                        &mut latest_state,
                        &mut last_state_root,
                    )?;
                }
            }
            Err(err) => {
                if err.kind() == io::ErrorKind::Interrupted
                    || err.kind() == io::ErrorKind::WouldBlock
                {
                    // Retry
                    continue;
                }
                eprintln!("{}", err);
                bail!(err);
            }
        }
    }
    last_state_root = tx_replayer.commit(
        &mut latest_state,
        tx_replayer.tx_counts.get(),
        tx_replayer.ops_counts.get(),
    )?;
    warn!("tx replay last state_root = {:?}", last_state_root);
    Ok(())
}

fn main() -> errors::Result<()> {
    env_logger::init();

    let matches = App::new("conflux storage benchmark")
        .arg(
            Arg::with_name("command")
                .value_name("command")
                .help("command, load tx (load) or run qps test (run)")
                .takes_value(true),
        )
        .arg(
            Arg::with_name("import_eth")
                .value_name("eth")
                .help("Ethereum blockchain file to import.")
                .takes_value(true)
                .last(true),
        )
        .arg(
            Arg::with_name("genesis")
                .value_name("genesis")
                .help("Ethereum genesis json config file.")
                .takes_value(true)
                .short("g")
                .long("genesis"),
        )
        .arg(
            Arg::with_name("txs")
                .value_name("transaction file")
                .help("File of verified transactions.")
                .short("t")
                .takes_value(true),
        )
        .arg(
            Arg::with_name("from_block")
                .value_name("stat block number")
                .help("load nonce file at start block number")
                .short("s")
                .takes_value(true),
        )
        .arg(
            Arg::with_name("nonce_dir")
                .value_name("nonce dir")
                .help("load/save nonce file")
                .short("n")
                .takes_value(true),
        )
        .arg(
            Arg::with_name("conflux_data_dir")
                .value_name("Conflux data dir")
                .help("Conflux data dir")
                .short("d")
                .takes_value(true),
        )
        .arg(
            Arg::with_name("reset_db")
                .value_name("reset database")
                .help("reset database and start from genesis")
                .short("R")
                .takes_value(false),
        )
        .arg(
            Arg::with_name("last_epoch_number")
                .value_name("last epoch number")
                .help("last epoch number from previous tx replay")
                .short("h")
                .takes_value(true),
        )
        .arg(
            Arg::with_name("txs_to_process")
                .value_name("number of txs to process")
                .help("number of tx to process from rlp file")
                .long("txs_to_process")
                .takes_value(true),
        )
        .arg(
            Arg::with_name("replay_bytes_skip")
                .value_name("number of bytes to skip in replay mode")
                .help("number of bytes to skip in replay mode")
                .long("skip")
                .takes_value(true),
        )
        .get_matches_from(std::env::args().collect::<Vec<_>>());

    let command = matches
        .value_of("command")
        .map_or("load".to_string(), |x| x.to_string());
    if command == "load" {
        let tx_extractor = EthTxExtractor::new_from_spec(
            matches.value_of("genesis").unwrap(),
            matches.value_of("txs").unwrap(),
            matches.value_of("nonce_dir").unwrap().to_string(),
            matches
                .value_of("from_block")
                .unwrap()
                .parse::<u64>()
                .unwrap(),
            Arc::new(Box::new(RealizedEthTxMaker {})),
        )?;
        let _tx_extractor_stopper = EthTxExtractorStopper(tx_extractor.clone());

        tx_extract(matches, tx_extractor)
    } else if command == "convert" {
        let tx_converter = EthTxExtractor::new_from_spec(
            matches.value_of("genesis").unwrap(),
            matches.value_of("txs").unwrap(),
            matches.value_of("nonce_dir").unwrap().to_string(),
            matches
                .value_of("from_block")
                .unwrap()
                .parse::<u64>()
                .unwrap(),
            Arc::new(Box::new(EthTxMaker::default())),
        )?;
        let _tx_converter_stopper = EthTxExtractorStopper(tx_converter.clone());

        tx_extract(matches, tx_converter)
    } else if command == "run" {
        tx_replay(matches)
    } else {
        println!("Unknown command: {}", command);
        Ok(())
    }
}

use cfx_types::hexstr_to_h256;
use cfxcore::{
    block_data_manager::StateAvailabilityBoundary,
    statedb::StateDb,
    storage::{
        state::StateTrait,
        storage_db::key_value_db::{KeyValueDbTrait, KeyValueDbTraitRead},
        KvdbSqlite, KvdbSqliteStatements, StateIndex, StateRootWithAuxInfo,
        StateRootWithAuxInfoToFromRlpBytes, StorageConfiguration,
        StorageManager, StorageManagerTrait,
    },
};
use clap::{App, Arg, ArgMatches};
use env_logger;
use error_chain::*;
use ethcore::{
    ethereum::ethash::EthashParams, spec::CommonParams as EthCommonParams,
};
use ethcore_types::{
    block::Block as EthBlock, transaction::UnverifiedTransaction,
};
use ethereum_types::*;
use ethjson::{
    spec::Spec as EthSpec, transaction::Transaction as EthJsonTransaction,
};
use ethkey::{public_to_address, Secret};
use heapsize::HeapSizeOf;
use lazy_static::*;
use log::*;
use parking_lot::{Condvar, Mutex, RwLock};
use primitives::{Account, StorageKey, MERKLE_NULL_NODE};
use rlp::{Decodable, *};
use std::{
    cell::Cell,
    collections::{vec_deque::VecDeque, BTreeMap},
    fmt::Debug,
    fs::{self, File},
    io::{self, Read, Write},
    marker::{Send, Sync},
    mem,
    ops::{Deref, Shr},
    slice,
    sync::{
        atomic::{AtomicUsize, Ordering},
        mpsc, Arc,
    },
    thread::{self, JoinHandle},
    time::Duration,
    vec::Vec,
};
