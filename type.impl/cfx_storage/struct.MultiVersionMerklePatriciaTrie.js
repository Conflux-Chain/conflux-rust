(function() {var type_impls = {
"cfx_storage":[["<details class=\"toggle implementors-toggle\" open><summary><section id=\"impl-MultiVersionMerklePatriciaTrie\" class=\"impl\"><a class=\"src rightside\" href=\"src/cfx_storage/impls/delta_mpt/mod.rs.html#105-387\">source</a><a href=\"#impl-MultiVersionMerklePatriciaTrie\" class=\"anchor\">§</a><h3 class=\"code-header\">impl <a class=\"struct\" href=\"cfx_storage/struct.MultiVersionMerklePatriciaTrie.html\" title=\"struct cfx_storage::MultiVersionMerklePatriciaTrie\">MultiVersionMerklePatriciaTrie</a></h3></section></summary><div class=\"impl-items\"><section id=\"method.new\" class=\"method\"><a class=\"src rightside\" href=\"src/cfx_storage/impls/delta_mpt/mod.rs.html#106-137\">source</a><h4 class=\"code-header\">pub fn <a href=\"cfx_storage/struct.MultiVersionMerklePatriciaTrie.html#tymethod.new\" class=\"fn\">new</a>(\n    db_manager: <a class=\"struct\" href=\"https://doc.rust-lang.org/nightly/alloc/sync/struct.Arc.html\" title=\"struct alloc::sync::Arc\">Arc</a>&lt;dyn <a class=\"trait\" href=\"cfx_storage/delta_mpt_open_db_manager/trait.OpenableOnDemandOpenDeltaDbTrait.html\" title=\"trait cfx_storage::delta_mpt_open_db_manager::OpenableOnDemandOpenDeltaDbTrait\">OpenableOnDemandOpenDeltaDbTrait</a>&gt;,\n    snapshot_epoch_id: <a class=\"type\" href=\"primitives/epoch/type.EpochId.html\" title=\"type primitives::epoch::EpochId\">EpochId</a>,\n    storage_manager: <a class=\"struct\" href=\"https://doc.rust-lang.org/nightly/alloc/sync/struct.Arc.html\" title=\"struct alloc::sync::Arc\">Arc</a>&lt;StorageManager&gt;,\n    mpt_id: <a class=\"primitive\" href=\"https://doc.rust-lang.org/nightly/std/primitive.u16.html\">u16</a>,\n    node_memory_manager: <a class=\"struct\" href=\"https://doc.rust-lang.org/nightly/alloc/sync/struct.Arc.html\" title=\"struct alloc::sync::Arc\">Arc</a>&lt;NodeMemoryManager&lt;&lt;LRU&lt;<a class=\"primitive\" href=\"https://doc.rust-lang.org/nightly/std/primitive.u32.html\">u32</a>, (<a class=\"primitive\" href=\"https://doc.rust-lang.org/nightly/std/primitive.u16.html\">u16</a>, <a class=\"primitive\" href=\"https://doc.rust-lang.org/nightly/std/primitive.u32.html\">u32</a>)&gt; as CacheAlgorithm&gt;::CacheAlgoData, LRU&lt;<a class=\"primitive\" href=\"https://doc.rust-lang.org/nightly/std/primitive.u32.html\">u32</a>, (<a class=\"primitive\" href=\"https://doc.rust-lang.org/nightly/std/primitive.u16.html\">u16</a>, <a class=\"primitive\" href=\"https://doc.rust-lang.org/nightly/std/primitive.u32.html\">u32</a>)&gt;&gt;&gt;\n) -&gt; <a class=\"type\" href=\"cfx_storage/type.Result.html\" title=\"type cfx_storage::Result\">Result</a>&lt;Self&gt;</h4></section><section id=\"method.new_single_mpt\" class=\"method\"><a class=\"src rightside\" href=\"src/cfx_storage/impls/delta_mpt/mod.rs.html#139-163\">source</a><h4 class=\"code-header\">pub fn <a href=\"cfx_storage/struct.MultiVersionMerklePatriciaTrie.html#tymethod.new_single_mpt\" class=\"fn\">new_single_mpt</a>(\n    db_manager: <a class=\"struct\" href=\"https://doc.rust-lang.org/nightly/alloc/sync/struct.Arc.html\" title=\"struct alloc::sync::Arc\">Arc</a>&lt;dyn <a class=\"trait\" href=\"cfx_storage/delta_mpt_open_db_manager/trait.OpenableOnDemandOpenDeltaDbTrait.html\" title=\"trait cfx_storage::delta_mpt_open_db_manager::OpenableOnDemandOpenDeltaDbTrait\">OpenableOnDemandOpenDeltaDbTrait</a>&gt;,\n    node_memory_manager: <a class=\"struct\" href=\"https://doc.rust-lang.org/nightly/alloc/sync/struct.Arc.html\" title=\"struct alloc::sync::Arc\">Arc</a>&lt;NodeMemoryManager&lt;&lt;LRU&lt;<a class=\"primitive\" href=\"https://doc.rust-lang.org/nightly/std/primitive.u32.html\">u32</a>, (<a class=\"primitive\" href=\"https://doc.rust-lang.org/nightly/std/primitive.u16.html\">u16</a>, <a class=\"primitive\" href=\"https://doc.rust-lang.org/nightly/std/primitive.u32.html\">u32</a>)&gt; as CacheAlgorithm&gt;::CacheAlgoData, LRU&lt;<a class=\"primitive\" href=\"https://doc.rust-lang.org/nightly/std/primitive.u32.html\">u32</a>, (<a class=\"primitive\" href=\"https://doc.rust-lang.org/nightly/std/primitive.u16.html\">u16</a>, <a class=\"primitive\" href=\"https://doc.rust-lang.org/nightly/std/primitive.u32.html\">u32</a>)&gt;&gt;&gt;\n) -&gt; <a class=\"type\" href=\"cfx_storage/type.Result.html\" title=\"type cfx_storage::Result\">Result</a>&lt;Self&gt;</h4></section><section id=\"method.get_mpt_id\" class=\"method\"><a class=\"src rightside\" href=\"src/cfx_storage/impls/delta_mpt/mod.rs.html#165\">source</a><h4 class=\"code-header\">pub fn <a href=\"cfx_storage/struct.MultiVersionMerklePatriciaTrie.html#tymethod.get_mpt_id\" class=\"fn\">get_mpt_id</a>(&amp;self) -&gt; <a class=\"primitive\" href=\"https://doc.rust-lang.org/nightly/std/primitive.u16.html\">u16</a></h4></section><section id=\"method.start_commit\" class=\"method\"><a class=\"src rightside\" href=\"src/cfx_storage/impls/delta_mpt/mod.rs.html#167-174\">source</a><h4 class=\"code-header\">pub fn <a href=\"cfx_storage/struct.MultiVersionMerklePatriciaTrie.html#tymethod.start_commit\" class=\"fn\">start_commit</a>(\n    &amp;self\n) -&gt; <a class=\"type\" href=\"cfx_storage/type.Result.html\" title=\"type cfx_storage::Result\">Result</a>&lt;<a class=\"struct\" href=\"cfx_storage/struct.AtomicCommitTransaction.html\" title=\"struct cfx_storage::AtomicCommitTransaction\">AtomicCommitTransaction</a>&lt;'_, <a class=\"struct\" href=\"https://doc.rust-lang.org/nightly/alloc/boxed/struct.Box.html\" title=\"struct alloc::boxed::Box\">Box</a>&lt;<a class=\"type\" href=\"cfx_storage/storage_db/delta_db_manager/type.DeltaDbTransactionTraitObj.html\" title=\"type cfx_storage::storage_db::delta_db_manager::DeltaDbTransactionTraitObj\">DeltaDbTransactionTraitObj</a>&gt;&gt;&gt;</h4></section><section id=\"method.get_root_node_ref_by_epoch\" class=\"method\"><a class=\"src rightside\" href=\"src/cfx_storage/impls/delta_mpt/mod.rs.html#269-278\">source</a><h4 class=\"code-header\">pub fn <a href=\"cfx_storage/struct.MultiVersionMerklePatriciaTrie.html#tymethod.get_root_node_ref_by_epoch\" class=\"fn\">get_root_node_ref_by_epoch</a>(\n    &amp;self,\n    epoch_id: &amp;<a class=\"type\" href=\"primitives/epoch/type.EpochId.html\" title=\"type primitives::epoch::EpochId\">EpochId</a>\n) -&gt; <a class=\"type\" href=\"cfx_storage/type.Result.html\" title=\"type cfx_storage::Result\">Result</a>&lt;<a class=\"enum\" href=\"https://doc.rust-lang.org/nightly/core/option/enum.Option.html\" title=\"enum core::option::Option\">Option</a>&lt;<a class=\"enum\" href=\"https://doc.rust-lang.org/nightly/core/option/enum.Option.html\" title=\"enum core::option::Option\">Option</a>&lt;<a class=\"enum\" href=\"cfx_storage/enum.NodeRefDeltaMpt.html\" title=\"enum cfx_storage::NodeRefDeltaMpt\">NodeRefDeltaMpt</a>&gt;&gt;&gt;</h4></section><details class=\"toggle method-toggle\" open><summary><section id=\"method.get_root_node_ref\" class=\"method\"><a class=\"src rightside\" href=\"src/cfx_storage/impls/delta_mpt/mod.rs.html#281-294\">source</a><h4 class=\"code-header\">pub fn <a href=\"cfx_storage/struct.MultiVersionMerklePatriciaTrie.html#tymethod.get_root_node_ref\" class=\"fn\">get_root_node_ref</a>(\n    &amp;self,\n    merkle_root: &amp;<a class=\"type\" href=\"primitives/state_root/type.MerkleHash.html\" title=\"type primitives::state_root::MerkleHash\">MerkleHash</a>\n) -&gt; <a class=\"type\" href=\"cfx_storage/type.Result.html\" title=\"type cfx_storage::Result\">Result</a>&lt;<a class=\"enum\" href=\"https://doc.rust-lang.org/nightly/core/option/enum.Option.html\" title=\"enum core::option::Option\">Option</a>&lt;<a class=\"enum\" href=\"cfx_storage/enum.NodeRefDeltaMpt.html\" title=\"enum cfx_storage::NodeRefDeltaMpt\">NodeRefDeltaMpt</a>&gt;&gt;</h4></section></summary><div class=\"docblock\"><p>Find trie root by merkle root is mainly for debugging.</p>\n</div></details><section id=\"method.get_parent_epoch\" class=\"method\"><a class=\"src rightside\" href=\"src/cfx_storage/impls/delta_mpt/mod.rs.html#296-306\">source</a><h4 class=\"code-header\">pub fn <a href=\"cfx_storage/struct.MultiVersionMerklePatriciaTrie.html#tymethod.get_parent_epoch\" class=\"fn\">get_parent_epoch</a>(&amp;self, epoch_id: &amp;<a class=\"type\" href=\"primitives/epoch/type.EpochId.html\" title=\"type primitives::epoch::EpochId\">EpochId</a>) -&gt; <a class=\"type\" href=\"cfx_storage/type.Result.html\" title=\"type cfx_storage::Result\">Result</a>&lt;<a class=\"enum\" href=\"https://doc.rust-lang.org/nightly/core/option/enum.Option.html\" title=\"enum core::option::Option\">Option</a>&lt;<a class=\"type\" href=\"primitives/epoch/type.EpochId.html\" title=\"type primitives::epoch::EpochId\">EpochId</a>&gt;&gt;</h4></section><section id=\"method.get_node_memory_manager\" class=\"method\"><a class=\"src rightside\" href=\"src/cfx_storage/impls/delta_mpt/mod.rs.html#346-348\">source</a><h4 class=\"code-header\">pub fn <a href=\"cfx_storage/struct.MultiVersionMerklePatriciaTrie.html#tymethod.get_node_memory_manager\" class=\"fn\">get_node_memory_manager</a>(\n    &amp;self\n) -&gt; &amp;NodeMemoryManager&lt;&lt;LRU&lt;<a class=\"primitive\" href=\"https://doc.rust-lang.org/nightly/std/primitive.u32.html\">u32</a>, (<a class=\"primitive\" href=\"https://doc.rust-lang.org/nightly/std/primitive.u16.html\">u16</a>, <a class=\"primitive\" href=\"https://doc.rust-lang.org/nightly/std/primitive.u32.html\">u32</a>)&gt; as CacheAlgorithm&gt;::CacheAlgoData, LRU&lt;<a class=\"primitive\" href=\"https://doc.rust-lang.org/nightly/std/primitive.u32.html\">u32</a>, (<a class=\"primitive\" href=\"https://doc.rust-lang.org/nightly/std/primitive.u16.html\">u16</a>, <a class=\"primitive\" href=\"https://doc.rust-lang.org/nightly/std/primitive.u32.html\">u32</a>)&gt;&gt;</h4></section><section id=\"method.get_merkle\" class=\"method\"><a class=\"src rightside\" href=\"src/cfx_storage/impls/delta_mpt/mod.rs.html#350-373\">source</a><h4 class=\"code-header\">pub fn <a href=\"cfx_storage/struct.MultiVersionMerklePatriciaTrie.html#tymethod.get_merkle\" class=\"fn\">get_merkle</a>(\n    &amp;self,\n    maybe_node: <a class=\"enum\" href=\"https://doc.rust-lang.org/nightly/core/option/enum.Option.html\" title=\"enum core::option::Option\">Option</a>&lt;<a class=\"enum\" href=\"cfx_storage/enum.NodeRefDeltaMpt.html\" title=\"enum cfx_storage::NodeRefDeltaMpt\">NodeRefDeltaMpt</a>&gt;\n) -&gt; <a class=\"type\" href=\"cfx_storage/type.Result.html\" title=\"type cfx_storage::Result\">Result</a>&lt;<a class=\"enum\" href=\"https://doc.rust-lang.org/nightly/core/option/enum.Option.html\" title=\"enum core::option::Option\">Option</a>&lt;<a class=\"type\" href=\"primitives/state_root/type.MerkleHash.html\" title=\"type primitives::state_root::MerkleHash\">MerkleHash</a>&gt;&gt;</h4></section><section id=\"method.get_merkle_root_by_epoch_id\" class=\"method\"><a class=\"src rightside\" href=\"src/cfx_storage/impls/delta_mpt/mod.rs.html#375-384\">source</a><h4 class=\"code-header\">pub fn <a href=\"cfx_storage/struct.MultiVersionMerklePatriciaTrie.html#tymethod.get_merkle_root_by_epoch_id\" class=\"fn\">get_merkle_root_by_epoch_id</a>(\n    &amp;self,\n    epoch_id: &amp;<a class=\"type\" href=\"primitives/epoch/type.EpochId.html\" title=\"type primitives::epoch::EpochId\">EpochId</a>\n) -&gt; <a class=\"type\" href=\"cfx_storage/type.Result.html\" title=\"type cfx_storage::Result\">Result</a>&lt;<a class=\"enum\" href=\"https://doc.rust-lang.org/nightly/core/option/enum.Option.html\" title=\"enum core::option::Option\">Option</a>&lt;<a class=\"type\" href=\"primitives/state_root/type.MerkleHash.html\" title=\"type primitives::state_root::MerkleHash\">MerkleHash</a>&gt;&gt;</h4></section><section id=\"method.log_usage\" class=\"method\"><a class=\"src rightside\" href=\"src/cfx_storage/impls/delta_mpt/mod.rs.html#386\">source</a><h4 class=\"code-header\">pub fn <a href=\"cfx_storage/struct.MultiVersionMerklePatriciaTrie.html#tymethod.log_usage\" class=\"fn\">log_usage</a>(&amp;self)</h4></section></div></details>",0,"cfx_storage::impls::delta_mpt::DeltaMpt"],["<details class=\"toggle implementors-toggle\" open><summary><section id=\"impl-MultiVersionMerklePatriciaTrie\" class=\"impl\"><a class=\"src rightside\" href=\"src/cfx_storage/impls/delta_mpt/mod.rs.html#390-411\">source</a><a href=\"#impl-MultiVersionMerklePatriciaTrie\" class=\"anchor\">§</a><h3 class=\"code-header\">impl <a class=\"struct\" href=\"cfx_storage/struct.MultiVersionMerklePatriciaTrie.html\" title=\"struct cfx_storage::MultiVersionMerklePatriciaTrie\">MultiVersionMerklePatriciaTrie</a></h3></section></summary><div class=\"impl-items\"><section id=\"method.get_arc_db\" class=\"method\"><a class=\"src rightside\" href=\"src/cfx_storage/impls/delta_mpt/mod.rs.html#408-410\">source</a><h4 class=\"code-header\">pub fn <a href=\"cfx_storage/struct.MultiVersionMerklePatriciaTrie.html#tymethod.get_arc_db\" class=\"fn\">get_arc_db</a>(&amp;self) -&gt; <a class=\"type\" href=\"cfx_storage/type.Result.html\" title=\"type cfx_storage::Result\">Result</a>&lt;<a class=\"struct\" href=\"cfx_storage/delta_mpt_open_db_manager/struct.ArcDeltaDbWrapper.html\" title=\"struct cfx_storage::delta_mpt_open_db_manager::ArcDeltaDbWrapper\">ArcDeltaDbWrapper</a>&gt;</h4></section></div></details>",0,"cfx_storage::impls::delta_mpt::DeltaMpt"],["<details class=\"toggle implementors-toggle\" open><summary><section id=\"impl-MallocSizeOf-for-MultiVersionMerklePatriciaTrie\" class=\"impl\"><a class=\"src rightside\" href=\"src/cfx_storage/impls/delta_mpt/mod.rs.html#94-103\">source</a><a href=\"#impl-MallocSizeOf-for-MultiVersionMerklePatriciaTrie\" class=\"anchor\">§</a><h3 class=\"code-header\">impl <a class=\"trait\" href=\"malloc_size_of/trait.MallocSizeOf.html\" title=\"trait malloc_size_of::MallocSizeOf\">MallocSizeOf</a> for <a class=\"struct\" href=\"cfx_storage/struct.MultiVersionMerklePatriciaTrie.html\" title=\"struct cfx_storage::MultiVersionMerklePatriciaTrie\">MultiVersionMerklePatriciaTrie</a></h3></section></summary><div class=\"impl-items\"><details class=\"toggle method-toggle\" open><summary><section id=\"method.size_of\" class=\"method trait-impl\"><a class=\"src rightside\" href=\"src/cfx_storage/impls/delta_mpt/mod.rs.html#95-102\">source</a><a href=\"#method.size_of\" class=\"anchor\">§</a><h4 class=\"code-header\">fn <a href=\"malloc_size_of/trait.MallocSizeOf.html#tymethod.size_of\" class=\"fn\">size_of</a>(&amp;self, ops: &amp;mut <a class=\"struct\" href=\"malloc_size_of/struct.MallocSizeOfOps.html\" title=\"struct malloc_size_of::MallocSizeOfOps\">MallocSizeOfOps</a>) -&gt; <a class=\"primitive\" href=\"https://doc.rust-lang.org/nightly/std/primitive.usize.html\">usize</a></h4></section></summary><div class='docblock'>Measure the heap usage of all descendant heap-allocated structures, but\nnot the space taken up by the value itself.</div></details></div></details>","MallocSizeOf","cfx_storage::impls::delta_mpt::DeltaMpt"]]
};if (window.register_type_impls) {window.register_type_impls(type_impls);} else {window.pending_type_impls = type_impls;}})()