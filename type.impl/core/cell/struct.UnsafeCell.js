(function() {var type_impls = {
"cfx_storage":[["<details class=\"toggle implementors-toggle\" open><summary><section id=\"impl-UnsafeCell%3CT%3E\" class=\"impl\"><a class=\"src rightside\" href=\"https://doc.rust-lang.org/nightly/src/core/cell.rs.html#2031\">source</a><a href=\"#impl-UnsafeCell%3CT%3E\" class=\"anchor\">§</a><h3 class=\"code-header\">impl&lt;T&gt; <a class=\"struct\" href=\"https://doc.rust-lang.org/nightly/core/cell/struct.UnsafeCell.html\" title=\"struct core::cell::UnsafeCell\">UnsafeCell</a>&lt;T&gt;</h3></section></summary><div class=\"impl-items\"><details class=\"toggle method-toggle\" open><summary><section id=\"method.new\" class=\"method\"><span class=\"rightside\"><span class=\"since\" title=\"Stable since Rust version 1.0.0, const since 1.32.0\">1.0.0 (const: 1.32.0)</span> · <a class=\"src\" href=\"https://doc.rust-lang.org/nightly/src/core/cell.rs.html#2047\">source</a></span><h4 class=\"code-header\">pub const fn <a href=\"https://doc.rust-lang.org/nightly/core/cell/struct.UnsafeCell.html#tymethod.new\" class=\"fn\">new</a>(value: T) -&gt; <a class=\"struct\" href=\"https://doc.rust-lang.org/nightly/core/cell/struct.UnsafeCell.html\" title=\"struct core::cell::UnsafeCell\">UnsafeCell</a>&lt;T&gt;</h4></section></summary><div class=\"docblock\"><p>Constructs a new instance of <code>UnsafeCell</code> which will wrap the specified\nvalue.</p>\n<p>All access to the inner value through <code>&amp;UnsafeCell&lt;T&gt;</code> requires <code>unsafe</code> code.</p>\n<h5 id=\"examples\"><a class=\"doc-anchor\" href=\"#examples\">§</a>Examples</h5>\n<div class=\"example-wrap\"><pre class=\"rust rust-example-rendered\"><code><span class=\"kw\">use </span>std::cell::UnsafeCell;\n\n<span class=\"kw\">let </span>uc = UnsafeCell::new(<span class=\"number\">5</span>);</code></pre></div>\n</div></details><details class=\"toggle method-toggle\" open><summary><section id=\"method.into_inner\" class=\"method\"><span class=\"rightside\"><span class=\"since\" title=\"Stable since Rust version 1.0.0, const unstable\">1.0.0 (const: <a href=\"https://github.com/rust-lang/rust/issues/78729\" title=\"Tracking issue for const_cell_into_inner\">unstable</a>)</span> · <a class=\"src\" href=\"https://doc.rust-lang.org/nightly/src/core/cell.rs.html#2065\">source</a></span><h4 class=\"code-header\">pub fn <a href=\"https://doc.rust-lang.org/nightly/core/cell/struct.UnsafeCell.html#tymethod.into_inner\" class=\"fn\">into_inner</a>(self) -&gt; T</h4></section></summary><div class=\"docblock\"><p>Unwraps the value, consuming the cell.</p>\n<h5 id=\"examples-1\"><a class=\"doc-anchor\" href=\"#examples-1\">§</a>Examples</h5>\n<div class=\"example-wrap\"><pre class=\"rust rust-example-rendered\"><code><span class=\"kw\">use </span>std::cell::UnsafeCell;\n\n<span class=\"kw\">let </span>uc = UnsafeCell::new(<span class=\"number\">5</span>);\n\n<span class=\"kw\">let </span>five = uc.into_inner();</code></pre></div>\n</div></details></div></details>",0,"cfx_storage::impls::delta_mpt::node_memory_manager::TrieNodeDeltaMptCell"],["<details class=\"toggle implementors-toggle\" open><summary><section id=\"impl-UnsafeCell%3CT%3E\" class=\"impl\"><a class=\"src rightside\" href=\"https://doc.rust-lang.org/nightly/src/core/cell.rs.html#2070\">source</a><a href=\"#impl-UnsafeCell%3CT%3E\" class=\"anchor\">§</a><h3 class=\"code-header\">impl&lt;T&gt; <a class=\"struct\" href=\"https://doc.rust-lang.org/nightly/core/cell/struct.UnsafeCell.html\" title=\"struct core::cell::UnsafeCell\">UnsafeCell</a>&lt;T&gt;<div class=\"where\">where\n    T: ?<a class=\"trait\" href=\"https://doc.rust-lang.org/nightly/core/marker/trait.Sized.html\" title=\"trait core::marker::Sized\">Sized</a>,</div></h3></section></summary><div class=\"impl-items\"><details class=\"toggle method-toggle\" open><summary><section id=\"method.from_mut\" class=\"method\"><a class=\"src rightside\" href=\"https://doc.rust-lang.org/nightly/src/core/cell.rs.html#2087\">source</a><h4 class=\"code-header\">pub const fn <a href=\"https://doc.rust-lang.org/nightly/core/cell/struct.UnsafeCell.html#tymethod.from_mut\" class=\"fn\">from_mut</a>(value: <a class=\"primitive\" href=\"https://doc.rust-lang.org/nightly/std/primitive.reference.html\">&amp;mut T</a>) -&gt; &amp;mut <a class=\"struct\" href=\"https://doc.rust-lang.org/nightly/core/cell/struct.UnsafeCell.html\" title=\"struct core::cell::UnsafeCell\">UnsafeCell</a>&lt;T&gt;</h4></section><span class=\"item-info\"><div class=\"stab unstable\"><span class=\"emoji\">🔬</span><span>This is a nightly-only experimental API. (<code>unsafe_cell_from_mut</code>)</span></div></span></summary><div class=\"docblock\"><p>Converts from <code>&amp;mut T</code> to <code>&amp;mut UnsafeCell&lt;T&gt;</code>.</p>\n<h5 id=\"examples\"><a class=\"doc-anchor\" href=\"#examples\">§</a>Examples</h5>\n<div class=\"example-wrap\"><pre class=\"rust rust-example-rendered\"><code><span class=\"kw\">use </span>std::cell::UnsafeCell;\n\n<span class=\"kw\">let </span><span class=\"kw-2\">mut </span>val = <span class=\"number\">42</span>;\n<span class=\"kw\">let </span>uc = UnsafeCell::from_mut(<span class=\"kw-2\">&amp;mut </span>val);\n\n<span class=\"kw-2\">*</span>uc.get_mut() -= <span class=\"number\">1</span>;\n<span class=\"macro\">assert_eq!</span>(<span class=\"kw-2\">*</span>uc.get_mut(), <span class=\"number\">41</span>);</code></pre></div>\n</div></details><details class=\"toggle method-toggle\" open><summary><section id=\"method.get\" class=\"method\"><span class=\"rightside\"><span class=\"since\" title=\"Stable since Rust version 1.0.0, const since 1.32.0\">1.0.0 (const: 1.32.0)</span> · <a class=\"src\" href=\"https://doc.rust-lang.org/nightly/src/core/cell.rs.html#2112\">source</a></span><h4 class=\"code-header\">pub const fn <a href=\"https://doc.rust-lang.org/nightly/core/cell/struct.UnsafeCell.html#tymethod.get\" class=\"fn\">get</a>(&amp;self) -&gt; <a class=\"primitive\" href=\"https://doc.rust-lang.org/nightly/std/primitive.pointer.html\">*mut T</a></h4></section></summary><div class=\"docblock\"><p>Gets a mutable pointer to the wrapped value.</p>\n<p>This can be cast to a pointer of any kind.\nEnsure that the access is unique (no active references, mutable or not)\nwhen casting to <code>&amp;mut T</code>, and ensure that there are no mutations\nor mutable aliases going on when casting to <code>&amp;T</code></p>\n<h5 id=\"examples-1\"><a class=\"doc-anchor\" href=\"#examples-1\">§</a>Examples</h5>\n<div class=\"example-wrap\"><pre class=\"rust rust-example-rendered\"><code><span class=\"kw\">use </span>std::cell::UnsafeCell;\n\n<span class=\"kw\">let </span>uc = UnsafeCell::new(<span class=\"number\">5</span>);\n\n<span class=\"kw\">let </span>five = uc.get();</code></pre></div>\n</div></details><details class=\"toggle method-toggle\" open><summary><section id=\"method.get_mut\" class=\"method\"><span class=\"rightside\"><span class=\"since\" title=\"Stable since Rust version 1.50.0, const unstable\">1.50.0 (const: <a href=\"https://github.com/rust-lang/rust/issues/88836\" title=\"Tracking issue for const_unsafecell_get_mut\">unstable</a>)</span> · <a class=\"src\" href=\"https://doc.rust-lang.org/nightly/src/core/cell.rs.html#2137\">source</a></span><h4 class=\"code-header\">pub fn <a href=\"https://doc.rust-lang.org/nightly/core/cell/struct.UnsafeCell.html#tymethod.get_mut\" class=\"fn\">get_mut</a>(&amp;mut self) -&gt; <a class=\"primitive\" href=\"https://doc.rust-lang.org/nightly/std/primitive.reference.html\">&amp;mut T</a></h4></section></summary><div class=\"docblock\"><p>Returns a mutable reference to the underlying data.</p>\n<p>This call borrows the <code>UnsafeCell</code> mutably (at compile-time) which\nguarantees that we possess the only reference.</p>\n<h5 id=\"examples-2\"><a class=\"doc-anchor\" href=\"#examples-2\">§</a>Examples</h5>\n<div class=\"example-wrap\"><pre class=\"rust rust-example-rendered\"><code><span class=\"kw\">use </span>std::cell::UnsafeCell;\n\n<span class=\"kw\">let </span><span class=\"kw-2\">mut </span>c = UnsafeCell::new(<span class=\"number\">5</span>);\n<span class=\"kw-2\">*</span>c.get_mut() += <span class=\"number\">1</span>;\n\n<span class=\"macro\">assert_eq!</span>(<span class=\"kw-2\">*</span>c.get_mut(), <span class=\"number\">6</span>);</code></pre></div>\n</div></details><details class=\"toggle method-toggle\" open><summary><section id=\"method.raw_get\" class=\"method\"><span class=\"rightside\"><span class=\"since\" title=\"Stable since Rust version 1.56.0, const since 1.56.0\">1.56.0 (const: 1.56.0)</span> · <a class=\"src\" href=\"https://doc.rust-lang.org/nightly/src/core/cell.rs.html#2173\">source</a></span><h4 class=\"code-header\">pub const fn <a href=\"https://doc.rust-lang.org/nightly/core/cell/struct.UnsafeCell.html#tymethod.raw_get\" class=\"fn\">raw_get</a>(this: <a class=\"primitive\" href=\"https://doc.rust-lang.org/nightly/std/primitive.pointer.html\">*const </a><a class=\"struct\" href=\"https://doc.rust-lang.org/nightly/core/cell/struct.UnsafeCell.html\" title=\"struct core::cell::UnsafeCell\">UnsafeCell</a>&lt;T&gt;) -&gt; <a class=\"primitive\" href=\"https://doc.rust-lang.org/nightly/std/primitive.pointer.html\">*mut T</a></h4></section></summary><div class=\"docblock\"><p>Gets a mutable pointer to the wrapped value.\nThe difference from <a href=\"https://doc.rust-lang.org/nightly/core/cell/struct.UnsafeCell.html#method.get\" title=\"method core::cell::UnsafeCell::get\"><code>get</code></a> is that this function accepts a raw pointer,\nwhich is useful to avoid the creation of temporary references.</p>\n<p>The result can be cast to a pointer of any kind.\nEnsure that the access is unique (no active references, mutable or not)\nwhen casting to <code>&amp;mut T</code>, and ensure that there are no mutations\nor mutable aliases going on when casting to <code>&amp;T</code>.</p>\n<h5 id=\"examples-3\"><a class=\"doc-anchor\" href=\"#examples-3\">§</a>Examples</h5>\n<p>Gradual initialization of an <code>UnsafeCell</code> requires <code>raw_get</code>, as\ncalling <code>get</code> would require creating a reference to uninitialized data:</p>\n\n<div class=\"example-wrap\"><pre class=\"rust rust-example-rendered\"><code><span class=\"kw\">use </span>std::cell::UnsafeCell;\n<span class=\"kw\">use </span>std::mem::MaybeUninit;\n\n<span class=\"kw\">let </span>m = MaybeUninit::&lt;UnsafeCell&lt;i32&gt;&gt;::uninit();\n<span class=\"kw\">unsafe </span>{ UnsafeCell::raw_get(m.as_ptr()).write(<span class=\"number\">5</span>); }\n<span class=\"comment\">// avoid below which references to uninitialized data\n// unsafe { UnsafeCell::get(&amp;*m.as_ptr()).write(5); }\n</span><span class=\"kw\">let </span>uc = <span class=\"kw\">unsafe </span>{ m.assume_init() };\n\n<span class=\"macro\">assert_eq!</span>(uc.into_inner(), <span class=\"number\">5</span>);</code></pre></div>\n</div></details></div></details>",0,"cfx_storage::impls::delta_mpt::node_memory_manager::TrieNodeDeltaMptCell"],["<section id=\"impl-Sync-for-UnsafeCell%3CT%3E\" class=\"impl\"><span class=\"rightside\"><span class=\"since\" title=\"Stable since Rust version 1.0.0\">1.0.0</span> · <a class=\"src\" href=\"https://doc.rust-lang.org/nightly/src/core/cell.rs.html#2029\">source</a></span><a href=\"#impl-Sync-for-UnsafeCell%3CT%3E\" class=\"anchor\">§</a><h3 class=\"code-header\">impl&lt;T&gt; !<a class=\"trait\" href=\"https://doc.rust-lang.org/nightly/core/marker/trait.Sync.html\" title=\"trait core::marker::Sync\">Sync</a> for <a class=\"struct\" href=\"https://doc.rust-lang.org/nightly/core/cell/struct.UnsafeCell.html\" title=\"struct core::cell::UnsafeCell\">UnsafeCell</a>&lt;T&gt;<div class=\"where\">where\n    T: ?<a class=\"trait\" href=\"https://doc.rust-lang.org/nightly/core/marker/trait.Sized.html\" title=\"trait core::marker::Sized\">Sized</a>,</div></h3></section>","Sync","cfx_storage::impls::delta_mpt::node_memory_manager::TrieNodeDeltaMptCell"],["<details class=\"toggle implementors-toggle\" open><summary><section id=\"impl-Debug-for-UnsafeCell%3CT%3E\" class=\"impl\"><span class=\"rightside\"><span class=\"since\" title=\"Stable since Rust version 1.9.0\">1.9.0</span> · <a class=\"src\" href=\"https://doc.rust-lang.org/nightly/src/core/fmt/mod.rs.html#2574\">source</a></span><a href=\"#impl-Debug-for-UnsafeCell%3CT%3E\" class=\"anchor\">§</a><h3 class=\"code-header\">impl&lt;T&gt; <a class=\"trait\" href=\"https://doc.rust-lang.org/nightly/core/fmt/trait.Debug.html\" title=\"trait core::fmt::Debug\">Debug</a> for <a class=\"struct\" href=\"https://doc.rust-lang.org/nightly/core/cell/struct.UnsafeCell.html\" title=\"struct core::cell::UnsafeCell\">UnsafeCell</a>&lt;T&gt;<div class=\"where\">where\n    T: ?<a class=\"trait\" href=\"https://doc.rust-lang.org/nightly/core/marker/trait.Sized.html\" title=\"trait core::marker::Sized\">Sized</a>,</div></h3></section></summary><div class=\"impl-items\"><details class=\"toggle method-toggle\" open><summary><section id=\"method.fmt\" class=\"method trait-impl\"><a class=\"src rightside\" href=\"https://doc.rust-lang.org/nightly/src/core/fmt/mod.rs.html#2575\">source</a><a href=\"#method.fmt\" class=\"anchor\">§</a><h4 class=\"code-header\">fn <a href=\"https://doc.rust-lang.org/nightly/core/fmt/trait.Debug.html#tymethod.fmt\" class=\"fn\">fmt</a>(&amp;self, f: &amp;mut <a class=\"struct\" href=\"https://doc.rust-lang.org/nightly/core/fmt/struct.Formatter.html\" title=\"struct core::fmt::Formatter\">Formatter</a>&lt;'_&gt;) -&gt; <a class=\"enum\" href=\"https://doc.rust-lang.org/nightly/core/result/enum.Result.html\" title=\"enum core::result::Result\">Result</a>&lt;<a class=\"primitive\" href=\"https://doc.rust-lang.org/nightly/std/primitive.unit.html\">()</a>, <a class=\"struct\" href=\"https://doc.rust-lang.org/nightly/core/fmt/struct.Error.html\" title=\"struct core::fmt::Error\">Error</a>&gt;</h4></section></summary><div class='docblock'>Formats the value using the given formatter. <a href=\"https://doc.rust-lang.org/nightly/core/fmt/trait.Debug.html#tymethod.fmt\">Read more</a></div></details></div></details>","Debug","cfx_storage::impls::delta_mpt::node_memory_manager::TrieNodeDeltaMptCell"],["<section id=\"impl-DispatchFromDyn%3CUnsafeCell%3CU%3E%3E-for-UnsafeCell%3CT%3E\" class=\"impl\"><a class=\"src rightside\" href=\"https://doc.rust-lang.org/nightly/src/core/cell.rs.html#2208\">source</a><a href=\"#impl-DispatchFromDyn%3CUnsafeCell%3CU%3E%3E-for-UnsafeCell%3CT%3E\" class=\"anchor\">§</a><h3 class=\"code-header\">impl&lt;T, U&gt; <a class=\"trait\" href=\"https://doc.rust-lang.org/nightly/core/ops/unsize/trait.DispatchFromDyn.html\" title=\"trait core::ops::unsize::DispatchFromDyn\">DispatchFromDyn</a>&lt;<a class=\"struct\" href=\"https://doc.rust-lang.org/nightly/core/cell/struct.UnsafeCell.html\" title=\"struct core::cell::UnsafeCell\">UnsafeCell</a>&lt;U&gt;&gt; for <a class=\"struct\" href=\"https://doc.rust-lang.org/nightly/core/cell/struct.UnsafeCell.html\" title=\"struct core::cell::UnsafeCell\">UnsafeCell</a>&lt;T&gt;<div class=\"where\">where\n    T: <a class=\"trait\" href=\"https://doc.rust-lang.org/nightly/core/ops/unsize/trait.DispatchFromDyn.html\" title=\"trait core::ops::unsize::DispatchFromDyn\">DispatchFromDyn</a>&lt;U&gt;,</div></h3></section>","DispatchFromDyn<UnsafeCell<U>>","cfx_storage::impls::delta_mpt::node_memory_manager::TrieNodeDeltaMptCell"],["<details class=\"toggle implementors-toggle\" open><summary><section id=\"impl-From%3CT%3E-for-UnsafeCell%3CT%3E\" class=\"impl\"><span class=\"rightside\"><span class=\"since\" title=\"Stable since Rust version 1.12.0\">1.12.0</span> · <a class=\"src\" href=\"https://doc.rust-lang.org/nightly/src/core/cell.rs.html#2190\">source</a></span><a href=\"#impl-From%3CT%3E-for-UnsafeCell%3CT%3E\" class=\"anchor\">§</a><h3 class=\"code-header\">impl&lt;T&gt; <a class=\"trait\" href=\"https://doc.rust-lang.org/nightly/core/convert/trait.From.html\" title=\"trait core::convert::From\">From</a>&lt;T&gt; for <a class=\"struct\" href=\"https://doc.rust-lang.org/nightly/core/cell/struct.UnsafeCell.html\" title=\"struct core::cell::UnsafeCell\">UnsafeCell</a>&lt;T&gt;</h3></section></summary><div class=\"impl-items\"><details class=\"toggle method-toggle\" open><summary><section id=\"method.from\" class=\"method trait-impl\"><a class=\"src rightside\" href=\"https://doc.rust-lang.org/nightly/src/core/cell.rs.html#2192\">source</a><a href=\"#method.from\" class=\"anchor\">§</a><h4 class=\"code-header\">fn <a href=\"https://doc.rust-lang.org/nightly/core/convert/trait.From.html#tymethod.from\" class=\"fn\">from</a>(t: T) -&gt; <a class=\"struct\" href=\"https://doc.rust-lang.org/nightly/core/cell/struct.UnsafeCell.html\" title=\"struct core::cell::UnsafeCell\">UnsafeCell</a>&lt;T&gt;</h4></section></summary><div class=\"docblock\"><p>Creates a new <code>UnsafeCell&lt;T&gt;</code> containing the given value.</p>\n</div></details></div></details>","From<T>","cfx_storage::impls::delta_mpt::node_memory_manager::TrieNodeDeltaMptCell"],["<details class=\"toggle implementors-toggle\" open><summary><section id=\"impl-Default-for-UnsafeCell%3CT%3E\" class=\"impl\"><span class=\"rightside\"><span class=\"since\" title=\"Stable since Rust version 1.10.0\">1.10.0</span> · <a class=\"src\" href=\"https://doc.rust-lang.org/nightly/src/core/cell.rs.html#2182\">source</a></span><a href=\"#impl-Default-for-UnsafeCell%3CT%3E\" class=\"anchor\">§</a><h3 class=\"code-header\">impl&lt;T&gt; <a class=\"trait\" href=\"https://doc.rust-lang.org/nightly/core/default/trait.Default.html\" title=\"trait core::default::Default\">Default</a> for <a class=\"struct\" href=\"https://doc.rust-lang.org/nightly/core/cell/struct.UnsafeCell.html\" title=\"struct core::cell::UnsafeCell\">UnsafeCell</a>&lt;T&gt;<div class=\"where\">where\n    T: <a class=\"trait\" href=\"https://doc.rust-lang.org/nightly/core/default/trait.Default.html\" title=\"trait core::default::Default\">Default</a>,</div></h3></section></summary><div class=\"impl-items\"><details class=\"toggle method-toggle\" open><summary><section id=\"method.default\" class=\"method trait-impl\"><a class=\"src rightside\" href=\"https://doc.rust-lang.org/nightly/src/core/cell.rs.html#2184\">source</a><a href=\"#method.default\" class=\"anchor\">§</a><h4 class=\"code-header\">fn <a href=\"https://doc.rust-lang.org/nightly/core/default/trait.Default.html#tymethod.default\" class=\"fn\">default</a>() -&gt; <a class=\"struct\" href=\"https://doc.rust-lang.org/nightly/core/cell/struct.UnsafeCell.html\" title=\"struct core::cell::UnsafeCell\">UnsafeCell</a>&lt;T&gt;</h4></section></summary><div class=\"docblock\"><p>Creates an <code>UnsafeCell</code>, with the <code>Default</code> value for T.</p>\n</div></details></div></details>","Default","cfx_storage::impls::delta_mpt::node_memory_manager::TrieNodeDeltaMptCell"],["<section id=\"impl-RefUnwindSafe-for-UnsafeCell%3CT%3E\" class=\"impl\"><span class=\"rightside\"><span class=\"since\" title=\"Stable since Rust version 1.9.0\">1.9.0</span> · <a class=\"src\" href=\"https://doc.rust-lang.org/nightly/src/core/panic/unwind_safe.rs.html#200\">source</a></span><a href=\"#impl-RefUnwindSafe-for-UnsafeCell%3CT%3E\" class=\"anchor\">§</a><h3 class=\"code-header\">impl&lt;T&gt; !<a class=\"trait\" href=\"https://doc.rust-lang.org/nightly/core/panic/unwind_safe/trait.RefUnwindSafe.html\" title=\"trait core::panic::unwind_safe::RefUnwindSafe\">RefUnwindSafe</a> for <a class=\"struct\" href=\"https://doc.rust-lang.org/nightly/core/cell/struct.UnsafeCell.html\" title=\"struct core::cell::UnsafeCell\">UnsafeCell</a>&lt;T&gt;<div class=\"where\">where\n    T: ?<a class=\"trait\" href=\"https://doc.rust-lang.org/nightly/core/marker/trait.Sized.html\" title=\"trait core::marker::Sized\">Sized</a>,</div></h3></section>","RefUnwindSafe","cfx_storage::impls::delta_mpt::node_memory_manager::TrieNodeDeltaMptCell"],["<section id=\"impl-CoerceUnsized%3CUnsafeCell%3CU%3E%3E-for-UnsafeCell%3CT%3E\" class=\"impl\"><a class=\"src rightside\" href=\"https://doc.rust-lang.org/nightly/src/core/cell.rs.html#2198\">source</a><a href=\"#impl-CoerceUnsized%3CUnsafeCell%3CU%3E%3E-for-UnsafeCell%3CT%3E\" class=\"anchor\">§</a><h3 class=\"code-header\">impl&lt;T, U&gt; <a class=\"trait\" href=\"https://doc.rust-lang.org/nightly/core/ops/unsize/trait.CoerceUnsized.html\" title=\"trait core::ops::unsize::CoerceUnsized\">CoerceUnsized</a>&lt;<a class=\"struct\" href=\"https://doc.rust-lang.org/nightly/core/cell/struct.UnsafeCell.html\" title=\"struct core::cell::UnsafeCell\">UnsafeCell</a>&lt;U&gt;&gt; for <a class=\"struct\" href=\"https://doc.rust-lang.org/nightly/core/cell/struct.UnsafeCell.html\" title=\"struct core::cell::UnsafeCell\">UnsafeCell</a>&lt;T&gt;<div class=\"where\">where\n    T: <a class=\"trait\" href=\"https://doc.rust-lang.org/nightly/core/ops/unsize/trait.CoerceUnsized.html\" title=\"trait core::ops::unsize::CoerceUnsized\">CoerceUnsized</a>&lt;U&gt;,</div></h3></section>","CoerceUnsized<UnsafeCell<U>>","cfx_storage::impls::delta_mpt::node_memory_manager::TrieNodeDeltaMptCell"],["<details class=\"toggle implementors-toggle\" open><summary><section id=\"impl-MallocSizeOf-for-UnsafeCell%3CT%3E\" class=\"impl\"><a class=\"src rightside\" href=\"src/malloc_size_of/lib.rs.html#216\">source</a><a href=\"#impl-MallocSizeOf-for-UnsafeCell%3CT%3E\" class=\"anchor\">§</a><h3 class=\"code-header\">impl&lt;T&gt; <a class=\"trait\" href=\"malloc_size_of/trait.MallocSizeOf.html\" title=\"trait malloc_size_of::MallocSizeOf\">MallocSizeOf</a> for <a class=\"struct\" href=\"https://doc.rust-lang.org/nightly/core/cell/struct.UnsafeCell.html\" title=\"struct core::cell::UnsafeCell\">UnsafeCell</a>&lt;T&gt;<div class=\"where\">where\n    T: <a class=\"trait\" href=\"malloc_size_of/trait.MallocSizeOf.html\" title=\"trait malloc_size_of::MallocSizeOf\">MallocSizeOf</a>,</div></h3></section></summary><div class=\"impl-items\"><details class=\"toggle method-toggle\" open><summary><section id=\"method.size_of\" class=\"method trait-impl\"><a class=\"src rightside\" href=\"src/malloc_size_of/lib.rs.html#217\">source</a><a href=\"#method.size_of\" class=\"anchor\">§</a><h4 class=\"code-header\">fn <a href=\"malloc_size_of/trait.MallocSizeOf.html#tymethod.size_of\" class=\"fn\">size_of</a>(&amp;self, ops: &amp;mut <a class=\"struct\" href=\"malloc_size_of/struct.MallocSizeOfOps.html\" title=\"struct malloc_size_of::MallocSizeOfOps\">MallocSizeOfOps</a>) -&gt; <a class=\"primitive\" href=\"https://doc.rust-lang.org/nightly/std/primitive.usize.html\">usize</a></h4></section></summary><div class='docblock'>Measure the heap usage of all descendant heap-allocated structures, but\nnot the space taken up by the value itself.</div></details></div></details>","MallocSizeOf","cfx_storage::impls::delta_mpt::node_memory_manager::TrieNodeDeltaMptCell"],["<details class=\"toggle implementors-toggle\" open><summary><section id=\"impl-WrappedCreateFrom%3C%26T,+UnsafeCell%3CT%3E%3E-for-UnsafeCell%3CT%3E\" class=\"impl\"><a class=\"src rightside\" href=\"src/cfx_storage/utils/mod.rs.html#75-81\">source</a><a href=\"#impl-WrappedCreateFrom%3C%26T,+UnsafeCell%3CT%3E%3E-for-UnsafeCell%3CT%3E\" class=\"anchor\">§</a><h3 class=\"code-header\">impl&lt;'x, T: <a class=\"trait\" href=\"https://doc.rust-lang.org/nightly/core/clone/trait.Clone.html\" title=\"trait core::clone::Clone\">Clone</a>&gt; <a class=\"trait\" href=\"cfx_storage/utils/trait.WrappedCreateFrom.html\" title=\"trait cfx_storage::utils::WrappedCreateFrom\">WrappedCreateFrom</a>&lt;<a class=\"primitive\" href=\"https://doc.rust-lang.org/nightly/std/primitive.reference.html\">&amp;'x T</a>, <a class=\"struct\" href=\"https://doc.rust-lang.org/nightly/core/cell/struct.UnsafeCell.html\" title=\"struct core::cell::UnsafeCell\">UnsafeCell</a>&lt;T&gt;&gt; for <a class=\"struct\" href=\"https://doc.rust-lang.org/nightly/core/cell/struct.UnsafeCell.html\" title=\"struct core::cell::UnsafeCell\">UnsafeCell</a>&lt;T&gt;</h3></section></summary><div class=\"impl-items\"><section id=\"method.take\" class=\"method trait-impl\"><a class=\"src rightside\" href=\"src/cfx_storage/utils/mod.rs.html#76\">source</a><a href=\"#method.take\" class=\"anchor\">§</a><h4 class=\"code-header\">fn <a href=\"cfx_storage/utils/trait.WrappedCreateFrom.html#tymethod.take\" class=\"fn\">take</a>(val: <a class=\"primitive\" href=\"https://doc.rust-lang.org/nightly/std/primitive.reference.html\">&amp;'x T</a>) -&gt; <a class=\"struct\" href=\"https://doc.rust-lang.org/nightly/core/cell/struct.UnsafeCell.html\" title=\"struct core::cell::UnsafeCell\">UnsafeCell</a>&lt;T&gt;</h4></section><details class=\"toggle method-toggle\" open><summary><section id=\"method.take_from\" class=\"method trait-impl\"><a class=\"src rightside\" href=\"src/cfx_storage/utils/mod.rs.html#78-80\">source</a><a href=\"#method.take_from\" class=\"anchor\">§</a><h4 class=\"code-header\">fn <a href=\"cfx_storage/utils/trait.WrappedCreateFrom.html#method.take_from\" class=\"fn\">take_from</a>(dest: &amp;mut <a class=\"struct\" href=\"https://doc.rust-lang.org/nightly/core/cell/struct.UnsafeCell.html\" title=\"struct core::cell::UnsafeCell\">UnsafeCell</a>&lt;T&gt;, x: <a class=\"primitive\" href=\"https://doc.rust-lang.org/nightly/std/primitive.reference.html\">&amp;'x T</a>)</h4></section></summary><div class='docblock'>Unoptimized default implementation.</div></details></div></details>","WrappedCreateFrom<&'x T, UnsafeCell<T>>","cfx_storage::impls::delta_mpt::node_memory_manager::TrieNodeDeltaMptCell"],["<details class=\"toggle implementors-toggle\" open><summary><section id=\"impl-UnsafeCellExtension%3CT%3E-for-UnsafeCell%3CT%3E\" class=\"impl\"><a class=\"src rightside\" href=\"src/cfx_storage/utils/mod.rs.html#89-95\">source</a><a href=\"#impl-UnsafeCellExtension%3CT%3E-for-UnsafeCell%3CT%3E\" class=\"anchor\">§</a><h3 class=\"code-header\">impl&lt;T: <a class=\"trait\" href=\"https://doc.rust-lang.org/nightly/core/marker/trait.Sized.html\" title=\"trait core::marker::Sized\">Sized</a>&gt; <a class=\"trait\" href=\"cfx_storage/utils/trait.UnsafeCellExtension.html\" title=\"trait cfx_storage::utils::UnsafeCellExtension\">UnsafeCellExtension</a>&lt;T&gt; for <a class=\"struct\" href=\"https://doc.rust-lang.org/nightly/core/cell/struct.UnsafeCell.html\" title=\"struct core::cell::UnsafeCell\">UnsafeCell</a>&lt;T&gt;</h3></section></summary><div class=\"impl-items\"><section id=\"method.get_ref\" class=\"method trait-impl\"><a class=\"src rightside\" href=\"src/cfx_storage/utils/mod.rs.html#90\">source</a><a href=\"#method.get_ref\" class=\"anchor\">§</a><h4 class=\"code-header\">fn <a href=\"cfx_storage/utils/trait.UnsafeCellExtension.html#tymethod.get_ref\" class=\"fn\">get_ref</a>(&amp;self) -&gt; <a class=\"primitive\" href=\"https://doc.rust-lang.org/nightly/std/primitive.reference.html\">&amp;T</a></h4></section><section id=\"method.get_mut\" class=\"method trait-impl\"><a class=\"src rightside\" href=\"src/cfx_storage/utils/mod.rs.html#92\">source</a><a href=\"#method.get_mut\" class=\"anchor\">§</a><h4 class=\"code-header\">fn <a href=\"cfx_storage/utils/trait.UnsafeCellExtension.html#tymethod.get_mut\" class=\"fn\">get_mut</a>(&amp;mut self) -&gt; <a class=\"primitive\" href=\"https://doc.rust-lang.org/nightly/std/primitive.reference.html\">&amp;mut T</a></h4></section><section id=\"method.get_as_mut\" class=\"method trait-impl\"><a class=\"src rightside\" href=\"src/cfx_storage/utils/mod.rs.html#94\">source</a><a href=\"#method.get_as_mut\" class=\"anchor\">§</a><h4 class=\"code-header\">unsafe fn <a href=\"cfx_storage/utils/trait.UnsafeCellExtension.html#tymethod.get_as_mut\" class=\"fn\">get_as_mut</a>(&amp;self) -&gt; <a class=\"primitive\" href=\"https://doc.rust-lang.org/nightly/std/primitive.reference.html\">&amp;mut T</a></h4></section></div></details>","UnsafeCellExtension<T>","cfx_storage::impls::delta_mpt::node_memory_manager::TrieNodeDeltaMptCell"]]
};if (window.register_type_impls) {window.register_type_impls(type_impls);} else {window.pending_type_impls = type_impls;}})()