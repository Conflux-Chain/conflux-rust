(function() {var type_impls = {
"diem_types":[["<details class=\"toggle implementors-toggle\" open><summary><section id=\"impl-MultiBLSPublicKey\" class=\"impl\"><a href=\"#impl-MultiBLSPublicKey\" class=\"anchor\">§</a><h3 class=\"code-header\">impl MultiBLSPublicKey</h3></section></summary><div class=\"impl-items\"><details class=\"toggle method-toggle\" open><summary><section id=\"method.new\" class=\"method\"><h4 class=\"code-header\">pub fn <a class=\"fn\">new</a>(public_keys: <a class=\"struct\" href=\"https://doc.rust-lang.org/nightly/alloc/vec/struct.Vec.html\" title=\"struct alloc::vec::Vec\">Vec</a>&lt;BLSPublicKey&gt;) -&gt; MultiBLSPublicKey</h4></section></summary><div class=\"docblock\"><p>Construct a new MultiBLSPublicKey.</p>\n</div></details><details class=\"toggle method-toggle\" open><summary><section id=\"method.public_keys\" class=\"method\"><h4 class=\"code-header\">pub fn <a class=\"fn\">public_keys</a>(&amp;self) -&gt; &amp;<a class=\"struct\" href=\"https://doc.rust-lang.org/nightly/alloc/vec/struct.Vec.html\" title=\"struct alloc::vec::Vec\">Vec</a>&lt;BLSPublicKey&gt;</h4></section></summary><div class=\"docblock\"><p>Getter public_keys</p>\n</div></details><details class=\"toggle method-toggle\" open><summary><section id=\"method.to_bytes\" class=\"method\"><h4 class=\"code-header\">pub fn <a class=\"fn\">to_bytes</a>(&amp;self) -&gt; <a class=\"struct\" href=\"https://doc.rust-lang.org/nightly/alloc/vec/struct.Vec.html\" title=\"struct alloc::vec::Vec\">Vec</a>&lt;<a class=\"primitive\" href=\"https://doc.rust-lang.org/nightly/std/primitive.u8.html\">u8</a>&gt; <a href=\"#\" class=\"tooltip\" data-notable-ty=\"Vec&lt;u8&gt;\">ⓘ</a></h4></section></summary><div class=\"docblock\"><p>Serialize a MultiBLSPublicKey.</p>\n</div></details></div></details>",0,"diem_types::validator_config::MultiConsensusPublicKey"],["<details class=\"toggle implementors-toggle\" open><summary><section id=\"impl-Hash-for-MultiBLSPublicKey\" class=\"impl\"><a href=\"#impl-Hash-for-MultiBLSPublicKey\" class=\"anchor\">§</a><h3 class=\"code-header\">impl <a class=\"trait\" href=\"https://doc.rust-lang.org/nightly/core/hash/trait.Hash.html\" title=\"trait core::hash::Hash\">Hash</a> for MultiBLSPublicKey</h3></section></summary><div class=\"impl-items\"><details class=\"toggle method-toggle\" open><summary><section id=\"method.hash\" class=\"method trait-impl\"><a href=\"#method.hash\" class=\"anchor\">§</a><h4 class=\"code-header\">fn <a href=\"https://doc.rust-lang.org/nightly/core/hash/trait.Hash.html#tymethod.hash\" class=\"fn\">hash</a>&lt;H&gt;(&amp;self, state: <a class=\"primitive\" href=\"https://doc.rust-lang.org/nightly/std/primitive.reference.html\">&amp;mut H</a>)<div class=\"where\">where\n    H: <a class=\"trait\" href=\"https://doc.rust-lang.org/nightly/core/hash/trait.Hasher.html\" title=\"trait core::hash::Hasher\">Hasher</a>,</div></h4></section></summary><div class='docblock'>Feeds this value into the given <a href=\"https://doc.rust-lang.org/nightly/core/hash/trait.Hasher.html\" title=\"trait core::hash::Hasher\"><code>Hasher</code></a>. <a href=\"https://doc.rust-lang.org/nightly/core/hash/trait.Hash.html#tymethod.hash\">Read more</a></div></details><details class=\"toggle method-toggle\" open><summary><section id=\"method.hash_slice\" class=\"method trait-impl\"><span class=\"rightside\"><span class=\"since\" title=\"Stable since Rust version 1.3.0\">1.3.0</span> · <a class=\"src\" href=\"https://doc.rust-lang.org/nightly/src/core/hash/mod.rs.html#238-240\">source</a></span><a href=\"#method.hash_slice\" class=\"anchor\">§</a><h4 class=\"code-header\">fn <a href=\"https://doc.rust-lang.org/nightly/core/hash/trait.Hash.html#method.hash_slice\" class=\"fn\">hash_slice</a>&lt;H&gt;(data: &amp;<a class=\"primitive\" href=\"https://doc.rust-lang.org/nightly/std/primitive.slice.html\">[Self]</a>, state: <a class=\"primitive\" href=\"https://doc.rust-lang.org/nightly/std/primitive.reference.html\">&amp;mut H</a>)<div class=\"where\">where\n    H: <a class=\"trait\" href=\"https://doc.rust-lang.org/nightly/core/hash/trait.Hasher.html\" title=\"trait core::hash::Hasher\">Hasher</a>,\n    Self: <a class=\"trait\" href=\"https://doc.rust-lang.org/nightly/core/marker/trait.Sized.html\" title=\"trait core::marker::Sized\">Sized</a>,</div></h4></section></summary><div class='docblock'>Feeds a slice of this type into the given <a href=\"https://doc.rust-lang.org/nightly/core/hash/trait.Hasher.html\" title=\"trait core::hash::Hasher\"><code>Hasher</code></a>. <a href=\"https://doc.rust-lang.org/nightly/core/hash/trait.Hash.html#method.hash_slice\">Read more</a></div></details></div></details>","Hash","diem_types::validator_config::MultiConsensusPublicKey"],["<details class=\"toggle implementors-toggle\" open><summary><section id=\"impl-VerifyingKey-for-MultiBLSPublicKey\" class=\"impl\"><a href=\"#impl-VerifyingKey-for-MultiBLSPublicKey\" class=\"anchor\">§</a><h3 class=\"code-header\">impl VerifyingKey for MultiBLSPublicKey</h3></section></summary><div class=\"docblock\"><p>We deduce VerifyingKey from pointing to the signature material\nwe get the ability to do <code>pubkey.validate(msg, signature)</code></p>\n</div><div class=\"impl-items\"><details class=\"toggle\" open><summary><section id=\"associatedtype.SignatureMaterial\" class=\"associatedtype trait-impl\"><a href=\"#associatedtype.SignatureMaterial\" class=\"anchor\">§</a><h4 class=\"code-header\">type <a class=\"associatedtype\">SignatureMaterial</a> = MultiBLSSignature</h4></section></summary><div class='docblock'>The associated signature type for this verifying key.</div></details><details class=\"toggle\" open><summary><section id=\"associatedtype.SigningKeyMaterial\" class=\"associatedtype trait-impl\"><a href=\"#associatedtype.SigningKeyMaterial\" class=\"anchor\">§</a><h4 class=\"code-header\">type <a class=\"associatedtype\">SigningKeyMaterial</a> = MultiBLSPrivateKey</h4></section></summary><div class='docblock'>The associated signing key type for this verifying key.</div></details><details class=\"toggle method-toggle\" open><summary><section id=\"method.verify_struct_signature\" class=\"method trait-impl\"><a href=\"#method.verify_struct_signature\" class=\"anchor\">§</a><h4 class=\"code-header\">fn <a class=\"fn\">verify_struct_signature</a>&lt;T&gt;(\n    &amp;self,\n    message: <a class=\"primitive\" href=\"https://doc.rust-lang.org/nightly/std/primitive.reference.html\">&amp;T</a>,\n    signature: &amp;Self::SignatureMaterial\n) -&gt; <a class=\"enum\" href=\"https://doc.rust-lang.org/nightly/core/result/enum.Result.html\" title=\"enum core::result::Result\">Result</a>&lt;<a class=\"primitive\" href=\"https://doc.rust-lang.org/nightly/std/primitive.unit.html\">()</a>, <a class=\"struct\" href=\"https://docs.rs/anyhow/1.0.70/anyhow/struct.Error.html\" title=\"struct anyhow::Error\">Error</a>&gt;<div class=\"where\">where\n    T: CryptoHash + <a class=\"trait\" href=\"https://docs.rs/serde/1.0.193/serde/ser/trait.Serialize.html\" title=\"trait serde::ser::Serialize\">Serialize</a>,</div></h4></section></summary><div class='docblock'>We provide the striaghtfoward implementation which dispatches to the\nsignature.</div></details><details class=\"toggle method-toggle\" open><summary><section id=\"method.batch_verify\" class=\"method trait-impl\"><a href=\"#method.batch_verify\" class=\"anchor\">§</a><h4 class=\"code-header\">fn <a class=\"fn\">batch_verify</a>&lt;T&gt;(\n    message: <a class=\"primitive\" href=\"https://doc.rust-lang.org/nightly/std/primitive.reference.html\">&amp;T</a>,\n    keys_and_signatures: <a class=\"struct\" href=\"https://doc.rust-lang.org/nightly/alloc/vec/struct.Vec.html\" title=\"struct alloc::vec::Vec\">Vec</a>&lt;(Self, Self::SignatureMaterial)&gt;\n) -&gt; <a class=\"enum\" href=\"https://doc.rust-lang.org/nightly/core/result/enum.Result.html\" title=\"enum core::result::Result\">Result</a>&lt;<a class=\"primitive\" href=\"https://doc.rust-lang.org/nightly/std/primitive.unit.html\">()</a>, <a class=\"struct\" href=\"https://docs.rs/anyhow/1.0.70/anyhow/struct.Error.html\" title=\"struct anyhow::Error\">Error</a>&gt;<div class=\"where\">where\n    T: CryptoHash + <a class=\"trait\" href=\"https://docs.rs/serde/1.0.193/serde/ser/trait.Serialize.html\" title=\"trait serde::ser::Serialize\">Serialize</a>,</div></h4></section></summary><div class='docblock'>We provide the implementation which dispatches to the signature.</div></details></div></details>","VerifyingKey","diem_types::validator_config::MultiConsensusPublicKey"],["<details class=\"toggle implementors-toggle\" open><summary><section id=\"impl-Debug-for-MultiBLSPublicKey\" class=\"impl\"><a href=\"#impl-Debug-for-MultiBLSPublicKey\" class=\"anchor\">§</a><h3 class=\"code-header\">impl <a class=\"trait\" href=\"https://doc.rust-lang.org/nightly/core/fmt/trait.Debug.html\" title=\"trait core::fmt::Debug\">Debug</a> for MultiBLSPublicKey</h3></section></summary><div class=\"impl-items\"><details class=\"toggle method-toggle\" open><summary><section id=\"method.fmt\" class=\"method trait-impl\"><a href=\"#method.fmt\" class=\"anchor\">§</a><h4 class=\"code-header\">fn <a href=\"https://doc.rust-lang.org/nightly/core/fmt/trait.Debug.html#tymethod.fmt\" class=\"fn\">fmt</a>(&amp;self, f: &amp;mut <a class=\"struct\" href=\"https://doc.rust-lang.org/nightly/core/fmt/struct.Formatter.html\" title=\"struct core::fmt::Formatter\">Formatter</a>&lt;'_&gt;) -&gt; <a class=\"enum\" href=\"https://doc.rust-lang.org/nightly/core/result/enum.Result.html\" title=\"enum core::result::Result\">Result</a>&lt;<a class=\"primitive\" href=\"https://doc.rust-lang.org/nightly/std/primitive.unit.html\">()</a>, <a class=\"struct\" href=\"https://doc.rust-lang.org/nightly/core/fmt/struct.Error.html\" title=\"struct core::fmt::Error\">Error</a>&gt;</h4></section></summary><div class='docblock'>Formats the value using the given formatter. <a href=\"https://doc.rust-lang.org/nightly/core/fmt/trait.Debug.html#tymethod.fmt\">Read more</a></div></details></div></details>","Debug","diem_types::validator_config::MultiConsensusPublicKey"],["<details class=\"toggle implementors-toggle\" open><summary><section id=\"impl-PartialEq-for-MultiBLSPublicKey\" class=\"impl\"><a href=\"#impl-PartialEq-for-MultiBLSPublicKey\" class=\"anchor\">§</a><h3 class=\"code-header\">impl <a class=\"trait\" href=\"https://doc.rust-lang.org/nightly/core/cmp/trait.PartialEq.html\" title=\"trait core::cmp::PartialEq\">PartialEq</a> for MultiBLSPublicKey</h3></section></summary><div class=\"impl-items\"><details class=\"toggle method-toggle\" open><summary><section id=\"method.eq\" class=\"method trait-impl\"><a href=\"#method.eq\" class=\"anchor\">§</a><h4 class=\"code-header\">fn <a href=\"https://doc.rust-lang.org/nightly/core/cmp/trait.PartialEq.html#tymethod.eq\" class=\"fn\">eq</a>(&amp;self, other: &amp;MultiBLSPublicKey) -&gt; <a class=\"primitive\" href=\"https://doc.rust-lang.org/nightly/std/primitive.bool.html\">bool</a></h4></section></summary><div class='docblock'>This method tests for <code>self</code> and <code>other</code> values to be equal, and is used\nby <code>==</code>.</div></details><details class=\"toggle method-toggle\" open><summary><section id=\"method.ne\" class=\"method trait-impl\"><span class=\"rightside\"><span class=\"since\" title=\"Stable since Rust version 1.0.0\">1.0.0</span> · <a class=\"src\" href=\"https://doc.rust-lang.org/nightly/src/core/cmp.rs.html#242\">source</a></span><a href=\"#method.ne\" class=\"anchor\">§</a><h4 class=\"code-header\">fn <a href=\"https://doc.rust-lang.org/nightly/core/cmp/trait.PartialEq.html#method.ne\" class=\"fn\">ne</a>(&amp;self, other: <a class=\"primitive\" href=\"https://doc.rust-lang.org/nightly/std/primitive.reference.html\">&amp;Rhs</a>) -&gt; <a class=\"primitive\" href=\"https://doc.rust-lang.org/nightly/std/primitive.bool.html\">bool</a></h4></section></summary><div class='docblock'>This method tests for <code>!=</code>. The default implementation is almost always\nsufficient, and should not be overridden without very good reason.</div></details></div></details>","PartialEq","diem_types::validator_config::MultiConsensusPublicKey"],["<section id=\"impl-Eq-for-MultiBLSPublicKey\" class=\"impl\"><a href=\"#impl-Eq-for-MultiBLSPublicKey\" class=\"anchor\">§</a><h3 class=\"code-header\">impl <a class=\"trait\" href=\"https://doc.rust-lang.org/nightly/core/cmp/trait.Eq.html\" title=\"trait core::cmp::Eq\">Eq</a> for MultiBLSPublicKey</h3></section>","Eq","diem_types::validator_config::MultiConsensusPublicKey"],["<details class=\"toggle implementors-toggle\" open><summary><section id=\"impl-ValidCryptoMaterial-for-MultiBLSPublicKey\" class=\"impl\"><a href=\"#impl-ValidCryptoMaterial-for-MultiBLSPublicKey\" class=\"anchor\">§</a><h3 class=\"code-header\">impl ValidCryptoMaterial for MultiBLSPublicKey</h3></section></summary><div class=\"impl-items\"><details class=\"toggle method-toggle\" open><summary><section id=\"method.to_bytes\" class=\"method trait-impl\"><a href=\"#method.to_bytes\" class=\"anchor\">§</a><h4 class=\"code-header\">fn <a class=\"fn\">to_bytes</a>(&amp;self) -&gt; <a class=\"struct\" href=\"https://doc.rust-lang.org/nightly/alloc/vec/struct.Vec.html\" title=\"struct alloc::vec::Vec\">Vec</a>&lt;<a class=\"primitive\" href=\"https://doc.rust-lang.org/nightly/std/primitive.u8.html\">u8</a>&gt; <a href=\"#\" class=\"tooltip\" data-notable-ty=\"Vec&lt;u8&gt;\">ⓘ</a></h4></section></summary><div class='docblock'>Convert the valid crypto material to bytes.</div></details></div></details>","ValidCryptoMaterial","diem_types::validator_config::MultiConsensusPublicKey"],["<details class=\"toggle implementors-toggle\" open><summary><section id=\"impl-Clone-for-MultiBLSPublicKey\" class=\"impl\"><a href=\"#impl-Clone-for-MultiBLSPublicKey\" class=\"anchor\">§</a><h3 class=\"code-header\">impl <a class=\"trait\" href=\"https://doc.rust-lang.org/nightly/core/clone/trait.Clone.html\" title=\"trait core::clone::Clone\">Clone</a> for MultiBLSPublicKey</h3></section></summary><div class=\"impl-items\"><details class=\"toggle method-toggle\" open><summary><section id=\"method.clone\" class=\"method trait-impl\"><a href=\"#method.clone\" class=\"anchor\">§</a><h4 class=\"code-header\">fn <a href=\"https://doc.rust-lang.org/nightly/core/clone/trait.Clone.html#tymethod.clone\" class=\"fn\">clone</a>(&amp;self) -&gt; MultiBLSPublicKey</h4></section></summary><div class='docblock'>Returns a copy of the value. <a href=\"https://doc.rust-lang.org/nightly/core/clone/trait.Clone.html#tymethod.clone\">Read more</a></div></details><details class=\"toggle method-toggle\" open><summary><section id=\"method.clone_from\" class=\"method trait-impl\"><span class=\"rightside\"><span class=\"since\" title=\"Stable since Rust version 1.0.0\">1.0.0</span> · <a class=\"src\" href=\"https://doc.rust-lang.org/nightly/src/core/clone.rs.html#169\">source</a></span><a href=\"#method.clone_from\" class=\"anchor\">§</a><h4 class=\"code-header\">fn <a href=\"https://doc.rust-lang.org/nightly/core/clone/trait.Clone.html#method.clone_from\" class=\"fn\">clone_from</a>(&amp;mut self, source: <a class=\"primitive\" href=\"https://doc.rust-lang.org/nightly/std/primitive.reference.html\">&amp;Self</a>)</h4></section></summary><div class='docblock'>Performs copy-assignment from <code>source</code>. <a href=\"https://doc.rust-lang.org/nightly/core/clone/trait.Clone.html#method.clone_from\">Read more</a></div></details></div></details>","Clone","diem_types::validator_config::MultiConsensusPublicKey"],["<details class=\"toggle implementors-toggle\" open><summary><section id=\"impl-Display-for-MultiBLSPublicKey\" class=\"impl\"><a href=\"#impl-Display-for-MultiBLSPublicKey\" class=\"anchor\">§</a><h3 class=\"code-header\">impl <a class=\"trait\" href=\"https://doc.rust-lang.org/nightly/core/fmt/trait.Display.html\" title=\"trait core::fmt::Display\">Display</a> for MultiBLSPublicKey</h3></section></summary><div class=\"impl-items\"><details class=\"toggle method-toggle\" open><summary><section id=\"method.fmt\" class=\"method trait-impl\"><a href=\"#method.fmt\" class=\"anchor\">§</a><h4 class=\"code-header\">fn <a href=\"https://doc.rust-lang.org/nightly/core/fmt/trait.Display.html#tymethod.fmt\" class=\"fn\">fmt</a>(&amp;self, f: &amp;mut <a class=\"struct\" href=\"https://doc.rust-lang.org/nightly/core/fmt/struct.Formatter.html\" title=\"struct core::fmt::Formatter\">Formatter</a>&lt;'_&gt;) -&gt; <a class=\"enum\" href=\"https://doc.rust-lang.org/nightly/core/result/enum.Result.html\" title=\"enum core::result::Result\">Result</a>&lt;<a class=\"primitive\" href=\"https://doc.rust-lang.org/nightly/std/primitive.unit.html\">()</a>, <a class=\"struct\" href=\"https://doc.rust-lang.org/nightly/core/fmt/struct.Error.html\" title=\"struct core::fmt::Error\">Error</a>&gt;</h4></section></summary><div class='docblock'>Formats the value using the given formatter. <a href=\"https://doc.rust-lang.org/nightly/core/fmt/trait.Display.html#tymethod.fmt\">Read more</a></div></details></div></details>","Display","diem_types::validator_config::MultiConsensusPublicKey"],["<details class=\"toggle implementors-toggle\" open><summary><section id=\"impl-PublicKey-for-MultiBLSPublicKey\" class=\"impl\"><a href=\"#impl-PublicKey-for-MultiBLSPublicKey\" class=\"anchor\">§</a><h3 class=\"code-header\">impl PublicKey for MultiBLSPublicKey</h3></section></summary><div class=\"docblock\"><p>We deduce PublicKey from this.</p>\n</div><div class=\"impl-items\"><details class=\"toggle\" open><summary><section id=\"associatedtype.PrivateKeyMaterial\" class=\"associatedtype trait-impl\"><a href=\"#associatedtype.PrivateKeyMaterial\" class=\"anchor\">§</a><h4 class=\"code-header\">type <a class=\"associatedtype\">PrivateKeyMaterial</a> = MultiBLSPrivateKey</h4></section></summary><div class='docblock'>We require public / private types to be coupled, i.e. their\nassociated type is each other.</div></details></div></details>","PublicKey","diem_types::validator_config::MultiConsensusPublicKey"],["<details class=\"toggle implementors-toggle\" open><summary><section id=\"impl-From%3C%26MultiBLSPrivateKey%3E-for-MultiBLSPublicKey\" class=\"impl\"><a href=\"#impl-From%3C%26MultiBLSPrivateKey%3E-for-MultiBLSPublicKey\" class=\"anchor\">§</a><h3 class=\"code-header\">impl <a class=\"trait\" href=\"https://doc.rust-lang.org/nightly/core/convert/trait.From.html\" title=\"trait core::convert::From\">From</a>&lt;&amp;MultiBLSPrivateKey&gt; for MultiBLSPublicKey</h3></section></summary><div class=\"docblock\"><p>Implementing From&lt;&amp;PrivateKey&lt;…&gt;&gt; allows to derive a public key in a more\nelegant fashion.</p>\n</div><div class=\"impl-items\"><details class=\"toggle method-toggle\" open><summary><section id=\"method.from\" class=\"method trait-impl\"><a href=\"#method.from\" class=\"anchor\">§</a><h4 class=\"code-header\">fn <a href=\"https://doc.rust-lang.org/nightly/core/convert/trait.From.html#tymethod.from\" class=\"fn\">from</a>(private_key: &amp;MultiBLSPrivateKey) -&gt; MultiBLSPublicKey</h4></section></summary><div class='docblock'>Converts to this type from the input type.</div></details></div></details>","From<&MultiBLSPrivateKey>","diem_types::validator_config::MultiConsensusPublicKey"],["<details class=\"toggle implementors-toggle\" open><summary><section id=\"impl-From%3CBLSPublicKey%3E-for-MultiBLSPublicKey\" class=\"impl\"><a href=\"#impl-From%3CBLSPublicKey%3E-for-MultiBLSPublicKey\" class=\"anchor\">§</a><h3 class=\"code-header\">impl <a class=\"trait\" href=\"https://doc.rust-lang.org/nightly/core/convert/trait.From.html\" title=\"trait core::convert::From\">From</a>&lt;BLSPublicKey&gt; for MultiBLSPublicKey</h3></section></summary><div class=\"docblock\"><p>Convenient method to create a MultiBLSPublicKey from a single\nBLSPublicKey.</p>\n</div><div class=\"impl-items\"><details class=\"toggle method-toggle\" open><summary><section id=\"method.from\" class=\"method trait-impl\"><a href=\"#method.from\" class=\"anchor\">§</a><h4 class=\"code-header\">fn <a href=\"https://doc.rust-lang.org/nightly/core/convert/trait.From.html#tymethod.from\" class=\"fn\">from</a>(ed_public_key: BLSPublicKey) -&gt; MultiBLSPublicKey</h4></section></summary><div class='docblock'>Converts to this type from the input type.</div></details></div></details>","From<BLSPublicKey>","diem_types::validator_config::MultiConsensusPublicKey"],["<section id=\"impl-StructuralPartialEq-for-MultiBLSPublicKey\" class=\"impl\"><a href=\"#impl-StructuralPartialEq-for-MultiBLSPublicKey\" class=\"anchor\">§</a><h3 class=\"code-header\">impl <a class=\"trait\" href=\"https://doc.rust-lang.org/nightly/core/marker/trait.StructuralPartialEq.html\" title=\"trait core::marker::StructuralPartialEq\">StructuralPartialEq</a> for MultiBLSPublicKey</h3></section>","StructuralPartialEq","diem_types::validator_config::MultiConsensusPublicKey"],["<details class=\"toggle implementors-toggle\" open><summary><section id=\"impl-Serialize-for-MultiBLSPublicKey\" class=\"impl\"><a href=\"#impl-Serialize-for-MultiBLSPublicKey\" class=\"anchor\">§</a><h3 class=\"code-header\">impl <a class=\"trait\" href=\"https://docs.rs/serde/1.0.193/serde/ser/trait.Serialize.html\" title=\"trait serde::ser::Serialize\">Serialize</a> for MultiBLSPublicKey</h3></section></summary><div class=\"impl-items\"><details class=\"toggle method-toggle\" open><summary><section id=\"method.serialize\" class=\"method trait-impl\"><a href=\"#method.serialize\" class=\"anchor\">§</a><h4 class=\"code-header\">fn <a href=\"https://docs.rs/serde/1.0.193/serde/ser/trait.Serialize.html#tymethod.serialize\" class=\"fn\">serialize</a>&lt;S&gt;(\n    &amp;self,\n    serializer: S\n) -&gt; <a class=\"enum\" href=\"https://doc.rust-lang.org/nightly/core/result/enum.Result.html\" title=\"enum core::result::Result\">Result</a>&lt;&lt;S as <a class=\"trait\" href=\"https://docs.rs/serde/1.0.193/serde/ser/trait.Serializer.html\" title=\"trait serde::ser::Serializer\">Serializer</a>&gt;::<a class=\"associatedtype\" href=\"https://docs.rs/serde/1.0.193/serde/ser/trait.Serializer.html#associatedtype.Ok\" title=\"type serde::ser::Serializer::Ok\">Ok</a>, &lt;S as <a class=\"trait\" href=\"https://docs.rs/serde/1.0.193/serde/ser/trait.Serializer.html\" title=\"trait serde::ser::Serializer\">Serializer</a>&gt;::<a class=\"associatedtype\" href=\"https://docs.rs/serde/1.0.193/serde/ser/trait.Serializer.html#associatedtype.Error\" title=\"type serde::ser::Serializer::Error\">Error</a>&gt;<div class=\"where\">where\n    S: <a class=\"trait\" href=\"https://docs.rs/serde/1.0.193/serde/ser/trait.Serializer.html\" title=\"trait serde::ser::Serializer\">Serializer</a>,</div></h4></section></summary><div class='docblock'>Serialize this value into the given Serde serializer. <a href=\"https://docs.rs/serde/1.0.193/serde/ser/trait.Serialize.html#tymethod.serialize\">Read more</a></div></details></div></details>","Serialize","diem_types::validator_config::MultiConsensusPublicKey"],["<details class=\"toggle implementors-toggle\" open><summary><section id=\"impl-Deserialize%3C'de%3E-for-MultiBLSPublicKey\" class=\"impl\"><a href=\"#impl-Deserialize%3C'de%3E-for-MultiBLSPublicKey\" class=\"anchor\">§</a><h3 class=\"code-header\">impl&lt;'de&gt; <a class=\"trait\" href=\"https://docs.rs/serde/1.0.193/serde/de/trait.Deserialize.html\" title=\"trait serde::de::Deserialize\">Deserialize</a>&lt;'de&gt; for MultiBLSPublicKey</h3></section></summary><div class=\"impl-items\"><details class=\"toggle method-toggle\" open><summary><section id=\"method.deserialize\" class=\"method trait-impl\"><a href=\"#method.deserialize\" class=\"anchor\">§</a><h4 class=\"code-header\">fn <a href=\"https://docs.rs/serde/1.0.193/serde/de/trait.Deserialize.html#tymethod.deserialize\" class=\"fn\">deserialize</a>&lt;D&gt;(\n    deserializer: D\n) -&gt; <a class=\"enum\" href=\"https://doc.rust-lang.org/nightly/core/result/enum.Result.html\" title=\"enum core::result::Result\">Result</a>&lt;MultiBLSPublicKey, &lt;D as <a class=\"trait\" href=\"https://docs.rs/serde/1.0.193/serde/de/trait.Deserializer.html\" title=\"trait serde::de::Deserializer\">Deserializer</a>&lt;'de&gt;&gt;::<a class=\"associatedtype\" href=\"https://docs.rs/serde/1.0.193/serde/de/trait.Deserializer.html#associatedtype.Error\" title=\"type serde::de::Deserializer::Error\">Error</a>&gt;<div class=\"where\">where\n    D: <a class=\"trait\" href=\"https://docs.rs/serde/1.0.193/serde/de/trait.Deserializer.html\" title=\"trait serde::de::Deserializer\">Deserializer</a>&lt;'de&gt;,</div></h4></section></summary><div class='docblock'>Deserialize this value from the given Serde deserializer. <a href=\"https://docs.rs/serde/1.0.193/serde/de/trait.Deserialize.html#tymethod.deserialize\">Read more</a></div></details></div></details>","Deserialize<'de>","diem_types::validator_config::MultiConsensusPublicKey"],["<details class=\"toggle implementors-toggle\" open><summary><section id=\"impl-Length-for-MultiBLSPublicKey\" class=\"impl\"><a href=\"#impl-Length-for-MultiBLSPublicKey\" class=\"anchor\">§</a><h3 class=\"code-header\">impl Length for MultiBLSPublicKey</h3></section></summary><div class=\"impl-items\"><details class=\"toggle method-toggle\" open><summary><section id=\"method.length\" class=\"method trait-impl\"><a href=\"#method.length\" class=\"anchor\">§</a><h4 class=\"code-header\">fn <a class=\"fn\">length</a>(&amp;self) -&gt; <a class=\"primitive\" href=\"https://doc.rust-lang.org/nightly/std/primitive.usize.html\">usize</a></h4></section></summary><div class='docblock'>The serialized length of the data</div></details></div></details>","Length","diem_types::validator_config::MultiConsensusPublicKey"],["<details class=\"toggle implementors-toggle\" open><summary><section id=\"impl-TryFrom%3C%26%5Bu8%5D%3E-for-MultiBLSPublicKey\" class=\"impl\"><a href=\"#impl-TryFrom%3C%26%5Bu8%5D%3E-for-MultiBLSPublicKey\" class=\"anchor\">§</a><h3 class=\"code-header\">impl <a class=\"trait\" href=\"https://doc.rust-lang.org/nightly/core/convert/trait.TryFrom.html\" title=\"trait core::convert::TryFrom\">TryFrom</a>&lt;&amp;[<a class=\"primitive\" href=\"https://doc.rust-lang.org/nightly/std/primitive.u8.html\">u8</a>]&gt; for MultiBLSPublicKey</h3></section></summary><div class=\"impl-items\"><details class=\"toggle method-toggle\" open><summary><section id=\"method.try_from\" class=\"method trait-impl\"><a href=\"#method.try_from\" class=\"anchor\">§</a><h4 class=\"code-header\">fn <a href=\"https://doc.rust-lang.org/nightly/core/convert/trait.TryFrom.html#tymethod.try_from\" class=\"fn\">try_from</a>(bytes: &amp;[<a class=\"primitive\" href=\"https://doc.rust-lang.org/nightly/std/primitive.u8.html\">u8</a>]) -&gt; <a class=\"enum\" href=\"https://doc.rust-lang.org/nightly/core/result/enum.Result.html\" title=\"enum core::result::Result\">Result</a>&lt;MultiBLSPublicKey, CryptoMaterialError&gt;</h4></section></summary><div class=\"docblock\"><p>Deserialize a MultiBLSPublicKey. This method will also check for key\nand threshold validity, and will only deserialize keys that are safe\nagainst small subgroup attacks.</p>\n</div></details><details class=\"toggle\" open><summary><section id=\"associatedtype.Error\" class=\"associatedtype trait-impl\"><a href=\"#associatedtype.Error\" class=\"anchor\">§</a><h4 class=\"code-header\">type <a href=\"https://doc.rust-lang.org/nightly/core/convert/trait.TryFrom.html#associatedtype.Error\" class=\"associatedtype\">Error</a> = CryptoMaterialError</h4></section></summary><div class='docblock'>The type returned in the event of a conversion error.</div></details></div></details>","TryFrom<&[u8]>","diem_types::validator_config::MultiConsensusPublicKey"]]
};if (window.register_type_impls) {window.register_type_impls(type_impls);} else {window.pending_type_impls = type_impls;}})()