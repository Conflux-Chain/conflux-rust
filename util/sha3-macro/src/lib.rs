extern crate keccak_hash;
extern crate proc_macro;
extern crate proc_macro2;
extern crate quote;
extern crate syn;

use proc_macro::TokenStream;
use quote::quote;
use syn::LitStr;

#[proc_macro]
pub fn keccak(input_stream: TokenStream) -> TokenStream {
    let ast: LitStr = syn::parse(input_stream)
        .expect("Only accept literature string input like \"foo\" as input");
    let hash: [u8; 32] = keccak_hash::keccak(ast.value().as_bytes()).0;
    let bytes = hash.as_ref().iter();
    let output = quote! {
        [#(#bytes,)*]
    };
    output.into()
}
