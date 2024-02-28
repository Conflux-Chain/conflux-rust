extern crate keccak_hash;
extern crate proc_macro;
extern crate proc_macro2;
extern crate quote;
extern crate syn;

use proc_macro::TokenStream;
use quote::quote;
use syn::{Error, LitStr};

#[proc_macro]
pub fn keccak(input_stream: TokenStream) -> TokenStream {
    let ast: LitStr = match syn::parse(input_stream) {
        Ok(ast) => ast,
        Err(err) => {
            return Error::new(
                err.span(),
                "only accept literature string input like \"foo\" as input",
            )
            .into_compile_error()
            .into();
        }
    };
    let hash: [u8; 32] = keccak_hash::keccak(ast.value().as_bytes()).0;
    let bytes = hash.as_ref().iter();
    let output = quote! {
        [#(#bytes,)*]
    };
    output.into()
}
