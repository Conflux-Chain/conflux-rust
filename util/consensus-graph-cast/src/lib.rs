extern crate proc_macro;
use proc_macro::TokenStream;
use quote::quote;
use syn;

#[proc_macro_derive(ConsensusCast)]
pub fn derive_consensus_cast(input: TokenStream) -> TokenStream {
    let ast = syn::parse(input).unwrap();
    impl_consensus_cast_macro(&ast)
}

fn impl_consensus_cast_macro(ast: &syn::DeriveInput) -> TokenStream {
    let name = &ast.ident;
    let gen = quote! {
        impl ConsensusCast for #name {
            fn consensus_graph(&self) -> &ConsensusGraph {
                self.consensus
                .as_any()
                .downcast_ref::<ConsensusGraph>()
                .expect("downcast should succeed")
            }
        }
    };
    gen.into()
}
