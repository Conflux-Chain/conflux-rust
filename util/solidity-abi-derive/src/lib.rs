extern crate proc_macro;
extern crate proc_macro2;
extern crate quote;
extern crate syn;

use proc_macro::TokenStream;
use proc_macro2::{Ident, Span};
use proc_macro_crate::{crate_name, FoundCrate};
use quote::quote;
use syn::{parse_macro_input, Data, DeriveInput, Field, Type};

#[proc_macro_derive(ABIVariable)]
pub fn keccak(input_stream: TokenStream) -> TokenStream {
    let ast = parse_macro_input!(input_stream as DeriveInput);

    let ident = &ast.ident;

    let fields: Vec<&Field> = if let Data::Struct(ref data_struct) = ast.data {
        data_struct.fields.iter().collect()
    } else {
        unimplemented!("Only support struct");
    };

    let field_idents: Vec<proc_macro2::TokenStream> = fields
        .iter()
        .enumerate()
        .map(|(idx, field)| match &field.ident {
            Some(ident) => quote! {#ident},
            None => {
                let idx = syn::Index::from(idx);
                quote! {#idx}
            }
        })
        .collect();

    let types: Vec<Type> =
        fields.iter().map(|field| field.ty.clone()).collect();

    let dummy_types: Vec<syn::Ident> = (0..types.len())
        .map(|idx| syn::Ident::new(&format!("Field{}", idx), Span::call_site()))
        .collect();

    let abi_crate = match crate_name("solidity-abi")
        .expect("solidity-abi is present in `Cargo.toml`")
    {
        FoundCrate::Itself => quote!(crate),
        FoundCrate::Name(name) => {
            let ident = Ident::new(&name, Span::call_site());
            quote!( #ident )
        }
    };

    let dummy_const = syn::Ident::new(
        &format!("_IMPL_ABI_VARIABLE_DUMMY_{}", ident),
        Span::call_site(),
    );

    let env = quote! {
        use #abi_crate::{ABIDecodeError, ABIListWriter, ABIVariable, LinkedBytes, read_abi_list};
        #(type #dummy_types = #types;)*
    };

    let impl_abi = quote! {
        impl ABIVariable for #ident {
            const BASIC_TYPE: bool = false;
            const STATIC_LENGTH: Option<usize> = {
                let mut answer = Some(0);
                #(answer = match (answer, #dummy_types::STATIC_LENGTH) {
                    (_, None) | (None, _) => None,
                    (Some(x), Some(y)) => Some(x+y),
                };)*
                answer
            };

            fn from_abi(data: &[u8]) -> Result<Self, ABIDecodeError> {
                let mut pointer = data.iter();

                Ok(Self {
                    #(#field_idents: read_abi_list(data, &mut pointer)?,)*
                })
            }

            fn to_abi(&self) -> LinkedBytes {
                let heads_length: usize = 0 #( + #dummy_types::STATIC_LENGTH.unwrap_or(32))*;
                let mut recorder = ABIListWriter::with_heads_length(heads_length);
                #(recorder.write_down(&self.#field_idents);)*
                recorder.into_linked_bytes()
            }

            fn to_packed_abi(&self) -> LinkedBytes {
                let mut recorder = LinkedBytes::new();
                #(recorder.append(&mut self.#field_idents.to_packed_abi());)*
                recorder
            }
        }
    };

    let answer = quote! {
        #[allow(non_upper_case_globals, unused_attributes, unused_qualifications)]
        const #dummy_const: () = {
            #env

            #impl_abi
        };
    };

    answer.into()
}
