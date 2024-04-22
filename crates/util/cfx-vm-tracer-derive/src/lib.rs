extern crate proc_macro;
use proc_macro::TokenStream;
use quote::quote;
use syn::{Data, DataStruct, DeriveInput, Error, Fields, Ident};

type Result<T> = std::result::Result<T, Error>;

macro_rules! unwrap_or_compile_error {
    ($e:expr) => {
        match $e {
            Ok(x) => x,
            Err(e) => return e.into_compile_error().into(),
        }
    };
}

#[proc_macro_derive(AsTracer, attributes(skip_tracer))]
pub fn generate_as_tracer_function(input: TokenStream) -> TokenStream {
    let input = syn::parse_macro_input!(input as DeriveInput);
    let name = &input.ident;

    let data = unwrap_or_compile_error!(get_struct_data(&input));
    let skipped_fields = unwrap_or_compile_error!(check_all_fields(data));
    let field_names = unwrap_or_compile_error!(get_field_names(data, name));
    unwrap_or_compile_error!(check_num_fields(&field_names, name, 10));

    let mut match_arms = Vec::new();
    let match_more_fields = if skipped_fields {
        quote!(, ..)
    } else {
        quote!()
    };

    for mask in 0..(1 << field_names.len()) {
        let mut this_combination = Vec::new();
        let mut tuple_elements = Vec::new();
        for (index, field) in field_names.iter().enumerate() {
            if (mask >> index) & 1 == 1 {
                this_combination.push(quote! { #field: Some(#field) });
                tuple_elements.push(quote! { #field });
            } else {
                this_combination.push(quote! { #field: None });
            }
        }
        let match_arm = match tuple_elements.len() {
            0 => quote! {
                #name {#(#this_combination),* #match_more_fields} => Box::new(()) // as Box<dyn MyTrait>
            },
            1 => quote! {
                #name {#(#this_combination),* #match_more_fields} => Box::new(#(#tuple_elements),*) // as Box<dyn MyTrait>
            },
            _ => quote! {
                #name {#(#this_combination),* #match_more_fields} => Box::new((#(#tuple_elements),*)) // as Box<dyn MyTrait>
            },
        };
        match_arms.push(match_arm);
    }

    let expanded = quote! {
        impl AsTracer for #name {
            fn as_tracer<'a>(&'a mut self) -> Box<dyn 'a + TracerTrait> {
                match self {
                    #(#match_arms,)*
                }
            }
        }
    };

    expanded.into()
}

#[proc_macro_derive(DrainTrace)]
pub fn generate_drain_trace_function(input: TokenStream) -> TokenStream {
    let input = syn::parse_macro_input!(input as DeriveInput);
    let name = &input.ident;

    let data = unwrap_or_compile_error!(get_struct_data(&input));
    let field_names = unwrap_or_compile_error!(get_field_names(data, name));

    let drain_statements = field_names.iter().map(|field| {
        quote! { self.#field.drain_trace(map); }
    });

    let expanded = quote! {
        impl DrainTrace for #name {
            fn drain_trace(self, map: &mut typemap::ShareDebugMap) {
                #(#drain_statements)*
            }
        }
    };

    expanded.into()
}

fn get_struct_data(input: &DeriveInput) -> Result<&DataStruct> {
    match &input.data {
        Data::Struct(data) => Ok(data),
        _ => Err(Error::new_spanned(&input.ident, "Only struct is supported")),
    }
}

fn check_all_fields(data: &DataStruct) -> Result<bool> {
    let mut type_error = vec![];
    let mut skipped_field = false;
    for field in &data.fields {
        if field
            .attrs
            .iter()
            .any(|attr| attr.path.is_ident("skip_tracer"))
        {
            skipped_field = true;
            continue;
        }

        if let syn::Type::Path(type_path) = &field.ty {
            if type_path
                .path
                .segments
                .last()
                .map_or(false, |seg| seg.ident == "Option")
            {
                continue;
            }
        }
        type_error.push(Error::new_spanned(
            &field.ty,
            "All fields must be of type Option",
        ));
    }
    if !type_error.is_empty() {
        let mut type_error_iter = type_error.into_iter();
        let mut error = type_error_iter.next().unwrap();
        error.extend(type_error_iter);
        Err(error)
    } else {
        Ok(skipped_field)
    }
}

fn get_field_names<'a>(
    data: &'a DataStruct, name: &Ident,
) -> Result<Vec<&'a Option<Ident>>> {
    match &data.fields {
        Fields::Named(fields) => Ok(fields
            .named
            .iter()
            .filter(|f| {
                !f.attrs.iter().any(|attr| attr.path.is_ident("skip_tracer"))
            })
            .map(|f| &f.ident)
            .collect::<Vec<_>>()),
        _ => Err(Error::new_spanned(&name, "Only named struct is supported")),
    }
}

fn check_num_fields(
    field_names: &Vec<&Option<Ident>>, name: &Ident, max_entries: usize,
) -> Result<()> {
    if field_names.len() > max_entries {
        Err(Error::new_spanned(
            name,
            "Too many fields in the struct! Limit is 10.",
        ))
    } else {
        Ok(())
    }
}
