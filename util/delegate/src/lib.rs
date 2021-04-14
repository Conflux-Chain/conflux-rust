//! This crate removes some boilerplate for structs that simply delegate
//! some of their methods to one or more of their fields.
//!
//! It gives you the `delegate!` macro, which delegates method calls to selected
//! expressions (usually inner fields).
//!
//! ## Features:
//! - Delegate to a method with a different name
//! ```rust
//! use delegate::delegate;
//!
//! struct Stack {
//!     inner: Vec<u32>,
//! }
//! impl Stack {
//!     delegate! {
//!         to self.inner {
//!             #[call(push)]
//!             pub fn add(&mut self, value: u32);
//!         }
//!     }
//! }
//! ```
//! - Use an arbitrary inner field expression
//! ```rust
//! use delegate::delegate;
//! use std::{cell::RefCell, ops::Deref, rc::Rc};
//!
//! struct Wrapper {
//!     inner: Rc<RefCell<Vec<u32>>>,
//! }
//! impl Wrapper {
//!     delegate! {
//!         to self.inner.deref().borrow_mut() {
//!             pub fn push(&mut self, val: u32);
//!         }
//!     }
//! }
//! ```
//! - Change the return type of the delegated method using a `From` impl or omit
//!   it altogether
//! ```rust
//! use delegate::delegate;
//! use std::convert as delegate_convert;
//!
//! struct Inner;
//! impl Inner {
//!     pub fn method(&self, num: u32) -> u32 { num }
//! }
//! struct Wrapper {
//!     inner: Inner,
//! }
//! impl Wrapper {
//!     delegate! {
//!         to self.inner {
//!             // calls method, converts result to u64
//!             #[into]
//!             pub fn method(&self, num: u32) -> u64;
//!
//!             // calls method, returns ()
//!             #[call(method)]
//!             pub fn method_noreturn(&self, num: u32);
//!         }
//!     }
//! }
//! ```
//! - Delegate to multiple fields
//! ```rust
//! use delegate::delegate;
//!
//! struct MultiStack {
//!     left: Vec<u32>,
//!     right: Vec<u32>,
//! }
//! impl MultiStack {
//!     delegate! {
//!         to self.left {
//!             ///! Push an item to the top of the left stack
//!             #[call(push)]
//!             pub fn push_left(&mut self, value: u32);
//!         }
//!         to self.right {
//!             ///! Push an item to the top of the right stack
//!             #[call(push)]
//!             pub fn push_right(&mut self, value: u32);
//!         }
//!     }
//! }
//! ```
//! - Delegation of generic methods
//! - Inserts `#[inline(always)]` automatically (unless you specify `#[inline]`
//!   manually on the method)

extern crate proc_macro;

use proc_macro::TokenStream;
use proc_macro2::TokenStream as TokenStream2;
use quote::quote;
use std::collections::HashMap;
use syn::{self, parse::ParseStream, spanned::Spanned, Error};

mod kw {
    syn::custom_keyword!(to);
    syn::custom_keyword!(target);
}

struct DelegatedMethod {
    method: syn::TraitItemMethod,
    attributes: Vec<syn::Attribute>,
    visibility: syn::Visibility,
}

impl syn::parse::Parse for DelegatedMethod {
    fn parse(input: ParseStream) -> Result<Self, Error> {
        let attributes = input.call(syn::Attribute::parse_outer)?;
        let visibility = input.call(syn::Visibility::parse)?;

        Ok(DelegatedMethod {
            method: input.parse()?,
            attributes,
            visibility,
        })
    }
}

struct DelegatedSegment {
    delegator: syn::Expr,
    methods: Vec<DelegatedMethod>,
}

impl syn::parse::Parse for DelegatedSegment {
    fn parse(input: ParseStream) -> Result<Self, Error> {
        if let Ok(keyword) = input.parse::<kw::target>() {
            return Err(Error::new(keyword.span(), "You are using the old `target` expression, which is deprecated. Please replace `target` with `to`."));
        } else {
            input.parse::<kw::to>()?;
        }

        input.parse::<syn::Expr>().and_then(|delegator| {
            let delegator = match delegator {
                syn::Expr::Field(_) => delegator,
                syn::Expr::MethodCall(_) => delegator,
                syn::Expr::Call(_) => delegator,
                syn::Expr::Group(group) => *group.expr,
                _ => panic!("Use a field expression to select delegator (e.g. self.inner)"),
            };

            let content;
            syn::braced!(content in input);

            let mut methods = vec![];
            while !content.is_empty() {
                methods.push(content.parse::<DelegatedMethod>().unwrap());
            }

            Ok(DelegatedSegment { delegator, methods })
        })
    }
}

struct DelegationBlock {
    segments: Vec<DelegatedSegment>,
}

impl syn::parse::Parse for DelegationBlock {
    fn parse(input: ParseStream) -> Result<Self, Error> {
        let mut segments = vec![];
        while !input.is_empty() {
            segments.push(input.parse()?);
        }

        Ok(DelegationBlock { segments })
    }
}

struct CallMethodAttribute {
    name: syn::Ident,
}

impl syn::parse::Parse for CallMethodAttribute {
    fn parse(input: ParseStream) -> Result<Self, Error> {
        let content;
        syn::parenthesized!(content in input);
        Ok(CallMethodAttribute {
            name: content.parse()?,
        })
    }
}

/// Iterates through the attributes of a method and filters special attributes.
/// call => sets the name of the target method to call
/// into => generates a `into()` call for the returned value
///
/// Returns tuple (blackbox attributes, name, into)
fn parse_attributes<'a>(
    attrs: &'a [syn::Attribute], method: &syn::TraitItemMethod,
) -> (Vec<&'a syn::Attribute>, Option<syn::Ident>, bool) {
    let mut name: Option<syn::Ident> = None;
    let mut into: Option<bool> = None;
    let mut map: HashMap<&str, Box<dyn FnMut(TokenStream2) -> ()>> =
        Default::default();
    map.insert(
        "call",
        Box::new(|stream| {
            let target = syn::parse2::<CallMethodAttribute>(stream).unwrap();
            if name.is_some() {
                panic!(
                    "Multiple call attributes specified for {}",
                    method.sig.ident
                )
            }
            name = Some(target.name.clone());
        }),
    );
    map.insert(
        "target_method",
        Box::new(|_| {
            panic!("You are using the old `target_method` attribute, which is deprecated. Please replace `target_method` with `call`.");
        }),
    );
    map.insert(
        "into",
        Box::new(|_| {
            if into.is_some() {
                panic!(
                    "Multiple into attributes specified for {}",
                    method.sig.ident
                )
            }
            into = Some(true);
        }),
    );
    let attrs: Vec<&syn::Attribute> = attrs
        .iter()
        .filter(|attr| {
            if let syn::AttrStyle::Outer = attr.style {
                for (ident, callback) in map.iter_mut() {
                    if attr.path.is_ident(ident) {
                        callback(attr.tokens.clone());
                        return false;
                    }
                }
            }

            true
        })
        .collect();

    drop(map);
    (attrs, name, into.unwrap_or(true))
}

/// Returns true if there are any `inline` attributes in the input.
fn has_inline_attribute(attrs: &[&syn::Attribute]) -> bool {
    attrs.iter().any(|attr| {
        if let syn::AttrStyle::Outer = attr.style {
            attr.path.is_ident("inline")
        } else {
            false
        }
    })
}

#[proc_macro]
pub fn delegate(tokens: TokenStream) -> TokenStream {
    let block: DelegationBlock = syn::parse_macro_input!(tokens);
    let sections = block.segments.iter().map(|delegator| {
        let delegator_attribute = &delegator.delegator;
        let functions = delegator.methods.iter().map(|method| {
            let input = &method.method;
            let signature = &input.sig;
            let inputs = &input.sig.inputs;

            let (attrs, name, into) = parse_attributes(&method.attributes, &input);

            if input.default.is_some() {
                panic!(
                    "Do not include implementation of delegated functions ({})",
                    signature.ident
                );
            }
            let args: Vec<syn::Ident> = inputs
                .iter()
                .filter_map(|i| match i {
                    syn::FnArg::Typed(typed) => match &*typed.pat {
                        syn::Pat::Ident(ident) => {
                            if ident.ident == "self" {
                                None
                            } else {
                                Some(ident.ident.clone())
                            }
                        }
                        _ => panic!(
                            "You have to use simple identifiers for delegated method parameters ({})",
                            input.sig.ident
                        ),
                    },
                    _ => None,
                })
                .collect();

            let name = match &name {
                Some(n) => &n,
                None => &input.sig.ident
            };
            let inline = if has_inline_attribute(&attrs) {
                quote!()
            } else {
                quote! { #[inline(always)] }
            };
            let visibility = &method.visibility;

            let body = quote::quote! { #delegator_attribute.#name(#(#args),*) };
            let span = input.span();
            let body = match &signature.output {
                syn::ReturnType::Default => quote::quote! { #body; },
                syn::ReturnType::Type(_, ret_type) => {
                    if into {
                        quote::quote! { delegate_convert::Into::<#ret_type>::into(#body) }
                    }
                    else {
                        body
                    }
                }
            };

            quote::quote_spanned! {span=>
                #(#attrs)*
                #inline
                #visibility #signature {
                    #body
                }
            }
        });

        quote! { #(#functions)* }
    });

    let result = quote! {
        #(#sections)*
    };
    result.into()
}
