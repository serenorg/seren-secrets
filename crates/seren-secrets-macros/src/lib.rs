use proc_macro::TokenStream;
use proc_macro2::Span;
use quote::quote;
use syn::{DeriveInput, LitStr, parse_macro_input};

/// Implements `Debug` for the annotated type by printing
/// `TypeName("<redacted>")` regardless of field values, so sensitive structs
/// can participate in `{:?}` formatting without leaking plaintext.
///
/// Applies to structs and enums. Generic parameters are forwarded to the
/// `impl` block unchanged and no `Debug` bounds are added for them, which is
/// correct because the implementation never inspects field values.
#[proc_macro_derive(RedactedDebug)]
pub fn derive_redacted_debug(input: TokenStream) -> TokenStream {
    let input = parse_macro_input!(input as DeriveInput);
    let ident = &input.ident;
    let name_lit = LitStr::new(&ident.to_string(), Span::call_site());
    let (impl_generics, ty_generics, where_clause) = input.generics.split_for_impl();

    TokenStream::from(quote! {
        impl #impl_generics ::std::fmt::Debug for #ident #ty_generics #where_clause {
            fn fmt(&self, f: &mut ::std::fmt::Formatter<'_>) -> ::std::fmt::Result {
                f.debug_tuple(#name_lit).field(&"<redacted>").finish()
            }
        }
    })
}
