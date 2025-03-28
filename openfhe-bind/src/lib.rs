#![deny(missing_docs)]
#![deny(rustdoc::broken_intra_doc_links)]
#![warn(missing_docs)]

#[cfg(not(target_arch = "wasm32"))]
extern crate link_cplusplus;

#[allow(non_camel_case_types)]
#[allow(unused)]
mod bindgen {
	use std::os::raw::c_long;

	include!(concat!(env!("OUT_DIR"), "/bindings.rs"));
}