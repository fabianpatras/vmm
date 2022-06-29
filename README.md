# vmm
A proof of concept Rust-based Virtual Machine Monitor for MacOS

This is the source code for my bachelor thesis.

# Description

It is a minimal VMM that can boot a linux kernel to the point where `init` process would start. It does not go beyond that with the current implementation.

Its purpose is to try out the [rust-vmm](https://github.com/rust-vmm) crates in a MacOS environment using [hv create](https://crates.io/crates/hv) as bindings for working with [Hypervisor.Framework](https://developer.apple.com/documentation/hypervisor?language=objc) .

It must be run on an Intel MacOS 10.15+ that supports hypervisor framework. 



# Usage

By running `cargo run` the vmm will start a VM with 1 vCPU (it does not support more), 4GB guest memory. The VM will load the kernel located at `resources/kernel/ootb_kernel` build with `rust-vmm/vmm-reference`'s [script](https://github.com/rust-vmm/vmm-reference/tree/85bcd6e1d73248c775904561c694e593026b53c6/resources/kernel)
