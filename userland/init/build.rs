fn main() {
    // Same trap as the kernel's: cargo does not know the linker script is an
    // input, so editing `init.ld` leaves the previous binary in place and the
    // next boot fails against the old layout — which looks exactly like the
    // edit not working.
    println!("cargo:rerun-if-changed=init.ld");
    println!("cargo:rerun-if-changed=build.rs");
}
