fn main() {
    // Cargo does not know the linker script is an input. Without this, editing
    // `kernel.ld` — changing the load address, adding a section symbol — leaves
    // the previous image in place and the next boot fails against the old
    // layout, which looks exactly like the edit not working.
    println!("cargo:rerun-if-changed=kernel.ld");
    println!("cargo:rerun-if-changed=build.rs");
}
