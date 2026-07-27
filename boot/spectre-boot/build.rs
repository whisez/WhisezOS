fn main() {
    // The halt path used to be hand-written assembly in a separate object,
    // built here with `cc`. It is now a `core::arch::asm!` block in the loader
    // itself: it is three instructions, and requiring a C toolchain on every
    // developer's machine to assemble `cli; hlt; jmp` was a build dependency
    // that bought nothing.
    println!("cargo:rerun-if-changed=build.rs");
}
