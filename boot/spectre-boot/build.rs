fn main() {
    if std::env::var_os("CARGO_FEATURE_PRODUCTION_LOADER").is_some() {
        // The halt path must be assembly: it runs after we have deliberately
        // invalidated the Rust runtime's assumptions (allocator torn down,
        // boot services exited, possibly with a partial page table).
        cc::Build::new()
            .file("src/arch/x86_64/halt.S")
            .flag("-ffreestanding")
            .compile("spectre_halt");
    }

    println!("cargo:rerun-if-changed=src/arch/x86_64/halt.S");
}
