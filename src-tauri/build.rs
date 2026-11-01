fn main() {
    if std::env::var("CARGO_CFG_TARGET_OS").as_deref() == Ok("linux") {
        println!("cargo:rerun-if-changed=../headerUndUtil/sha.c");
        println!("cargo:rerun-if-changed=../headerUndUtil/sha.h");
        cc::Build::new()
            .file("../headerUndUtil/sha.c")
            .flag_if_supported("-std=gnu11")
            .compile("annakav_sha");
    }
    // Embed the repository database so installed apps never depend on the CWD.
    let database = std::path::Path::new("../db");
    println!("cargo:rerun-if-changed={}", database.display());
    let mut entries: Vec<_> = std::fs::read_dir(database)
        .expect("Cannot read bundled signature database")
        .map(|entry| entry.expect("Cannot read database entry").path())
        .filter(|path| path.is_file())
        .collect();
    entries.sort();
    let mut generated = String::from("const BUNDLED_SIGNATURES: &[(&str, &[u8])] = &[\n");
    for path in entries {
        println!("cargo:rerun-if-changed={}", path.display());
        let name = path
            .file_name()
            .unwrap()
            .to_str()
            .expect("Invalid signature filename");
        let bytes = std::fs::read(&path).expect("Cannot read bundled signature");
        generated.push_str(&format!("({name:?}, &{bytes:?}),\n"));
    }
    generated.push_str("];\n");
    let output = std::path::PathBuf::from(std::env::var_os("OUT_DIR").unwrap());
    std::fs::write(output.join("bundled_signatures.rs"), generated).unwrap();
    tauri_build::build()
}
