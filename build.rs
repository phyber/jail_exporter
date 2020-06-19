use rustc_version::version;

fn main() {
    let v = version().unwrap();

    println!("cargo:rustc-env=RUSTC_VERSION={}", v);
}
