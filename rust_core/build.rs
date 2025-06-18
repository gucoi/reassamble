use std::env;
use std::path::PathBuf;

fn main() {
    // 告诉 cargo 如果 C 代码改变就重新运行
    println!("cargo:rerun-if-changed=../c_capture/src");
    println!("cargo:rerun-if-changed=../c_capture/include");

    // 获取输出目录
    let out_dir = PathBuf::from(env::var("OUT_DIR").unwrap());

    // 编译 C 代码
    cc::Build::new()
        .include("../c_capture/include")
        .file("../c_capture/src/capture.c")
        .file("../c_capture/src/backends/pcap_backend.c")
        .compile("c_capture");

    // 生成 Rust 绑定
    let bindings = bindgen::Builder::default()
        .header("../c_capture/include/capture.h")
        .header("../c_capture/include/capture_types.h")
        .header("../c_capture/include/backends/capture_backend.h")
        .header("../c_capture/include/backends/pcap_backend.h")
        .allowlist_type("capture_.*")
        .allowlist_function("capture_.*")
        .allowlist_var("CAPTURE_.*")
        .clang_arg("-I../c_capture/include")
        .parse_callbacks(Box::new(bindgen::CargoCallbacks::new()))
        .generate()
        .expect("无法生成绑定");

    // 写入绑定文件
    bindings
        .write_to_file(out_dir.join("bindings.rs"))
        .expect("无法写入绑定文件");

    // 链接 libcapture.so
    println!("cargo:rustc-link-lib=dylib=capture");
    println!("cargo:rustc-link-search=native={}", out_dir.parent().unwrap().parent().unwrap().parent().unwrap().join("c_capture/build/lib").display());
    
    // 链接 libpcap
    println!("cargo:rustc-link-lib=dylib=pcap");
} 