fn main() {
    // 设置链接库搜索路径
    println!("cargo:rustc-link-search=native=../c_capture/build/lib");
    
    // 链接 capture 库
    println!("cargo:rustc-link-lib=dylib=capture");
    
    // 重新运行构建脚本的条件
    println!("cargo:rerun-if-changed=../c_capture/include");
    println!("cargo:rerun-if-changed=../c_capture/src");
} 