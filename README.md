```

██████  ██    ██ ███████ ████████       ██████  ██████   ██████   ██████ ██   ██  ██████  ██      ██       ██████  ██     ██ 
██   ██ ██    ██ ██         ██          ██   ██ ██   ██ ██    ██ ██      ██   ██ ██    ██ ██      ██      ██    ██ ██     ██ 
██████  ██    ██ ███████    ██    █████ ██████  ██████  ██    ██ ██      ███████ ██    ██ ██      ██      ██    ██ ██  █  ██ 
██   ██ ██    ██      ██    ██          ██      ██   ██ ██    ██ ██      ██   ██ ██    ██ ██      ██      ██    ██ ██ ███ ██ 
██   ██  ██████  ███████    ██          ██      ██   ██  ██████   ██████ ██   ██  ██████  ███████ ███████  ██████   ███ ███  
                                                                                                                             


                                 Process Hollowing in Rust (x86 / x64)         
                                    Process Executable Replacement
```
<p align="center">
    <img src="https://img.shields.io/badge/language-Rust-orange.svg?style=for-the-badge&logo=rust" alt="Rust">
    <img src="https://img.shields.io/badge/platform-Windows-0078d7.svg?style=for-the-badge&logo=windows" alt="Windows">
    <img src="https://img.shields.io/badge/arch-x64-green.svg?style=for-the-badge&logo=processor" alt="x64">
</p>

## :open_book: Project Overview :

A robust process hollowing implementation written in Rust for Windows x64 systems. This loader can inject into both x86 and x64 system processes, defaulting to Explorer as the target process.

The loader is able to inject PE image with and witout relocation table, if there is no relocation table the loader try to allocate memory at the preferred image base address.

### :sparkles: Features :

- x64 executable supporting both x86 and x64 target processes
- PE image injection with and without relocation tables
- Automatic preferred base address allocation attempt for images without relocation
- Compatible with Windows system processes
- Robust error handling and logging

## :rocket: Getting Started :

> **Warning** <br>
> This is a **x64 executable**, you can't compile this project in x86, this loader is made to inject into x86 and x64 processes.
> You can easily make a x86 process hollowing program based on this repository.

### :gear: Build :

To build the project, you need to have Rust installed on your system. You can install Rust from [here](https://www.rust-lang.org/tools/install). Once you have Rust installed, you can build the project using the following command :

```shell
cargo build --release
```

This will create a `Process-Hollowing.exe` executable in the `target/release` directory.


## 🧪 Usage :

### How to use the program :

Use it in the command line :

```shell
Process-Hollowing.exe <source image>
```
This can be integrated with reading the file directly in the code.

## References :

https://github.com/adamhlt/Process-Hollowing
https://github.com/m0n0ph1/Process-Hollowing
https://chuongdong.com/reverse%20engineering/2020/08/15/PE-Parser/
https://chuongdong.com/malware%20development/2020/08/19/Process-Hollowing/

## :page_facing_up: License :

This project is licensed under the MIT License - see the [LICENSE](LICENSE) file for details.
