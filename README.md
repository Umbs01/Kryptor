
# Kryptor

## Description

A simple command line cryptography tool made in Rust




## Installations

required [cargo](https://www.rust-lang.org/tools/install) to install

then in your CLI
```
$ cargo install kryptor
```


## Features

- Encode/Decode formats such as base64 base32 ROT13 A1Z26 hex

- hashing

- hexdump


## Usage/Examples

```
$ kryptor -h       
Kryptor 0.1.3
A simple command-line cryptography tool

USAGE:
    kryptor [FLAGS] [OPTIONS] [FILE]...

FLAGS:
    -h, --help       Prints help information
    -p, --hexdump    hexdump the file specified
    -V, --version    Prints version information

OPTIONS:
    -d, --decode <decode>    decode text to the format specified [possible values: base32, base64, hex, ROT13, A1Z26]
    -e, --encode <encode>    encode to the format specified [possible values: base32, base64, hex, ROT13, A1Z26]
    -s, --hash <hash>        hash the strings in the file [possible values: SHA256, SHA512]

ARGS:
    <FILE>...    Input file(s) or leave blank to recieve input from stdin [default: -]
```

file.txt

`hello world`

```
$ kryptor --encode base64 file.txt > output.txt
```

output.txt

`aGVsbG8gd29ybGQh`
