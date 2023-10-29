
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
Kryptor offers following key features:

- **Encode/Decode**: Kryptor supports encoding and decoding of various formats, including base64, base32, ROT13, A1Z26, and hexadecimal (hex).
- **Hashing**: You can hash strings using popular algorithms like SHA256 and SHA512.
- **Hexdump**: Kryptor provides the ability to create hexdumps of files.

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
## Examples

Here are some examples of how to use Kryptor:

- encode the context of a file in base64 and save it to a new file:
```
$ kryptor --encode base64 file.txt > output.txt
```
- Hash the strings in a file using SHA256 and display the result:
```
$ kryptor --hash SHA256 file.txt
```
- Create a hexdump of a file:
```
$ kryptor -p file.txt
```
