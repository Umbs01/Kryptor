
# Kryptor

A simple command line cryptography tool made in Rust




## Installations

required [cargo](https://www.rust-lang.org/tools/install) to install

then in your CLI
- `$ cargo install kryptor`



## Features

- Encode/Decode formats such as base64 ROT13 A1Z26 hex

- hashing

- hexdump


## Usage/Examples

file.txt

`hello world`

```
$ kryptor --encode base64 file.txt > output.txt
```

output.txt

`aGVsbG8gd29ybGQh`
