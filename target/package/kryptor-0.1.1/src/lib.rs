use clap::{App, Arg};
use std::error::Error;
use std::fs::File;
use std::io::{self, BufRead, BufReader};
use base32::{Alphabet, encode, decode};
use sha2::{Digest, Sha256, Sha512};

type MyResult<T> = Result<T, Box<dyn Error>>;

#[derive(Debug)]
pub struct Config {
    files: Vec<String>,
    encode_type: Option<String>,
    decode_type: Option<String>,
    hash: Option<String>,
}

pub fn get_args() -> MyResult<Config> {
    let matches = App::new("Kryptor")
        .version("0.1.0")
        .about("A simple command-line cryptography tool")
        .arg(
            Arg::with_name("files")
                .value_name("FILE")
                .help("Input file(s)")
                .multiple(true)
                .default_value("-"),
        )
        .arg(
            Arg::with_name("decode")
                .short("d")
                .long("decode")
                .takes_value(true)
                .possible_values(&["base32","base64","ROT13","A1Z26"])
                .conflicts_with("encode")
                .help("decode text to the format specified"),
        )
        .arg(
            Arg::with_name("encode")
                .short("e")
                .long("encode")
                .takes_value(true)
                .possible_values(&["base32","base64","ROT13","A1Z26"])
                .conflicts_with("decode")
                .help("encode to the format specified"),
        )
        .arg(
            Arg::with_name("hash")
                .short("s")
                .long("hash")
                .takes_value(true)
                .possible_values(&["SHA256","SHA512"])
                .help("hash the strings in the file")
        )
        .get_matches();
    
    let files: Vec<String> = matches
        .values_of("files")
        .unwrap_or_default()
        .map(String::from)
        .collect();
    
    let encode_type = matches.value_of("encode").map(String::from);
    let decode_type = matches.value_of("decode").map(String::from);
    let hash = matches.value_of("hash").map(String::from);

    Ok(Config { files, encode_type, decode_type, hash })
} 

// decode-encodings--------------------------------------------
fn base64_encode(input: &str) -> String {
    base64::encode(input)
}

fn base64_decode(input: &str) -> String {
    match base64::decode(input) {
        Ok(decoded) => String::from_utf8_lossy(&decoded).to_string(),
        Err(_) => {
            eprintln!("Error decoding base64.");
            input.to_string()
        }
    }
}

fn base32_encode(input: &str) -> String {
    let encoded = encode(Alphabet::RFC4648 { padding: false }, input.as_bytes());
    encoded
}

fn base32_decode(input: &str) -> Result<String, String> {
    match decode(Alphabet::RFC4648 { padding: false }, input) {
        Some(decoded_data) => {
            let decoded_string = String::from_utf8_lossy(&decoded_data).to_string();
            Ok(decoded_string)
        }
        None => {
            Err("Error decoding Base32".to_string())
        }
    }
}

// for handling base32_decode()
fn decode_base32_handler(input: &str) -> String {
    match base32_decode(input) {
        Ok(decoded_string) => decoded_string,
        Err(error) => {
            eprintln!("Error: {}", error); 
            String::from("Decoding error") 
        }
    }
}

// ciphering-------------------------------------------------
fn rot13_char(c: char) -> char {
    match c {
        'a'..='z' => ((((c as u8 - b'a') + 13) % 26) + b'a') as char,
        'A'..='Z' => ((((c as u8 - b'A') + 13) % 26) + b'A') as char,
        _ => c,
    }
}

// for handling rot13_char()
fn to_rot13(input: &str) -> String {
    format!("{}",input.chars().map(rot13_char).collect::<String>())
}

fn a1z26_encode(input: &str) -> String {
    let mut encoded_message = String::new();

    for character in input.chars() {
        if character.is_alphabetic() {
            let char_upper = character.to_ascii_uppercase();
            let char_code = (char_upper as u8 - b'A' + 1).to_string();
            encoded_message.push_str(&char_code);
            encoded_message.push('-');
        } else {
            encoded_message.push(character);
        }
    }
    if encoded_message.ends_with('-') {
        encoded_message.pop();
    }
    encoded_message
}

fn a1z26_decode(input: &str) -> String {
    let mut decoded_message = String::new();
    let mut current_number = String::new();

    for character in input.chars() {
        if character == '-' {
            if !current_number.is_empty() {
                if let Ok(number) = current_number.parse::<usize>() {
                    if number >= 1 && number <= 26 {
                        let decoded_char = (b'A' + (number - 1) as u8) as char;
                        decoded_message.push(decoded_char);
                    } else {
                        // Invalid code
                        decoded_message.push_str(&current_number);
                    }
                } else {
                    // Failed to parse as a number
                    decoded_message.push_str(&current_number);
                }
                current_number.clear();
            }
        } else if character.is_digit(10) {
            current_number.push(character);
        } else {
            // If the character is not a digit or hyphen, add it
            decoded_message.push(character);
        }
    }

    // Handle the last number
    if !current_number.is_empty() {
        if let Ok(number) = current_number.parse::<usize>() {
            if number >= 1 && number <= 26 {
                let decoded_char = (b'A' + (number - 1) as u8) as char;
                decoded_message.push(decoded_char);
            } else {
                decoded_message.push_str(&current_number);
            }
        } else {
            decoded_message.push_str(&current_number);
        }
    }

    decoded_message
}

// hashing-----------------------------------------------------
fn sha256hash(input: &str) -> String {
    let mut hasher = Sha256::new();

    // Update the hasher with the input bytes
    hasher.update(input.as_bytes());

    // Calculate the hash and convert it to a hex string
    let result = hasher.finalize();
    let hash_hex = result.iter().map(|byte| format!("{:02x}", byte)).collect::<String>();

    hash_hex
}

fn sha512hash(input: &str) -> String {
    let mut hasher = Sha512::new();

    hasher.update(input.as_bytes());

    let result = hasher.finalize();
    let hash_hex = result.iter().map(|byte| format!("{:02x}", byte)).collect::<String>();

    hash_hex
}

// run function-------------------------------------------------

pub fn run(config: Config) -> MyResult<()> {
    for filename in &config.files {
        match open(&filename) {
            Err(err) => eprintln!("{}: {}", filename, err),
            Ok(file) => {
                // iterate through the lines in the file(s)
                for line_result in file.lines() {
                    let line = line_result?;
                    let result = 

                    // for --encode flag
                    if config.encode_type.is_some() {

                        if let Some(encoding) = &config.encode_type {
                            match encoding.as_str() {
                                "base64" => base64_encode(&line),
                                "ROT13" => to_rot13(&line),
                                "base32" => base32_encode(&line),
                                "A1Z26" => a1z26_encode(&line),
                                _ => line.to_string(),
                            }
                        } else {
                            eprintln!("Encoding type not specified.");
                            return Ok(());
                        }
                    
                    // for --decode flag
                    } else if config.decode_type.is_some() {
                        if let Some(decoding) = &config.decode_type {
                            match decoding.as_str() {
                                "base64" => base64_decode(&line),
                                "ROT13" => to_rot13(&line),
                                "base32" => decode_base32_handler(&line),
                                "A1Z26" => a1z26_decode(&line),
                                _ => line.to_string(),
                            }
                        } else {
                            eprintln!("Decoding type not specified.");
                            return Ok(());
                        }
                    } else if config.hash.is_some() {
                        if let Some(hashing) = &config.hash {
                            match hashing.as_str() {
                                "SHA256" => sha256hash(&line),
                                "SHA512" => sha512hash(&line),
                                _ => line.to_string(),
                            }
                        } else {
                            eprintln!("Hashing format not specified.");
                            return Ok(());            
                        }

                    } else {
                        eprintln!("Either encoding or decoding must be specified.");
                        return Ok(());
                    };
                    println!("{}",result);
                }
            }
        }
    }
    Ok(())
}

// open function-----------------------------------------------------
fn open(filename: &str) -> MyResult<Box<dyn BufRead>> {
    match filename {
        "-" => Ok(Box::new( BufReader::new(io::stdin()))),
        _ => Ok(Box::new( BufReader::new(File::open(filename)?))),
    }
}

