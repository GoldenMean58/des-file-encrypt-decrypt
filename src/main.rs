#[macro_use] extern crate hex_literal;
extern crate clap;
extern crate des;
extern crate block_modes;
use clap::{Arg, App, SubCommand};
use std::io;
use std::io::prelude::*;
use std::io::BufWriter;
use std::fs::File;
use std::sync::Arc;
use tokio::task;

use block_modes::{BlockMode, Ecb};
use block_modes::block_padding::Pkcs7;
use des::Des;
type DesEcb = Ecb<Des, Pkcs7>;

const BLOCK_SIZE: usize = 8;

const IV: [u8; 8] = hex!("0000000000000000");

fn read_bytes(file_path: String) -> io::Result<Vec<u8>> {
    let mut f = File::open(file_path)?;
    let mut bytes : Vec<u8> = Vec::new();
    f.read_to_end(&mut bytes)?;
    Ok(bytes)
}

fn write_bytes(file_path: String, bytes: &[u8]) -> io::Result<()> {
    let f = File::create(file_path)?;
    let mut writer = BufWriter::new(f);
    writer.write(bytes)?;
    Ok(())
}

fn encrypt(index: usize, data: Arc<Vec<u8>>, key: Vec<u8>, thread: usize) -> Vec<u8> {
    let cipher = DesEcb::new_var(&key, &IV).unwrap();
    let data_full_len = (*data).len();
    let data_len = data_full_len / thread / BLOCK_SIZE * BLOCK_SIZE;
    let mut remainder = 0;
    if index != thread - 1 {
        if data_len == 0 {
            return vec![];
        }
    }else{
        remainder = data_full_len - thread * data_len;
    }
    // println!("{} .. {}", data_len*index, data_len*(index+1)+remainder);
    let blocks = &(*data)[data_len*index..data_len*(index+1)+remainder];
    let result = cipher.encrypt_vec(blocks);
    result
}

fn decrypt(index: usize, data: Arc<Vec<u8>>, key: Vec<u8>, thread: usize) -> Vec<u8> {
    let cipher = DesEcb::new_var(&key, &IV).unwrap();
    let data_full_len = (*data).len();
    let data_len = data_full_len / thread / BLOCK_SIZE * BLOCK_SIZE;
    let mut remainder = 0;
    if index != thread - 1 {
        if data_len == 0 {
            return vec![];
        }
    }else{
        remainder = data_full_len - thread * data_len;
    }
    // println!("{} .. {}", data_len*index, data_len*(index+1)+remainder);
    let blocks = &(*data)[data_len*index..data_len*(index+1)+remainder];
    let result = cipher.decrypt_vec(blocks).unwrap();
    result
}

async fn encrypt_file(in_file_path: String, out_file_path: String, key: Vec<u8>, thread: usize) {
    let ori_file_data = Arc::new(read_bytes(in_file_path).unwrap());
    let mut result : Vec<u8> = Vec::new();
    let mut t: Vec<task::JoinHandle<_>> = Vec::new();
    for i in 0..thread {
        let data = ori_file_data.clone();
        let key = key.clone();
        t.push(task::spawn_blocking(move || {encrypt(i, data, key, thread)}));
    }
    let mut rets : Vec<Vec<u8>> = Vec::new();
    println!("Starting encrypting...");
    for handle in t {
        let ret = handle.await.unwrap();
        rets.push(ret);
    }
    println!("Encryption finished, now joining blocks...");
    for i in 0..thread {
        result.append(&mut rets[i]);
    }
    println!("Joining blocks finished, now writing into the file...");
    write_bytes(out_file_path, &result).unwrap();
    println!("Done");
}

async fn decrypt_file(in_file_path: String, out_file_path: String, key: Vec<u8>, thread: usize) {
    let mut result: Vec<u8> = Vec::new();
    let ori_file_data = Arc::new(read_bytes(in_file_path).unwrap());
    let mut t: Vec<task::JoinHandle<_>> = Vec::new();
    for i in 0..thread {
        let data = ori_file_data.clone();
        let key = key.clone();
        t.push(task::spawn_blocking(move || {decrypt(i, data, key, thread)}));
    }
    let mut rets : Vec<Vec<u8>> = Vec::new();
    println!("Starting decrypting...");
    for handle in t {
        let ret = handle.await.unwrap();
        rets.push(ret);
    }
    println!("Decryption finished, now joining blocks...");
    for i in 0..thread {
        result.append(&mut rets[i]);
    }
    println!("Joining blocks finished, now writing into the file...");
    write_bytes(out_file_path, &result).unwrap();
    println!("Done");
}

#[tokio::main]
async fn main() {
    let matches = App::new("File encrypt and decrypt tool")
                          .version("0.1")
                          .author("Shuxiang Li. <lishuxiang@cug.edu.cn>")
                          .about("Use des to encrypt and decrypt files")
                          .subcommand(SubCommand::with_name("enc")
                                      .about("encrypt a file")
                                      .version("0.1")
                                      .author("Shuxiang Li. <lishuxiang@cug.edu.cn>")
                                      .arg(Arg::with_name("KEY")
                                          .long("key")
                                          .short("k")
                                          .help("the key used to encrypt")
                                          .value_name("KEY"))
                                      .arg(Arg::with_name("INPUT")
                                          .short("i")
                                          .long("input")
                                          .help("the file to be encrypted")
                                          .value_name("INPUT"))
                                      .arg(Arg::with_name("THREAD")
                                          .short("t")
                                          .long("thread")
                                          .help("running thread count")
                                          .value_name("THREAD"))
                                      .arg(Arg::with_name("OUTPUT")
                                          .short("o")
                                          .long("output")
                                          .help("encryption output")
                                          .value_name("OUTPUT")))
                          .subcommand(SubCommand::with_name("dec")
                                      .about("decrypt a file")
                                      .version("0.1")
                                      .author("Shuxiang Li. <lishuxiang@cug.edu.cn>")
                                      .arg(Arg::with_name("KEY")
                                          .short("k")
                                          .long("key")
                                          .help("the key used to decrypt")
                                          .value_name("KEY"))
                                      .arg(Arg::with_name("INPUT")
                                          .short("i")
                                          .long("input")
                                          .help("the file to be decrypted")
                                          .value_name("INPUT"))
                                      .arg(Arg::with_name("THREAD")
                                          .short("t")
                                          .long("thread")
                                          .help("running thread count")
                                          .value_name("THREAD"))
                                      .arg(Arg::with_name("OUTPUT")
                                          .short("o")
                                          .long("output")
                                          .help("decryption output")
                                          .value_name("OUTPUT")))
                          .get_matches();
    if let Some(matches) = matches.subcommand_matches("enc") {
        let key = matches.value_of("KEY").unwrap_or("12345678");
        let thread = matches.value_of("THREAD").unwrap_or("8").parse().unwrap_or(8);
        let key = match key.len() { 
            BLOCK_SIZE => key.to_string(),
            _ => {
                    if key.len() < BLOCK_SIZE {
                        let mut corret: String = String::from(key);
                        corret.push_str(&"0".repeat(BLOCK_SIZE - key.len()));
                        corret
                    } else {
                        (&key[0..BLOCK_SIZE]).to_string()
                    }
            }
        };
        println!("{}", key);
        let input_file = matches.value_of("INPUT").unwrap();
        let output_file = matches.value_of("OUTPUT").unwrap();
        encrypt_file(input_file.to_owned(), output_file.to_owned(), key.as_bytes().to_vec(), thread).await;
    } else if let Some(matches) = matches.subcommand_matches("dec") {
        let key = matches.value_of("KEY").unwrap_or("12345678");
        let thread = matches.value_of("THREAD").unwrap_or("8").parse().unwrap_or(8);
        let key = match key.len() { 
            BLOCK_SIZE => key.to_string(),
            _ => {
                    if key.len() < BLOCK_SIZE {
                        let mut corret: String = String::from(key);
                        corret.push_str(&"0".repeat(BLOCK_SIZE - key.len()));
                        corret
                    } else {
                        (&key[0..BLOCK_SIZE]).to_string()
                    }
            }
        };
        println!("{}", key);
        let input_file = matches.value_of("INPUT").unwrap();
        let output_file = matches.value_of("OUTPUT").unwrap();
        decrypt_file(input_file.to_owned(), output_file.to_owned(), key.as_bytes().to_vec(), thread).await;
    }

    // more program logic goes here...
}
