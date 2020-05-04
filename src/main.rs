#[macro_use] 
extern crate hex_literal;
extern crate clap;
extern crate des;
extern crate block_modes;
use futures::executor;
use clap::{Arg, App, SubCommand};
use fltk::{window::*, button::*, text::*, frame::*, group::*, valuator::*, dialog::*};
use std::io;
use std::io::prelude::*;
use std::io::BufWriter;
use std::fs::{File, read};
use std::sync::Arc;
use tokio::task;

use block_modes::{BlockMode, Ecb};
use block_modes::block_padding::Pkcs7;
use des::Des;
type DesEcb = Ecb<Des, Pkcs7>;

const BLOCK_SIZE: usize = 8;

const IV: [u8; 8] = hex!("0000000000000000");

fn read_bytes(file_path: String) -> io::Result<Vec<u8>> {
    Ok(read(file_path)?)
}

fn write_bytes(file_path: String, bytes: &[u8]) -> io::Result<()> {
    let f = File::create(file_path)?;
    let mut writer = BufWriter::new(f);
    writer.write_all(bytes)?;
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
    cipher.encrypt_vec(blocks)
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
    cipher.decrypt_vec(blocks).unwrap()
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
    for mut ret in rets.iter_mut() {
        result.append(&mut ret);
    }
    for mut ret in rets.iter_mut().take(1) {
        result.append(&mut ret);
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
    for mut ret in rets.iter_mut() {
        result.append(&mut ret);
    }
    // for i in 0..thread {
    //     result.append(&mut rets[i]);
    // }
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
        let key = if let BLOCK_SIZE = key.len() {
            key.to_string()
        } else if key.len() < BLOCK_SIZE {
            let mut corret: String = String::from(key);
            corret.push_str(&"0".repeat(BLOCK_SIZE - key.len()));
            corret
        } else {
            (&key[0..BLOCK_SIZE]).to_string()
        };
        let input_file = matches.value_of("INPUT").unwrap();
        let output_file = matches.value_of("OUTPUT").unwrap();
        encrypt_file(input_file.to_owned(), output_file.to_owned(), key.as_bytes().to_vec(), thread).await;
    } else if let Some(matches) = matches.subcommand_matches("dec") {
        let key = matches.value_of("KEY").unwrap_or("12345678");
        let thread = matches.value_of("THREAD").unwrap_or("8").parse().unwrap_or(8);
        let key = if let BLOCK_SIZE = key.len() {
            key.to_string()
        } else if key.len() < BLOCK_SIZE {
            let mut corret: String = String::from(key);
            corret.push_str(&"0".repeat(BLOCK_SIZE - key.len()));
            corret
        } else {
            (&key[0..BLOCK_SIZE]).to_string()
        };
        let input_file = matches.value_of("INPUT").unwrap();
        let output_file = matches.value_of("OUTPUT").unwrap();
        decrypt_file(input_file.to_owned(), output_file.to_owned(), key.as_bytes().to_vec(), thread).await;
    }
    // more program logic goes here...
    let app = fltk::app::App::default();
    let mut wind = Window::new(100, 100, 600, 360, "Des encrypt and decrypt");
    let tab = Tabs::new(10, 10, 600 - 20, 360 - 20, "");
    let grp1 = Group::new(10, 35, 600 - 20, 360 - 45, "Encryption");
    let _frame_input_enc = Frame::new(20, 55, 50, 20, "Input file");
    let mut input_enc = TextBuffer::default();
    let _text_input_enc = TextEditor::new(20, 20 + 55, 400, 30, &mut input_enc);
    let mut but_input_enc_file_dlg = Button::new(430, 20 + 55, 100, 30, "Browser");
    let _frame_output_enc = Frame::new(20, 70 + 55, 60, 20, "Output file");
    let mut output_enc = TextBuffer::default();
    let _text_output_enc = TextEditor::new(20, 100 + 55, 400, 30, &mut output_enc);
    let mut but_output_enc_file_dlg = Button::new(430, 100 + 55, 100, 30, "Browser");
    let _frame_pass_enc = Frame::new(20, 150 + 55, 50, 20, "Password");
    let mut pass_enc = TextBuffer::default();
    let _text_pass_enc = TextEditor::new(20, 170 + 55, 400, 30, &mut pass_enc);
    let mut but_enc = Button::new(20, 220 + 55, 80, 40, "Encrypt");
    let mut thread_slide_enc = Slider::new(120, 220 + 55, 300, 50, "Thread count = 1");
    thread_slide_enc.set_type(SliderType::HorizontalSlider);
    grp1.end();

    let grp2 = Group::new(10, 35, 600 - 20, 360 - 45, "Decryption");
    let _frame_input_dec = Frame::new(20, 55, 50, 20, "Input file");
    let mut input_dec = TextBuffer::default();
    let _text_input_dec = TextEditor::new(20, 20 + 55, 400, 30, &mut input_dec);
    let mut but_input_dec_file_dlg = Button::new(430, 20 + 55, 100, 30, "Browser");
    let _frame_output_dec = Frame::new(20, 70 + 55, 60, 20, "Output file");
    let mut output_dec = TextBuffer::default();
    let _text_output_dec = TextEditor::new(20, 100 + 55, 400, 30, &mut output_dec);
    let mut but_output_dec_file_dlg = Button::new(430, 100 + 55, 100, 30, "Browser");
    let _frame_pass_dec = Frame::new(20, 150 + 55, 50, 20, "Password");
    let mut pass_dec = TextBuffer::default();
    let _text_pass_dec = TextEditor::new(20, 170 + 55, 400, 30, &mut pass_dec);
    let mut but_dec = Button::new(20, 220 + 55, 80, 40, "Decrypt");
    let mut thread_slide_dec = Slider::new(120, 220 + 55, 300, 50, "Thread count = 1");
    thread_slide_dec.set_type(SliderType::HorizontalSlider);
    grp2.end();
    tab.end();
    wind.end();
    wind.show();
    unsafe {
        let input_enc_p: *mut TextBuffer = &mut input_enc;
        but_input_enc_file_dlg.set_callback(Box::new(move || {
            let mut file_dialog = FileDialog::new(FileDialogType::BrowseFile);
            file_dialog.show();
            let file_name = file_dialog.filename().into_os_string().into_string().unwrap();
            (*input_enc_p).set_text(&file_name);
        }));
        let output_enc_p: *mut TextBuffer = &mut output_enc;
        but_output_enc_file_dlg.set_callback(Box::new(move || {
            let mut file_dialog = FileDialog::new(FileDialogType::BrowseFile);
            file_dialog.show();
            let file_name = file_dialog.filename().into_os_string().into_string().unwrap();
            (*output_enc_p).set_text(&file_name);
        }));
        let input_dec_p: *mut TextBuffer = &mut input_dec;
        but_input_dec_file_dlg.set_callback(Box::new(move || {
            let mut file_dialog = FileDialog::new(FileDialogType::BrowseFile);
            file_dialog.show();
            let file_name = file_dialog.filename().into_os_string().into_string().unwrap();
            (*input_dec_p).set_text(&file_name);
        }));
        let output_dec_p: *mut TextBuffer = &mut output_dec;
        but_output_dec_file_dlg.set_callback(Box::new(move || {
            let mut file_dialog = FileDialog::new(FileDialogType::BrowseFile);
            file_dialog.show();
            let file_name = file_dialog.filename().into_os_string().into_string().unwrap();
            (*output_dec_p).set_text(&file_name);
        }));
        let thread_slide_enc_p: *const Slider = &thread_slide_enc;
        let thread_slide_dec_p: *const Slider = &thread_slide_dec;
        but_enc.set_callback(Box::new(move || {executor::block_on(encrypt_file(input_enc.text(), output_enc.text(), pass_enc.text().as_bytes().to_vec(), ((*thread_slide_enc_p).value() * 31.0 + 1.0) as usize));}));
        but_dec.set_callback(Box::new(move || {executor::block_on(decrypt_file(input_dec.text(), output_dec.text(), pass_dec.text().as_bytes().to_vec(), ((*thread_slide_dec_p).value() * 31.0 + 1.0) as usize));}));
        let thread_slide_enc_p: *mut Slider = &mut thread_slide_enc;
        thread_slide_enc.set_callback(Box::new(move || (*thread_slide_enc_p).set_label(&format!{"Thread count = {}", ((*thread_slide_enc_p).value() * 31.0 + 1.0) as usize})));
        let thread_slide_dec_p: *mut Slider = &mut thread_slide_dec;
        thread_slide_dec.set_callback(Box::new(move || (*thread_slide_dec_p).set_label(&format!{"Thread count = {}", ((*thread_slide_dec_p).value() * 31.0 + 1.0) as usize})));
    }
    app.run().unwrap();
}
