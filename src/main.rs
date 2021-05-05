use crypto::sha2::{Sha256, Sha512};
use std::io::{self, BufRead};
use std::path::Path;
use std::fs::File;
use clap::{Arg, App, SubCommand};
use crypto::digest::Digest;

mod tests;
mod hasher;
mod formatter;

use hasher as hs;
use hasher::FileHash;
use formatter::HashLineFormatter;


fn hash_files(file_names: &Vec<String>, h: &mut dyn FileHash, line_formatter: &dyn HashLineFormatter) {
    for i in file_names {
        let hash = match h.hash_file(i) {
            Ok(val) => val,
            Err(err) => {
                println!("{}", err.message()); 
                return;
            }
        };

        let line_out = line_formatter.format(&hash, i);

        println!("{}", line_out);
    }
}

fn verify_one_file(h: &mut dyn FileHash, ref_data: (&String, &String)) -> bool {
    let file_name = ref_data.0;
    let hash_val = ref_data.1;

    let verify_result = h.verify_file(file_name, hash_val);
    match verify_result {
        hs::HashError::Ok => {
            println!("{}: OK", file_name);
            return true;
        },
        hs::HashError::HashDifferent | hs::HashError::HashVerifyFail(_) => {
            println!("{}: FAILED!!!", file_name);
            return false;
        },
        _ => {
            println!("{}: {}", file_name, verify_result.message());
            return false;
        }  
    }   
}

fn verify_files(lines: &Vec<String>, h: &mut dyn FileHash, line_parser: &dyn HashLineFormatter) {
    let mut all_ok = true;

    for i in lines {
        match line_parser.parse(i) {
            Ok((file_name, hash_val)) => {
                all_ok &= verify_one_file(h, (&file_name, &hash_val));
            },
            Err(e) => {
                println!("{}", e.message());
                all_ok = false;
                break;
            }
        };
    }

    if !all_ok {
        println!("There were errors!!");
    }
}

fn read_lines_from_file<P>(filename: P) -> Result<Box<Vec<String>>, std::io::Error>
where P: AsRef<Path> {
    let mut result: Vec<String> = Vec::new();

    let file = File::open(filename)?;
    for i in io::BufReader::new(file).lines() {
        let l = match i {
            Ok(line) => line,
            Err(e) => return Err(e),
        };

        result.push(l);
    }

    Ok(Box::new(result))
}

fn verify_ref_file(ref_file: &String, h: &mut dyn FileHash, line_parser: &dyn HashLineFormatter) {
    let all_lines = match read_lines_from_file(Path::new(ref_file)) {
        Ok(lines) => lines,
        Err(e) => {
            println!("{}", e);
            return;
        }
    };
        
    verify_files(&all_lines, h, line_parser);
}

fn make_formatter(algo_name: &String, use_bsd: bool) -> Box<dyn HashLineFormatter> {
    if use_bsd {
        return Box::new(formatter::BsdFormatter::new(algo_name));
    }
    else
    {
        return Box::new(formatter::SimpleFormatter::new());
    }
}

fn make_file_hash(use_sha_512: bool) -> Box<dyn FileHash> {
    let mut hash: Box<dyn Digest> = Box::new(Sha256::new());
    let mut algo_name = "SHA256";

    if use_sha_512 {
        hash = Box::new(Sha512::new());
        algo_name = "SHA512";
    }
    
    return Box::new(hs::Hasher::new(&algo_name, hash));
}

fn main() {
    let mut app = App::new("rs256sum")
        .version("0.7.0")
        .author("Martin Grap <rmsk2@gmx.de>")
        .about("A sha256sum clone in Rust")          
        .subcommand(
            SubCommand::with_name("verify")
                .about("Verify reference data")        
                .arg(Arg::with_name("inputfile")
                    .required(true)
                    .short("i")
                    .long("input")
                    .takes_value(true)
                    .help("A file containing reference hashes"))
                .arg(Arg::with_name("sha512")
                    .long("sha512")
                    .help("Use SHA512"))
                .arg(Arg::with_name("use-bsd")
                    .long("use-bsd")
                    .help("Use BSD format")))
        .subcommand(
            SubCommand::with_name("gen")
                .about("Generate reference data")        
                .arg(Arg::with_name("files")
                    .required(true)
                    .short("f")
                    .long("files")
                    .takes_value(true)
                    .multiple(true)
                    .help("All files to hash"))
                .arg(Arg::with_name("sha512")
                    .long("sha512")
                    .help("Use SHA512"))
                .arg(Arg::with_name("use-bsd")
                    .long("use-bsd")
                    .help("Use BSD format")));

    let matches = app.clone().get_matches();
    let subcommand = matches.subcommand();

     match subcommand {
        ("gen", Some(gen_matches)) => {
            let mut file_names: Vec<String> = Vec::new();
            gen_matches.values_of("files").unwrap().for_each(|x| file_names.push(String::from(x)));
            let mut h = make_file_hash(gen_matches.is_present("sha512"));
            let f = make_formatter(&h.get_algo(), gen_matches.is_present("use-bsd"));

            hash_files(&file_names, h.as_mut(), f.as_ref());
        },
        ("verify", Some(verify_matches)) => {
            let ref_file = String::from(verify_matches.value_of("inputfile").unwrap());
            let mut h = make_file_hash(verify_matches.is_present("sha512"));
            let f = make_formatter(&h.get_algo(), verify_matches.is_present("use-bsd"));         

            verify_ref_file(&ref_file, h.as_mut(), f.as_ref());
        },
        _ => {
            match app.print_long_help() {
                Err(e) => println!("{}", e),
                _ => println!("")
            }
        }
    }
}

