use crypto::sha2::{Sha256/*, Sha512*/};
use std::io::{self, BufRead};
use std::path::Path;
use std::fs::File;
use clap::{Arg, App, SubCommand};

mod tests;
mod hasher;
mod formatter;

use hasher as hs;
use hs::FileHash;


fn hash_files(file_names: &Vec<String>, h: &mut dyn FileHash, line_formatter: &dyn formatter::HashLineFormatter) {
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

fn verify_files(lines: &Vec<String>, h: &mut dyn FileHash, line_parser: &dyn formatter::HashLineParser) {
    let mut all_ok = true;

    for i in lines {
        match line_parser.parse(i) {
            Ok((file_name, hash_val)) => {
                let verify_result = h.verify_file(&file_name, &hash_val);
                match verify_result {
                    hs::HashError::Ok => {
                        println!("{}: OK", file_name);
                    },
                    hs::HashError::HashDifferent | hs::HashError::HashVerifyFail(_) => {
                        all_ok = false;
                        println!("{}: FAILED!!!", file_name);
                    },
                    _ => {
                        all_ok = false;
                        println!("{}", verify_result.message());
                    } 
                }
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

fn verify_ref_file(ref_file: &String, h: &mut dyn FileHash, line_parser: &dyn formatter::HashLineParser) {
    let all_lines = match read_lines_from_file(Path::new(ref_file)) {
        Ok(name) => name,
        Err(e) => {
            println!("{}", e);
            return;
        }
    };
        
    verify_files(&all_lines, h, line_parser);
}

fn main() {
    let matches = App::new("rs256sum")
        .version("0.1.0")
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
                    .help("A file with reference hashes")))
        .subcommand(
            SubCommand::with_name("gen")
                .about("Generate reference data")        
                    .arg(Arg::with_name("files")
                    .required(true)
                    .short("f")
                    .long("files")
                    .takes_value(true)
                    .multiple(true)
                    .help("All files to hash")))
        .get_matches();

    let mut h = hs::Hasher::new("SHA-256", Box::new(Sha256::new()));
    let f = formatter::SimpleFormatter::new();
    let subcommand = matches.subcommand();

     match subcommand {
        ("gen", Some(gen_matches)) => {
            let mut file_names: Vec<String> = Vec::new();
            gen_matches.values_of("files").unwrap().for_each(|x| file_names.push(String::from(x)));

            hash_files(&file_names, &mut h, &f);
        },
        ("verify", Some(verify_matches)) => {
            let ref_file = String::from(verify_matches.value_of("inputfile").unwrap());
            verify_ref_file(&ref_file, &mut h, &f);
        },
        _ => {
            println!("Unrecognized command");
        }
    }
}

