use crypto::sha2::{Sha256, Sha512};
use std::fs::File;
use clap::{Arg, App, SubCommand};
use crypto::digest::Digest;
use std::rc::Rc;
use std::cell::RefCell;
use std::io::Read;

use std::io::{self, BufRead};

mod tests;
mod hasher;
mod formatter;
mod reffile;

use hasher as hs;
use hasher::FileHash;
use formatter::HashLineFormatter;
use reffile::RefFile;


fn hash_files<T>(file_names: T, h: &Rc<RefCell<dyn FileHash>>, line_formatter: &dyn HashLineFormatter) -> u32
where 
    T: IntoIterator<Item=String>
{
    let mut count: u32 = 0;

    for i in file_names {
        let hash = match h.borrow_mut().hash_file(&i) {
            Ok(val) => val,
            Err(err) => {
                println!("{}", err.message()); 
                return count;
            }
        };

        println!("{}", line_formatter.format(&hash, &i));
        count += 1;
    }

    return count;
}

fn verify_ref_file<R : Read>(ref_file: RefFile<R>) -> bool {
    let mut all_ok = true;

    ref_file.into_iter().for_each(|i| all_ok &= ref_file.process_one_file((&i.0, &i.1)));

    return all_ok;   
}

fn make_formatter(algo_name: &String, use_bsd: bool) -> Rc<dyn HashLineFormatter> {
    if use_bsd {
        return Rc::new(formatter::BsdFormatter::new(algo_name));
    } else {
        return Rc::new(formatter::SimpleFormatter::new());
    }
}

fn make_file_hash(use_sha_512: bool) -> Rc<RefCell<dyn FileHash>> {
    let mut hash: Box<dyn Digest> = Box::new(Sha256::new());
    let mut algo_name = "SHA256";

    if use_sha_512 {
        hash = Box::new(Sha512::new());
        algo_name = "SHA512";
    }

    return Rc::new(RefCell::new(hs::Hasher::new(algo_name, hash)));
}

fn main() {
    let mut app = App::new("rs256sum")
        .version("0.9.0")
        .author("Martin Grap <rmsk2@gmx.de>")
        .about("A sha256sum clone in Rust")          
        .subcommand(
            SubCommand::with_name("verify")
                .about("Verify reference data")        
                .arg(Arg::with_name("inputfile")
                    .short("i")
                    .long("input")
                    .takes_value(true)
                    .help("A file containing reference hashes"))
                .arg(Arg::with_name("sha512")
                    .long("sha512")
                    .help("Use SHA512"))
                .arg(Arg::with_name("use-bsd")
                    .long("use-bsd")
                    .help("Use BSD format"))
                .arg(Arg::with_name("from-stdin")
                    .long("from-stdin")
                    .help("Read reference data from stdin")))
        .subcommand(
            SubCommand::with_name("gen")
                .about("Generate reference data")        
                .arg(Arg::with_name("files")
                    .short("f")
                    .long("files")
                    .takes_value(true)
                    .multiple(true)
                    .help("Names of files to hash"))
                .arg(Arg::with_name("sha512")
                    .long("sha512")
                    .help("Use SHA512"))
                .arg(Arg::with_name("use-bsd")
                    .long("use-bsd")
                    .help("Use BSD format"))
                .arg(Arg::with_name("from-stdin")
                    .long("from-stdin")
                    .help("Read names of files to hash from stdin")));

    let matches = app.clone().get_matches();
    let subcommand = matches.subcommand();

     match subcommand {
        ("gen", Some(gen_matches)) => {
            let h = make_file_hash(gen_matches.is_present("sha512"));
            let f = make_formatter(&h.borrow().get_algo(), gen_matches.is_present("use-bsd"));
            let mut files_hashed: u32 = 0;
            
            if let Some(in_files) = gen_matches.values_of("files") {
                let mut file_names: Vec<String> = Vec::new();
                in_files.for_each(|x| file_names.push(String::from(x)));
                files_hashed += hash_files(file_names, &h, f.as_ref());
            }

            if gen_matches.is_present("from-stdin") {
                let mut line_iter = io::BufReader::new(io::stdin()).lines().map(|x| x.unwrap());
                files_hashed += hash_files(&mut line_iter, &h, f.as_ref());
            }

            if files_hashed == 0 {
                println!("No input specified");
            }
        },
        ("verify", Some(verify_matches)) => {
            let h = make_file_hash(verify_matches.is_present("sha512"));
            let f = make_formatter(&h.borrow().get_algo(), verify_matches.is_present("use-bsd"));
            let mut all_ok = true;  
            
            if verify_matches.is_present("inputfile") {
                let ref_file = String::from(verify_matches.value_of("inputfile").unwrap());

                let stream_in = match File::open(ref_file) {
                    Ok(f) => f,
                    Err(e) => {
                        println!("{}", e);
                        return;
                    }
                };
    
                all_ok &= verify_ref_file(RefFile::new(stream_in, &h, &f));
            }

            if verify_matches.is_present("from-stdin") {
                all_ok &= verify_ref_file(RefFile::new(io::stdin(), &h, &f));
            }

            if !all_ok {
                println!("There were errors!!");
            } 

        },
        _ => {
            match app.print_long_help() {
                Err(e) => println!("{}", e),
                _ => println!("")
            }
        }
    }
}

