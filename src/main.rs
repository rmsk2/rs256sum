use crypto::sha2::{Sha256, Sha512};
use std::fs::File;
use clap::{Arg, App, SubCommand};
use crypto::digest::Digest;
use std::rc::Rc;
use std::cell::RefCell;
use std::io::Read;

mod tests;
mod hasher;
mod formatter;
mod reffile;

use hasher as hs;
use hasher::FileHash;
use formatter::HashLineFormatter;
use reffile::RefFile;


fn hash_files<'a, T>(file_names: T, h: &Rc<RefCell<dyn FileHash>>, line_formatter: &dyn HashLineFormatter) 
where 
    T: IntoIterator<Item=&'a String>
{
    for i in file_names {
        let hash = match h.borrow_mut().hash_file(i) {
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

fn verify_ref_file<R : Read>(ref_file: RefFile<R>) {
    let mut all_ok = true;

    ref_file.into_iter().for_each(|i| all_ok &= ref_file.process_one_file((&i.0, &i.1)));

    if !all_ok {
        println!("There were errors!!");
    }    
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
            let h = make_file_hash(gen_matches.is_present("sha512"));
            let f = make_formatter(&h.borrow().get_algo(), gen_matches.is_present("use-bsd"));

            hash_files(&file_names, &h, f.as_ref());
        },
        ("verify", Some(verify_matches)) => {
            let ref_file = String::from(verify_matches.value_of("inputfile").unwrap());
            let h = make_file_hash(verify_matches.is_present("sha512"));
            let f = make_formatter(&h.borrow().get_algo(), verify_matches.is_present("use-bsd"));  
            
            let stream_in = match File::open(ref_file) {
                Ok(f) => f,
                Err(e) => {
                    println!("{}", e);
                    return;
                }
            };

            verify_ref_file(RefFile::new(stream_in, h, f));
        },
        _ => {
            match app.print_long_help() {
                Err(e) => println!("{}", e),
                _ => println!("")
            }
        }
    }
}

