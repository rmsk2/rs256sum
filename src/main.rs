use crypto::sha2::{Sha256, Sha512};
use std::fs::File;
use clap::{Arg, App, SubCommand};
use crypto::digest::Digest;
use std::rc::Rc;
use std::cell::RefCell;
use std::process;
use std::io::{self, Read, BufRead};

mod tests;
mod hasher;
mod formatter;
mod reffile;

use hasher as hs;
use hasher::FileHash;
use formatter::HashLineFormatter;
use reffile::RefFile;

const ALGO_SHA256: &str = "SHA256";
const ALGO_SHA512: &str = "SHA512";
const PROG_RETURN_OK: i32 = 0;
const PROG_RETURN_ERR: i32 = 42;


fn hash_files<T>(file_names: T, h: &Rc<RefCell<dyn FileHash>>, line_formatter: &dyn HashLineFormatter) -> (u32, bool)
where 
    T: IntoIterator<Item=String>
{
    let mut count: u32 = 0;

    for i in file_names {
        let hash = match h.borrow_mut().hash_file(&i) {
            Ok(val) => val,
            Err(err) => {
                eprintln!("{}", err.message()); 
                return (count, false);
            }
        };

        println!("{}", line_formatter.format(&hash, &i));
        count += 1;
    }

    return (count, true);
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
    let mut algo_name = ALGO_SHA256;

    if use_sha_512 {
        hash = Box::new(Sha512::new());
        algo_name = ALGO_SHA512;
    }

    return Rc::new(RefCell::new(hs::Hasher::new(algo_name, hash)));
}

fn gen_command(gen_matches: &clap::ArgMatches) -> i32 {
    let h = make_file_hash(gen_matches.is_present(ARG_SHA_512));
    let f = make_formatter(&h.borrow().get_algo(), gen_matches.is_present(ARG_USE_BSD));
    let mut files_hashed: u32 = 0;
    let mut all_ok = true;
    
    if let Some(in_files) = gen_matches.values_of(ARG_FILES) {
        let mut file_names: Vec<String> = Vec::new();
        in_files.for_each(|x| file_names.push(String::from(x)));
        let (hash_count, ok) = hash_files(file_names, &h, f.as_ref());
        files_hashed += hash_count;
        all_ok &= ok;
    }

    if gen_matches.is_present(ARG_FROM_STDIN) {
        let mut line_iter = io::BufReader::new(io::stdin()).lines().map(|x| x.unwrap());
        let (hash_count, ok) = hash_files(&mut line_iter, &h, f.as_ref());
        files_hashed += hash_count;
        all_ok &= ok;
    }

    if files_hashed == 0 {
        eprintln!("No input specified");
        return PROG_RETURN_ERR;
    }

    if !all_ok {
        return PROG_RETURN_ERR;
    }

    return PROG_RETURN_OK;
}

fn verify_command(verify_matches: &clap::ArgMatches) -> i32 {
    let h = make_file_hash(verify_matches.is_present(ARG_SHA_512));
    let f = make_formatter(&h.borrow().get_algo(), verify_matches.is_present(ARG_USE_BSD));
    let mut all_ok = true;  
    
    if verify_matches.is_present(ARG_INPUT_FILE) {
        let ref_file = String::from(verify_matches.value_of(ARG_INPUT_FILE).unwrap());

        let stream_in = match File::open(ref_file) {
            Ok(f) => f,
            Err(e) => {
                eprintln!("{}", e);
                return PROG_RETURN_ERR;
            }
        };

        all_ok &= verify_ref_file(RefFile::new(stream_in, &h, &f));
    }

    if verify_matches.is_present(ARG_FROM_STDIN) {
        all_ok &= verify_ref_file(RefFile::new(io::stdin(), &h, &f));
    }

    if !all_ok {
        eprintln!("There were errors!!");
        return PROG_RETURN_ERR;
    } 

    return PROG_RETURN_OK;
}

const COMMAND_GEN: &str = "gen";
const COMMAND_VERIFY: &str = "verify";
const ARG_INPUT_FILE: &str = "inputfile";
const ARG_SHA_512: &str = "sha512";
const ARG_USE_BSD: &str = "use-bsd";
const ARG_FROM_STDIN: &str = "from-stdin";
const ARG_FILES: &str = "files";

fn main() {
    let mut app = App::new("rs256sum")
        .version("0.9.5")
        .author("Martin Grap <rmsk2@gmx.de>")
        .about("A sha256sum clone in Rust")          
        .subcommand(
            SubCommand::with_name(COMMAND_VERIFY)
                .about("Verify reference data")        
                .arg(Arg::with_name(ARG_INPUT_FILE)
                    .short("i")
                    .long("input")
                    .takes_value(true)
                    .help("A file containing reference hashes"))
                .arg(Arg::with_name(ARG_SHA_512)
                    .long("sha512")
                    .help("Use SHA512"))
                .arg(Arg::with_name(ARG_USE_BSD)
                    .long("use-bsd")
                    .help("Use BSD format"))
                .arg(Arg::with_name(ARG_FROM_STDIN)
                    .long("from-stdin")
                    .help("Read reference data from stdin")))
        .subcommand(
            SubCommand::with_name(COMMAND_GEN)
                .about("Generate reference data")        
                .arg(Arg::with_name(ARG_FILES)
                    .short("f")
                    .long("files")
                    .takes_value(true)
                    .multiple(true)
                    .help("Names of files to hash"))
                .arg(Arg::with_name(ARG_SHA_512)
                    .long("sha512")
                    .help("Use SHA512"))
                .arg(Arg::with_name(ARG_USE_BSD)
                    .long("use-bsd")
                    .help("Use BSD format"))
                .arg(Arg::with_name(ARG_FROM_STDIN)
                    .long("from-stdin")
                    .help("Read names of files to hash from stdin")));

    let matches = app.clone().get_matches();
    let subcommand = matches.subcommand();

    let return_code = match subcommand {
        (COMMAND_GEN, Some(gen_matches)) => {
            gen_command(gen_matches)
        },
        (COMMAND_VERIFY, Some(verify_matches)) => {
            verify_command(verify_matches)
        },
        _ => {
            match app.print_long_help() {
                Err(e) => eprintln!("{}", e),
                _ => eprintln!("")
            }

            PROG_RETURN_ERR
        }
    };

    process::exit(return_code);
}

