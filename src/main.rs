//use clap::parser::ValuesRef;
use crypto::sha2::{Sha256, Sha512};
use std::fs::File;
use clap::{Arg, Command};
use crypto::digest::Digest;
use std::rc::Rc;
use std::process;
use std::io::{self, Read, BufRead};

mod tests;
mod hasher;
mod formatter;
mod reffile;

use hasher::Hasher;
use hasher::FileHash;
use hasher::HashError;
use formatter::HashLineFormatter;
use reffile::RefFile;

const ALGO_SHA256: &str = "SHA256";
const ALGO_SHA512: &str = "SHA512";
const PROG_RETURN_OK: i32 = 0;
const PROG_RETURN_ERR: i32 = 42;


fn hash_files<T>(file_names: T, h: &mut dyn FileHash, line_formatter: &dyn HashLineFormatter) -> (u32, bool)
where 
    T: IntoIterator<Item=String>
{
    let mut count: u32 = 0;

    for i in file_names {
        let hash = match h.hash_file(&i) {
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

pub fn process_one_file(hasher: &mut dyn FileHash, ref_data: (&String, &String)) -> bool {
    let (file_name, hash_val) = ref_data;

    let verify_result = hasher.verify_file(file_name, hash_val);
    match verify_result {
        HashError::Ok => {
            println!("{}: OK", file_name);
            return true;
        },
        HashError::HashDifferent | HashError::HashVerifyFail(_) => {
            println!("{}: FAILED!!!", file_name);
            return false;
        },
        _ => {
            println!("{}: {}", file_name, verify_result.message());
            return false;
        }  
    }   
}

fn verify_ref_file<R : Read>(ref_file: RefFile<R>, hasher: &mut dyn FileHash) -> bool {
    let mut all_ok = true;
 
    ref_file.into_iter().for_each(|i| all_ok &= process_one_file(hasher, (&i.0, &i.1)));

    return all_ok;   
}

fn make_formatter(algo_name: &String, use_bsd: bool) -> Rc<dyn HashLineFormatter> {
    if use_bsd {
        return Rc::new(formatter::BsdFormatter::new(algo_name));
    } else {
        return Rc::new(formatter::SimpleFormatter::new());
    }
}

fn make_file_hash(use_sha_512: bool) -> Box<dyn FileHash> {
    let mut hash: Box<dyn Digest> = Box::new(Sha256::new());
    let mut algo_name = ALGO_SHA256;

    if use_sha_512 {
        hash = Box::new(Sha512::new());
        algo_name = ALGO_SHA512;
    }

    return Box::new(Hasher::new(algo_name, hash));
}

fn is_option_present(matches: &clap::ArgMatches, id: &str) -> bool {
    let test_res = matches.value_source(id);

    return match test_res {
        Some(v) => {
            return v == clap::parser::ValueSource::CommandLine;
        }
        None => false
    }
}

fn gen_command(gen_matches: &clap::ArgMatches) -> i32 {
    let mut h = make_file_hash(is_option_present(gen_matches, ARG_SHA_512));
    let f = make_formatter(&h.get_algo(), is_option_present(gen_matches, ARG_USE_BSD));
    let mut files_hashed: u32 = 0;
    let mut all_ok = true;
    
    let in_files_match_data= gen_matches.get_many::<String>(ARG_FILES);

    if let Some(in_files) = in_files_match_data {
        let mut file_names: Vec<String> = Vec::new();
        in_files.for_each(|x| file_names.push(String::from(x)));
        let (hash_count, ok) = hash_files(file_names, h.as_mut(), f.as_ref());
        files_hashed += hash_count;
        all_ok &= ok;
    }

    if is_option_present(gen_matches, ARG_FROM_STDIN) {
        let mut line_iter = io::BufReader::new(io::stdin()).lines().map(|x| x.unwrap());
        let (hash_count, ok) = hash_files(&mut line_iter, h.as_mut(), f.as_ref());
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
    let mut h = make_file_hash(is_option_present(verify_matches, ARG_SHA_512));
    let f = make_formatter(&h.get_algo(), is_option_present(verify_matches, ARG_USE_BSD));
    let mut all_ok = true;  
    
    if is_option_present(verify_matches, ARG_INPUT_FILE) {
        let in_file: Option<&String> = verify_matches.get_one(ARG_INPUT_FILE);
        let ref_file: String = String::from(in_file.unwrap().clone());

        let stream_in = match File::open(ref_file) {
            Ok(f) => f,
            Err(e) => {
                eprintln!("{}", e);
                return PROG_RETURN_ERR;
            }
        };

        all_ok &= verify_ref_file(RefFile::new(stream_in, &f), h.as_mut());
    }

    if is_option_present(verify_matches, ARG_FROM_STDIN) {
        all_ok &= verify_ref_file(RefFile::new(io::stdin(), &f), h.as_mut());
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
    let mut app = Command::new("rs256sum")
        .version("0.9.5")
        .author("Martin Grap <rmsk2@gmx.de>")
        .about("A sha256sum clone in Rust")          
        .subcommand(
            Command::new(COMMAND_VERIFY)
                .about("Verify reference data")        
                .arg(Arg::new(ARG_INPUT_FILE)
                    .short('i')
                    .long("input")
                    .num_args(1)
                    .help("A file containing reference hashes"))
                .arg(Arg::new(ARG_SHA_512)
                    .long("sha512")
                    .num_args(0)
                    .help("Uses SHA512"))
                .arg(Arg::new(ARG_USE_BSD)
                    .long("use-bsd")
                    .num_args(0)
                    .help("Uses BSD format"))
                .arg(Arg::new(ARG_FROM_STDIN)
                    .long("from-stdin")
                    .num_args(0)
                    .help("Reads reference data from stdin")))
        .subcommand(
            Command::new(COMMAND_GEN)
                .about("Generate reference data")        
                .arg(Arg::new(ARG_FILES)
                    .short('f')
                    .long("files")
                    .num_args(1..)
                    .help("Names of files to hash"))
                .arg(Arg::new(ARG_SHA_512)
                    .long("sha512")
                    .num_args(0)
                    .help("Uses SHA512"))
                .arg(Arg::new(ARG_USE_BSD)
                    .long("use-bsd")
                    .num_args(0)
                    .help("Uses BSD format"))
                .arg(Arg::new(ARG_FROM_STDIN)
                    .long("from-stdin")
                    .num_args(0)
                    .help("Reads names of files to hash from stdin")));

    let matches = app.clone().get_matches();
    let subcommand = matches.subcommand();

    let return_code = match subcommand {
        Some((COMMAND_GEN, gen_matches)) => {
            gen_command(gen_matches)
        },
        Some((COMMAND_VERIFY, verify_matches)) => {
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

