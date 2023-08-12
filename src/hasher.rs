use std::io::prelude::*;
use std::fs::File;
use digest::DynDigest;

#[allow(dead_code)]
pub enum HashError {
    Ok,
    GenericError,
    HashVerifyFail(String),
    HashDifferent,
    ReadError,
    FileOpenError(String)
}

const HEX_CHARS: &str = "0123456789abcdef";

fn to_hex_string(hash_val: Box<[u8]>) -> String {
    let mut res = String::new();

    for i in 0..hash_val.len() {
        let hi_nibble = (hash_val[i] & 0xF0u8) >> 4;
        let lo_nibble = hash_val[i] & 0x0Fu8;
        res.push(HEX_CHARS.as_bytes()[usize::from(hi_nibble)] as char);
        res.push(HEX_CHARS.as_bytes()[usize::from(lo_nibble)] as char);
    }

    return res;
}

impl HashError {
    pub fn message(&self) -> String {
        match self {
            HashError::GenericError => "Operation failed".to_string(),
            HashError::FileOpenError(file_name) => format!("Error opening file '{}'", file_name),
            HashError::Ok => "OK".to_string(),
            HashError::HashDifferent => "Hashes different".to_string(),
            HashError::HashVerifyFail(file_name) => format!("Hash verification for file '{}' failed", file_name),
            HashError::ReadError => "Unable to read data".to_string()
        }
    }
} 

const BUFFER_SIZE: usize = 4096;

pub trait DataHasher {
    fn hash_data(&mut self, r: &mut dyn Read)-> Result<String, HashError>;
}

pub trait FileHash : DataHasher {
    fn get_algo(&self) -> String;
    fn verify_data(&mut self, r: &mut dyn Read, hash: &String)-> HashError;
    fn hash_file(&mut self, file_name: &String) -> Result<String, HashError>;
    fn verify_file(&mut self, file_name: &String, hash: &String) -> HashError;
}

pub struct Hasher {
    algo_name: String,
    hash_impl: Box<dyn DynDigest>,
    buffer: [u8; BUFFER_SIZE]
} 

impl Hasher {
    pub fn new(name: &str, d: Box<dyn DynDigest>) -> Hasher {
        let res = Hasher {
                    algo_name: String::from(name),
                    hash_impl: d,
                    buffer: [0; BUFFER_SIZE]
                }; 

        return res;
    }
}

impl DataHasher for Hasher {
    fn hash_data(&mut self, r: &mut dyn Read) -> Result<String, HashError> {
        self.hash_impl.reset();

        loop {
            let data_read =  r.read(&mut self.buffer);
            match data_read {
                Ok(0) => {
                    let hash_val = self.hash_impl.finalize_reset();
                    return Ok(to_hex_string(hash_val));
                },
                Ok(bytes_read) => self.hash_impl.update(&self.buffer[..bytes_read]),
                Err(_) => return Err(HashError::ReadError)
            }
        }
    }
}

impl FileHash for Hasher
{
    fn get_algo(&self) -> String {
        return self.algo_name.clone();
    }

    fn verify_data(&mut self, r: &mut dyn Read, hash: &String)-> HashError {
        let hash_res = match self.hash_data(r) {
            Ok(hash_val) => hash_val,
            Err(err_val) => return err_val,
        };

        if hash != &hash_res {
            return HashError::HashDifferent;
        }

        return HashError::Ok;        
    } 

    fn hash_file(&mut self, file_name: &String) -> Result<String, HashError> {
        let mut f = match File::open(file_name) {
            Ok(file) => file,
            Err(_) => return Err(HashError::FileOpenError(file_name.clone())),
        };

        return self.hash_data(&mut f);
    }

    fn verify_file(&mut self, file_name: &String, hash: &String) -> HashError {
        let hash_res = match self.hash_file(file_name) {
            Ok(hash_val) => hash_val,
            Err(err_val) => return err_val,
        };

        if hash != &hash_res {
            return HashError::HashVerifyFail(file_name.clone());
        }

        return HashError::Ok;
    }
}

