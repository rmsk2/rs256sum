use std::io::prelude::*;
use std::fs::File;
use crypto::digest::Digest;

#[allow(dead_code)]
pub enum HashError {
    Ok,
    GenericError,
    HashVerifyFail(String),
    HashDifferent,
    ReadError,
    FileOpenError(String)
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



const BUFFER_SIZE : usize = 4096;

pub trait FileHash {
    fn get_algo(&self) -> String;
    fn hash_data(&mut self, r: &mut dyn Read)-> Result<String, HashError>;
    fn verify_data(&mut self, r: &mut dyn Read, hash: &String)-> HashError;
    fn hash_file(&mut self, file_name: &String) -> Result<String, HashError>;
    fn verify_file(&mut self, file_name: &String, hash: &String) -> HashError;
}

pub struct Hasher {
    algo_name: String,
    hash_impl: Box<dyn Digest>,
    buffer: [u8; BUFFER_SIZE]
} 

impl Hasher {
    pub fn new(name: &str, d: Box<dyn Digest>) -> Hasher {
        let res = Hasher {
                    algo_name: String::from(name),
                    hash_impl: d,
                    buffer: [0; BUFFER_SIZE]
                }; 

        return res;
    }
}

impl FileHash for Hasher
{
    fn get_algo(&self) -> String {
        return self.algo_name.clone();
    }

    fn hash_data(&mut self, r: &mut dyn Read) -> Result<String, HashError> {
        self.hash_impl.reset();

        loop {
            let data_read =  r.read(&mut self.buffer);
            match data_read {
                Ok(0) => {
                    let res = self.hash_impl.result_str();
                    self.hash_impl.reset();
                    return Ok(res);
                },
                Ok(bytes_read) => self.hash_impl.input(&self.buffer[..bytes_read]),
                Err(_) => return Err(HashError::ReadError)
            }
        }
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

