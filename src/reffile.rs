use std::io::{self, BufRead, Read};
use std::rc::Rc;
use std::cell::RefCell;

use crate::hasher::FileHash;
use crate::hasher::HashError;
use crate::formatter::HashLineFormatter;

pub struct RefFileIter<R : Read> {
    parser: Rc<dyn HashLineFormatter>,
    line_iter: Rc<RefCell<std::io::Lines<io::BufReader<R>>>>    
}

impl<R : Read> Iterator for RefFileIter<R> {
    type Item = (String, String);

    fn next(&mut self) -> Option<(String, String)> {
        let line_res = self.line_iter.borrow_mut().next();
        let line_raw = match line_res {
            Some(d) => match d {
                Err(e) => {
                    println!("{}", e);
                    return None
                },
                Ok(d) => String::from(d)
            }
            None => return None
        };

        let res = self.parser.parse(&line_raw);

        let item = match res {
            Err(e) => {
                println!("{}", e.message());
                return None
            },
            Ok(i) => Some(i),
        };

        return item;
    }  
}

pub struct RefFile<R : Read> {
    hasher: Rc<RefCell<dyn FileHash>>,
    parser: Rc<dyn HashLineFormatter>,
    line_iter: Rc<RefCell<std::io::Lines<io::BufReader<R>>>>
}

impl<R : Read> RefFile<R> {
    pub fn new(s: R, h: &Rc<RefCell<dyn FileHash>>, p: &Rc<dyn HashLineFormatter>) -> Self {
        return RefFile {
            hasher: h.clone(),
            parser: p.clone(),
            line_iter: Rc::new(RefCell::new(io::BufReader::new(s).lines()))
        }
    }

    pub fn process_one_file(&self, ref_data: (&String, &String)) -> bool {
        let file_name = ref_data.0;
        let hash_val = ref_data.1;
    
        let verify_result = self.hasher.borrow_mut().verify_file(file_name, hash_val);
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
}

impl<R : Read> IntoIterator for &RefFile<R> {
    type Item = (String, String);
    type IntoIter = RefFileIter<R>;

    fn into_iter(self) -> Self::IntoIter {
        return RefFileIter {
            parser: self.parser.clone(),
            line_iter: self.line_iter.clone()
        }
    }
}