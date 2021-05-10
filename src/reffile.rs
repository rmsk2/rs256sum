use std::io::{self, BufRead, Read};
use std::rc::Rc;
use std::cell::RefCell;
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
                    eprintln!("{}", e);
                    return None
                },
                Ok(d) => String::from(d)
            }
            None => return None
        };

        let res = self.parser.parse(&line_raw);

        let item = match res {
            Err(e) => {
                eprintln!("{}", e.message());
                return None
            },
            Ok(i) => Some(i),
        };

        return item;
    }  
}

pub struct RefFile<R : Read> {
    parser: Rc<dyn HashLineFormatter>,
    line_iter: Rc<RefCell<std::io::Lines<io::BufReader<R>>>>
}

impl<R : Read> RefFile<R> {
    pub fn new(s: R, p: &Rc<dyn HashLineFormatter>) -> Self {
        return RefFile {
            parser: p.clone(),
            line_iter: Rc::new(RefCell::new(io::BufReader::new(s).lines()))
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