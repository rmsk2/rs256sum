use regex::Regex;

pub trait HashLineFormatter {
    fn format(&self, hash: &String, file_name: &String) -> String;
}

pub enum ParseError {
    FormatError(String),
}

impl ParseError {
    pub fn message(&self) -> String {
        match self {
            ParseError::FormatError(line) => format!("Input line '{}' has wrong format", line),
        }
    }
} 

pub trait HashLineParser {
    fn parse(&self, hash_line: &String) -> Result<(String, String), ParseError>; // (file_name, hash)
}

pub struct SimpleFormatter {
    exp : regex::Regex
}

impl SimpleFormatter {
    pub fn new() -> SimpleFormatter {
        return SimpleFormatter {
            exp: Regex::new(r"^([A-Fa-f0-9]+)  (.*)$").unwrap()
        }
    }
}

impl HashLineFormatter for SimpleFormatter {
    fn format(&self, hash: &String, file_name: &String) -> String {
        return format!("{}  {}", hash, file_name);
    }
}

impl HashLineParser for SimpleFormatter {
    fn parse(&self, hash_line: &String) -> Result<(String, String), ParseError> {
        let matches: Vec<regex::Captures> = self.exp.captures_iter(hash_line).collect();

        if matches.len() != 1 {
            return Err(ParseError::FormatError(hash_line.clone()));
        }

        let groups = &matches[0];
        let hash_val = &groups[1];
        let file_name = &groups[2];

        return Ok((String::from(file_name.trim()), String::from(hash_val)));
    }
}

// struct BsdFormatter {
//     algo_name: String
// }

// impl BsdFormatter {
//     fn new(name: &str) -> BsdFormatter {
//         return BsdFormatter {
//             algo_name: String::from(name)
//         }
//     }
// }

// impl HashLineFormatter for BsdFormatter {
//     fn format(&self, hash: &String, file_name: &String) -> String {
//         return format!("{} ({}) = {}", self.algo_name, file_name, hash);
//     }
// }
