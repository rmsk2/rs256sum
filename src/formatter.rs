use regex::Regex;

pub trait HashLineFormatter {
    fn format(&self, hash: &String, file_name: &String) -> String;
    fn parse(&self, hash_line: &String) -> Result<(String, String), ParseError>; // (file_name, hash)
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

pub struct BsdFormatter {
    algo_name: String,
    exp: regex::Regex
}

impl BsdFormatter {
    #[allow(dead_code)]
    pub fn from_str(name: &str) -> BsdFormatter {
        let n = String::from(name);

        return BsdFormatter::new(&n);
    }

    pub fn new(name: &String) -> BsdFormatter {
        let exp_str = format!("^{} \\((.*)\\) = ([A-Fa-f0-9]+)$", name);

        return BsdFormatter {
            algo_name: name.clone(),
            exp: Regex::new(&exp_str).unwrap()
        }
    }
}

impl HashLineFormatter for BsdFormatter {
    fn format(&self, hash: &String, file_name: &String) -> String {
        return format!("{} ({}) = {}", self.algo_name, file_name, hash);
    }

    fn parse(&self, hash_line: &String) -> Result<(String, String), ParseError> {
        let matches: Vec<regex::Captures> = self.exp.captures_iter(hash_line).collect();

        if matches.len() != 1 {
            return Err(ParseError::FormatError(hash_line.clone()));
        }

        let groups = &matches[0];
        let hash_val = &groups[2];
        let file_name = &groups[1];

        return Ok((String::from(file_name.trim()), String::from(hash_val)));
    }     
}

