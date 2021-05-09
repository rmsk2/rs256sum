#[cfg(test)]
use crate::hasher::*;
#[cfg(test)]
use crypto::sha2::Sha256;
#[cfg(test)]
use crate::formatter::*;
#[cfg(test)]
use crypto::digest::Digest;
#[cfg(test)]
use std::rc::Rc;
#[cfg(test)]
use std::cell::RefCell;
#[cfg(test)]
use crate::reffile::*;
#[cfg(test)]
use crate::*;


#[test]
fn try_error_messages() {
    assert_eq!(HashError::GenericError.message(), "Operation failed".to_string());
    assert_eq!(HashError::FileOpenError("test_file.txt".to_string()).message(), "Error opening file 'test_file.txt'");
    assert_eq!(HashError::HashVerifyFail("test_file.txt".to_string()).message(), "Hash verification for file 'test_file.txt' failed");
    assert_eq!(HashError::Ok.message(), "OK");
    assert_eq!(HashError::HashDifferent.message(), "Hashes different");
}

#[test]
fn test_sha256_hash_reference_values() {
    let mut h = Hasher::new("SHA-256", Box::new(Sha256::new()));
    let mut ref_data = "abc".as_bytes();
    let mut empty = "".as_bytes();
    let mut a_million_a: Vec<u8> = vec![97; 1000000];

    match h.hash_data(&mut ref_data) {
        Ok(ref_val) => assert_eq!(ref_val, "ba7816bf8f01cfea414140de5dae2223b00361a396177a9cb410ff61f20015ad"),
        _ => panic!("SHA256 hashing failed")
    };

    ref_data = "abc".as_bytes();

    let mut h_res = h.verify_data(&mut ref_data, &"ba7816bf8f01cfea414140de5dae2223b00361a396177a9cb410ff61f20015ad".to_string());
    match h_res {
        HashError::Ok => {},
        _ => {
            println!("{}", h_res.message());
            panic!("Verification failed");
        }
    };

    match h.hash_data(&mut empty) {
        Ok(ref_val) => assert_eq!(ref_val, "e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855"),
        _ => panic!("SHA256 hashing failed")
    };
    
    match h.hash_data(&mut a_million_a.as_slice()) {
        Ok(ref_val) => assert_eq!(ref_val, "cdc76e5c9914fb9281a1c7e284d73e67f1809a48a497200e046d39ccc7112cd0"),
        _ => panic!("SHA256 hashing failed")
    }; 
    
    a_million_a = vec![97; 1000000];

    h_res = h.verify_data(&mut a_million_a.as_slice(), &"cdc76e5c9914fb9281a1c7e284d73e67f1809a48a497200e046d39ccc7112cd0".to_string());
    match h_res {
        HashError::Ok => {},
        _ => {
            println!("{}", h_res.message());
            panic!("Verification failed");
        }
    };        
}

#[test]
fn simple_format_test() {
    let formatter = SimpleFormatter::new();

    let mut test_line = String::from("abcdef0123456789  data.txt");

    let data = match formatter.parse(&test_line) {
        Ok(res) => res,
        Err(e) => {
            println!("{}", e.message());
            panic!("SimpleFormatter test failed")
        }
    };

    assert_eq!(data.1, "abcdef0123456789");
    assert_eq!(data.0, "data.txt");

    test_line = String::from("abcdef0123456789                data.txt");

    let data = match formatter.parse(&test_line) {
        Ok(res) => res,
        Err(e) => {
            println!("{}", e.message());
            panic!("SimpleFormatter test failed")
        }
    };

    assert_eq!(data.1, "abcdef0123456789");
    assert_eq!(data.0, "data.txt");    

    test_line = String::from("abcdef012345678 data.txt");

    match formatter.parse(&test_line) {
        Ok(_) => panic!("SimpleFormatter test failed. The line was mismatched"),
        Err(_) => {}
    };    

    test_line = String::from("abcdef012345678G  data.txt");

    match formatter.parse(&test_line) {
        Ok(_) => panic!("SimpleFormatter test failed. The line was mismatched"),
        Err(_) => {}
    }; 

    test_line = String::from("abcdef01234567");

    match formatter.parse(&test_line) {
        Ok(_) => panic!("SimpleFormatter test failed. The line was mismatched"),
        Err(_) => {}
    }; 
}

#[test]
fn bsd_parser_test() {
    let p = BsdFormatter::from_str(ALGO_SHA256);

    let mut test_line = String::from("SHA256 (data.txt) = abcdef0123456789");

    let mut data = match p.parse(&test_line) {
        Ok(res) => res,
        Err(e) => {
            println!("{}", e.message());
            panic!("BsdFormatter test failed")
        }
    }; 
    
    assert_eq!(data.0, "data.txt");
    assert_eq!(data.1, "abcdef0123456789");

    test_line = String::from("SHA256 ((data .txt)) = abcdef0123456789");

    data = match p.parse(&test_line) {
        Ok(res) => res,
        Err(e) => {
            println!("{}", e.message());
            panic!("BsdFormatter test failed")
        }
    }; 
    
    assert_eq!(data.0, "(data .txt)");
    assert_eq!(data.1, "abcdef0123456789");    
}

#[test]
fn iterator_test() {
    let data = String::from("111111  dateia\n222222  dateib\n");
    let hash: Box<dyn Digest> = Box::new(Sha256::new());
    let algo_name = ALGO_SHA256;
    
    let h: Rc<RefCell<dyn FileHash>> = Rc::new(RefCell::new(Hasher::new(algo_name, hash)));
    let f: Rc<dyn HashLineFormatter> = Rc::new(SimpleFormatter::new());
    let ref_data = RefFile::new(data.as_bytes(), &h, &f);
    let res: Vec<(String, String)> = ref_data.into_iter().collect();

    assert_eq!(res.len(), 2);
    assert_eq!(res[0].1, "111111");
    assert_eq!(res[0].0, "dateia");
    assert_eq!(res[1].1, "222222");
    assert_eq!(res[1].0, "dateib");
}
#[test]
fn iterator_bsd_test() {
    let data = String::from("SHA256 (dateia) = 111111\nSHA256 (dateib) = 222222\n");
    let hash: Box<dyn Digest> = Box::new(Sha256::new());
    let algo_name = ALGO_SHA256;
    
    let h: Rc<RefCell<dyn FileHash>> = Rc::new(RefCell::new(Hasher::new(algo_name, hash)));
    let f: Rc<dyn HashLineFormatter> = Rc::new(BsdFormatter::new(&h.borrow().get_algo()));
    let ref_data = RefFile::new(data.as_bytes(), &h, &f);
    let res: Vec<(String, String)> = ref_data.into_iter().collect();

    assert_eq!(res.len(), 2);
    assert_eq!(res[0].1, "111111");
    assert_eq!(res[0].0, "dateia");
    assert_eq!(res[1].1, "222222");
    assert_eq!(res[1].0, "dateib");
}