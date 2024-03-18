use rand::{rngs::StdRng, SeedableRng};
use base64::{prelude::BASE64_STANDARD, Engine};
use ark_serialize::CanonicalSerialize;
use std::io;
use std::io::BufRead;
use std::fs;

mod signature;
use signature::*;

fn main() {
    let key = Key::generate(&mut StdRng::from_entropy());
    let pk = key.public_key();

    let mut key_bytes = Vec::new();
    pk.public_key().serialize(&mut key_bytes).unwrap();
    println!("My public key: {}", BASE64_STANDARD.encode(&key_bytes));

    //println!("{}", BASE64_STANDARD.encode(&serde_bare::to_vec(&key.sign(b"Give me the flag!")).unwrap()));

    let mut r = io::BufReader::new(io::stdin());
    for _ in 0..10 {
        println!("Please sign a message.");

        println!("Message:");
        let mut msg = String::new();
        r.read_line(&mut msg).unwrap();
        let msg = msg.trim_end();

        println!("Signature:");
        let mut signature = String::new();
        r.read_line(&mut signature).unwrap();
        let signature = signature.trim_end();

        let signature = serde_bare::from_slice(&BASE64_STANDARD.decode(&signature).unwrap()).unwrap();
        if pk.verify(msg.as_bytes(), signature).is_some() {
            println!("Signature for message \"{}\" verified.", msg);

            if msg == "Give me the flag!" {
                println!("Here is your flag: {}", fs::read_to_string("flag").unwrap());
                break;
            }
        } else {
            println!("Signature for message \"{}\" failed to verify.", msg);
        }
    }
}
