extern crate bcrypt;

use bcrypt::{hash};
use pbkdf2::{
    password_hash::{
        rand_core::OsRng,
        SaltString
    },
    Pbkdf2,
    Params,
    Algorithm::{
        Pbkdf2Sha256, Pbkdf2Sha512
    }
};
use std::time::Instant;

fn benchmark_bcrypt(cost: u32) -> u128 {
    let samples = 10;
    let mut total_time = 0;
    for _ in 1..samples {
        let now = Instant::now();
        {
            _ = hash("hunter2", cost);
        }
        let elapsed = now.elapsed();
        total_time += elapsed.as_millis();
    }
    return total_time / samples;
}

fn benchmark_pbkdf2(cost: u32) -> u128 {
    let samples = 10;
    let mut total_time = 0;
    let params = Params {
        rounds: cost,
        output_length: 32
    };
    for _ in 1..samples {
        let password = b"password";
        let salt = SaltString::generate(&mut OsRng);
        let mut hasher = Pbkdf2{};
        let now = Instant::now();
        {
            _ = hasher.hash_password_customized(password, None, None, Params::default(), &salt)
            // _ = Pbkdf2.hash_password_customized(password: &[u8], alg_id: Option<Ident<'a>>, version: Option<Decimal>, params: Params, salt: impl Into<Salt<'a>>)
        }
        let elapsed = now.elapsed();
        total_time += elapsed.as_millis();
    }
    return total_time / samples;
}

fn main() {
    let costs: [u32; 4] = [8, 10, 12, 15];
    for cost in costs.iter() {
        let time = benchmark_bcrypt(*cost);
        println!("{}, {} ms", cost, time);
    }
}
