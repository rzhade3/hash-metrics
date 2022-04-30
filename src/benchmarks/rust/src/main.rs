extern crate bcrypt;

use bcrypt::{hash};
use std::time::Instant;

fn time_hash(cost: u32) -> u128 {
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

fn main() {
    let costs: [u32; 4] = [8, 10, 12, 15];
    for cost in costs.iter() {
        let time = time_hash(*cost);
        println!("{}, {} ms", cost, time);
    }
}
