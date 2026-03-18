use criterion::{Criterion, criterion_group, criterion_main};
use magic_cap::ImmutableBuilder;
use std::hint::black_box;
use std::io::Write;

fn encode(block_size: usize, num_bytes: usize) -> () {
    let mut plaintext = vec![0u8; num_bytes];
    getrandom::fill(&mut plaintext).unwrap();

    let mut ciphertext: Vec<u8> = vec![]; //vec![0u8; 4096];

    // create an encrypted immutable + associated ReadCap
    let mut cryptor = ImmutableBuilder::new(block_size, &mut ciphertext, None).unwrap();
    cryptor.write(&plaintext).unwrap();
    let (_cap, ciphertext) = cryptor.done().unwrap();
    assert!(ciphertext.len() > num_bytes);
}

fn criterion_benchmark(c: &mut Criterion) {
    c.bench_function("encode 1 MiB (4096)", |b| {
        b.iter(|| encode(black_box(4096), black_box(1 * 1024 * 1024)))
    });
    c.bench_function("encode 1 MiB (8192)", |b| {
        b.iter(|| encode(black_box(8192), black_box(1 * 1024 * 1024)))
    });
}

criterion_group!(benches, criterion_benchmark);
criterion_main!(benches);
