use criterion::{criterion_group, criterion_main, Criterion};
use teddybear_status_list::StatusList;

fn encode_and_decode(c: &mut Criterion) {
    c.bench_function("one issue", |b| {
        b.iter(|| {
            let mut list = StatusList::default();
            list.set_random();
            let encoded = list.encode();
            StatusList::decode(&encoded).unwrap();
        })
    });

    c.bench_function("ten issues", |b| {
        b.iter(|| {
            let mut list = StatusList::default();

            for _ in 0..10 {
                list.set_random();
            }

            let encoded = list.encode();
            StatusList::decode(&encoded).unwrap();
        })
    });

    c.bench_function("one million issues", |b| {
        b.iter(|| {
            let mut list = StatusList::default();

            for _ in 0..1_000_000 {
                list.set_random();
            }

            let encoded = list.encode();
            StatusList::decode(&encoded).unwrap();
        })
    });
}

criterion_group!(list, encode_and_decode);
criterion_main!(list);
