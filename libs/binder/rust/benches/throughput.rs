/*
 * Copyright (C) 2020 The Android Open Source Project
 *
 * Licensed under the Apache License, Version 2.0 (the "License");
 * you may not use this file except in compliance with the License.
 * You may obtain a copy of the License at
 *
 *      http://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing, software
 * distributed under the License is distributed on an "AS IS" BASIS,
 * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 * See the License for the specific language governing permissions and
 * limitations under the License.
 */

//! Rust port of binderThroughputTest.cpp
//!
//! Measure the throughput of trivial, empty binder transaction between two
//! processes.

use binder::parcel::Parcel;
use binder::{
    declare_binder_interface, Binder, IBinder, Interface, ProcessState, SpIBinder, Status,
    StatusCode, TransactionCode,
};

use std::convert::TryInto;
use std::env;
use std::error::Error;
use std::fmt;
use std::io::{self, stdin, stdout, Read, Write};
use std::mem;
use std::process::{self, Child, Command, Stdio};
use std::time::Instant;

extern "C" {
    pub fn rand() -> std::os::raw::c_int;
    pub fn srand(seed: std::os::raw::c_uint);
}

const NUM_BUCKETS: u64 = 128;

static mut MAX_TIME_BUCKET: u64 = 50u64 * 1000000;
static mut TIME_PER_BUCKET: u64 = 50u64 * 1000000 / NUM_BUCKETS;

struct ProcResults {
    buckets: [u32; NUM_BUCKETS as usize],
    worst: u64,
    best: u64,
    transactions: u64,
    long_transactions: u64,
    total_time: u64,
}

impl ProcResults {
    fn new() -> Self {
        Self {
            buckets: [0; NUM_BUCKETS as usize],
            worst: 0,
            best: unsafe { MAX_TIME_BUCKET },
            transactions: 0,
            long_transactions: 0,
            total_time: 0,
        }
    }

    fn from_worker(worker: &mut Child) -> io::Result<Self> {
        let mut res = Self::new();
        let stdout = worker.stdout.as_mut().unwrap();
        for bucket in res.buckets.iter_mut() {
            let mut tmp = [0; 4];
            stdout.read_exact(&mut tmp)?;
            *bucket = u32::from_ne_bytes(tmp);
        }
        let mut tmp = [0; 8];
        stdout.read_exact(&mut tmp)?;
        res.worst = u64::from_ne_bytes(tmp);
        let mut tmp = [0; 8];
        stdout.read_exact(&mut tmp)?;
        res.best = u64::from_ne_bytes(tmp);
        let mut tmp = [0; 8];
        stdout.read_exact(&mut tmp)?;
        res.transactions = u64::from_ne_bytes(tmp);
        let mut tmp = [0; 8];
        stdout.read_exact(&mut tmp)?;
        res.long_transactions = u64::from_ne_bytes(tmp);
        let mut tmp = [0; 8];
        stdout.read_exact(&mut tmp)?;
        res.total_time = u64::from_ne_bytes(tmp);
        Ok(res)
    }

    fn write<W: Write>(&self, writer: &mut W) -> io::Result<()> {
        for bucket in self.buckets.iter() {
            writer.write_all(&bucket.to_ne_bytes())?;
        }
        writer.write_all(&self.worst.to_ne_bytes())?;
        writer.write_all(&self.best.to_ne_bytes())?;
        writer.write_all(&self.transactions.to_ne_bytes())?;
        writer.write_all(&self.long_transactions.to_ne_bytes())?;
        writer.write_all(&self.total_time.to_ne_bytes())?;
        writer.flush()
    }

    fn combine(mut self, other: &ProcResults) -> Self {
        self.buckets
            .iter_mut()
            .zip(other.buckets.iter())
            .for_each(|(bucket, other)| *bucket += other);
        Self {
            buckets: self.buckets,
            worst: self.worst.max(other.worst),
            best: self.best.min(other.best),
            transactions: self.transactions + other.transactions,
            long_transactions: self.long_transactions + other.long_transactions,
            total_time: self.total_time + other.total_time,
        }
    }

    fn add_time(&mut self, time: u64) {
        let max_time_bucket = unsafe { MAX_TIME_BUCKET };
        if time > max_time_bucket {
            self.long_transactions += 1;
        }
        let time_per_bucket = unsafe { TIME_PER_BUCKET };
        self.buckets[(NUM_BUCKETS as usize - 1).min((time / time_per_bucket) as usize)] += 1;
        self.best = time.min(self.best);
        self.worst = time.max(self.worst);
        self.transactions += 1;
        self.total_time += time;
    }
}

impl fmt::Display for ProcResults {
    fn fmt(&self, f: &mut fmt::Formatter) -> Result<(), fmt::Error> {
        if self.long_transactions > 0 {
            write!(
                f,
                "{}% of transactions took longer than estimated max latency. ",
                self.long_transactions as f64 / self.transactions as f64 * 100.0,
            )?;
            writeln!(
                f,
                "Consider setting -m to be higher than {} microseconds",
                self.worst / 1000,
            )?;
        }

        let best = self.best as f64 / 1.0E6;
        let worst = self.worst as f64 / 1.0E6;
        let average = self.total_time as f64 / self.transactions as f64 / 1.0E6;
        writeln!(
            f,
            "average: {}ms worst: {}ms best: {}ms",
            average, worst, best
        )?;

        let mut cur_total = 0u64;
        let time_per_bucket_ms = unsafe { TIME_PER_BUCKET } as f64 / 1.0E6;
        for (i, bucket) in self.buckets.iter().copied().enumerate() {
            let cur_time = time_per_bucket_ms * i as f64 + 0.5 * time_per_bucket_ms;
            let transactions = self.transactions as f64;
            let flast_total = cur_total as f64;
            let fnew_total = (cur_total + bucket as u64) as f64;
            if flast_total < 0.5 * transactions && fnew_total >= 0.5 * transactions {
                write!(f, "50%: {} ", cur_time)?;
            }
            if flast_total < 0.9 * transactions && fnew_total >= 0.9 * transactions {
                write!(f, "90%: {} ", cur_time)?;
            }
            if flast_total < 0.95 * transactions && fnew_total >= 0.95 * transactions {
                write!(f, "95%: {} ", cur_time)?;
            }
            if flast_total < 0.99 * transactions && fnew_total >= 0.99 * transactions {
                write!(f, "99%: {} ", cur_time)?;
            }
            cur_total += bucket as u64;
        }
        writeln!(f)
    }
}

/// Marker trait for binder workers
pub trait IBinderWorker: Interface {
    /// Peform a nop transaction with given payload size
    fn nop(&self, size: i32) -> Result<(), Status>;
}

struct BinderWorkerService;

impl Interface for BinderWorkerService {}
impl IBinderWorker for BinderWorkerService {
    fn nop(&self, _size: i32) -> Result<(), Status> {
        Ok(())
    }
}

impl BinderWorkerService {
    const BINDER_NOP: TransactionCode = SpIBinder::FIRST_CALL_TRANSACTION;
}

fn on_transact(
    _service: &dyn IBinderWorker,
    code: TransactionCode,
    _data: &Parcel,
    _reply: &mut Parcel,
) -> binder::Result<()> {
    match code {
        BinderWorkerService::BINDER_NOP => Ok(()),
        _ => Err(StatusCode::UNKNOWN_ERROR),
    }
}

declare_binder_interface! {
    IBinderWorker["BinderWorkerService"] {
        native: BnBinderWorker(on_transact),
        proxy: BpBinderWorker,
    }
}

impl IBinderWorker for BpBinderWorker {
    fn nop(&self, mut size: i32) -> Result<(), Status> {
        self.as_binder().transact(BinderWorkerService::BINDER_NOP, 0, |data| {
            while size >= mem::size_of::<u32>() as i32 {
                data.write(&0i32)?;
                size -= mem::size_of::<u32>() as i32;
            }
            Ok(())
        })?;
        Ok(())
    }
}
impl IBinderWorker for Binder<BnBinderWorker> {
    fn nop(&self, size: i32) -> Result<(), Status> {
        self.0.nop(size)
    }
}

fn signal<Out: Write>(out: &mut Out) {
    out.write_all(&[1u8]).unwrap();
    out.flush().unwrap();
}

fn wait<In: Read>(input: &mut In) {
    input.read_exact(&mut [0; 1]).unwrap()
}

trait Pipe {
    fn signal(&mut self);

    fn wait(&mut self);
}

impl Pipe for Child {
    fn signal(&mut self) {
        signal(self.stdin.as_mut().unwrap())
    }

    fn wait(&mut self) {
        wait(self.stdout.as_mut().unwrap())
    }
}

impl Pipe for [Child] {
    fn signal(&mut self) {
        self.iter_mut().for_each(|child| Pipe::signal(child));
    }

    fn wait(&mut self) {
        self.iter_mut().for_each(|child| Pipe::wait(child));
    }
}

fn generate_service_name(num: i32) -> String {
    format!("binderWorker{}", num)
}

fn worker_fx(num: i32, worker_count: i32, iterations: i32, payload_size: i32, cs_pair: bool) {
    ProcessState::start_thread_pool();
    let binder_native = BnBinderWorker::new_binder(BinderWorkerService);
    binder::add_service(&generate_service_name(num), binder_native.as_binder()).unwrap();

    let mut stdout = stdout();
    let mut stdin = stdin();

    unsafe { srand(num as u32) };
    signal(&mut stdout);
    wait(&mut stdin);

    // If client/server pairs, then half the workers are
    // servers and half are clients
    let server_count = if cs_pair {
        worker_count / 2
    } else {
        worker_count
    };

    // Get references to other binder services.
    eprintln!("Created BinderWorker{}", num);
    let mut workers = vec![];
    for i in 0..server_count {
        if num != i {
            let service: Box<dyn IBinderWorker> =
                binder::get_interface(&generate_service_name(i)).unwrap();
            workers.push(service);
        }
    }

    let mut start = libc::timespec {
        tv_sec: 0,
        tv_nsec: 0,
    };
    let mut end = libc::timespec {
        tv_sec: 0,
        tv_nsec: 0,
    };

    // Run the benchmark if client
    let mut results = ProcResults::new();
    for i in 0..iterations {
        let target = if cs_pair {
            (num % server_count) as usize
        } else {
            (unsafe { rand() }) as usize % workers.len()
        };

        // We are going out of our way here to make sure we use the same timing
        // measurement mechanism as the C++ benchmark so that our results are
        // directly comparable. std::time::Instant:::now uses global state and a
        // lock to ensure monotonically increasing time, whereas the C++
        // benchmark uses chrono::high_resolution_clock which has no such
        // overhead or guarantees.
        unsafe {
            libc::clock_gettime(libc::CLOCK_REALTIME, &mut start);
        }
        let reply = workers[target].nop(payload_size);
        unsafe {
            libc::clock_gettime(libc::CLOCK_REALTIME, &mut end);
        }
        let nanoseconds =
            (end.tv_sec - start.tv_sec) * 1_000_000_000 + (end.tv_nsec - start.tv_nsec);
        results.add_time(nanoseconds as u64);

        if let Err(e) = reply {
            eprintln!("thread {} failed {} i : {}", num, e, i);
            process::exit(1);
        }
    }

    // Signal completion to master and wait.
    signal(&mut stdout);
    wait(&mut stdin);

    // Send results to master and wait for go to exit.
    results.write(&mut stdout).expect("Failed to write results");
    wait(&mut stdin);

    process::exit(0);
}

fn run_main(
    iterations: i32,
    worker_count: i32,
    payload_size: i32,
    cs_pair: bool,
    training_round: bool,
) {
    let mut workers = Vec::with_capacity(worker_count.try_into().unwrap());
    // Create all the workers and wait for them to spawn.
    for i in 0..worker_count {
        workers.push(
            Command::new(env::current_exe().unwrap())
                .env("RUST_BACKTRACE", "1")
                .arg("--worker")
                .arg(i.to_string())
                .arg(iterations.to_string())
                .arg(worker_count.to_string())
                .arg(payload_size.to_string())
                .arg(cs_pair.to_string())
                .arg(unsafe { MAX_TIME_BUCKET }.to_string())
                .stdin(Stdio::piped())
                .stdout(Stdio::piped())
                .spawn()
                .expect("Worker failed to start"),
        );
    }
    workers.wait();

    // Run the workers and wait for completion.
    println!("waiting for workers to complete");
    let start = Instant::now();
    workers.signal();
    workers.wait();
    let duration = start.elapsed();

    let iterations_per_sec =
        (iterations * worker_count) as f64 / (duration.as_nanos() as f64 / 1.0E9);
    println!("iterations per sec: {}", iterations_per_sec);

    // Collect all results from the workers.
    println!("collecting results");
    workers.signal();
    let mut tot_results = ProcResults::new();
    for worker in workers.iter_mut() {
        let new_results =
            ProcResults::from_worker(worker).expect("Could not read results from worker");
        tot_results = ProcResults::combine(tot_results, &new_results);
    }

    // Kill all the workers.
    println!("killing workers");
    workers.signal();
    for worker in workers.iter_mut() {
        let status = worker.wait().expect("Worker wasn't running");
        if !status.success() {
            println!("nonzero worker status {}", status.code().unwrap());
        }
    }

    if training_round {
        // sets max_time_bucket to 2 * m_worst from the training round.
        // Also needs to adjust time_per_bucket accordingly.
        println!(
            "Max latency during training: {}ms",
            tot_results.worst as f64 / 1.0E6
        );
        unsafe {
            MAX_TIME_BUCKET = 2 * tot_results.worst;
            TIME_PER_BUCKET = 2 * tot_results.worst / NUM_BUCKETS;
        }
    } else {
        println!("{}", tot_results);
    }
}

fn main() -> Result<(), Box<dyn Error>> {
    let mut workers = 2;
    let mut iterations = 10000;
    let mut payload_size = 0;
    let mut cs_pair = false;
    let mut training_round = false;

    let args: Vec<_> = env::args().collect();

    if args.len() > 1 && args[1] == "--worker" {
        let num = args[2].parse().unwrap();
        let iterations = args[3].parse().unwrap();
        let worker_count = args[4].parse().unwrap();
        let payload_size = args[5].parse().unwrap();
        let cs_pair = args[6].parse().unwrap();
        let max_time_bucket = args[7].parse().unwrap();
        unsafe {
            MAX_TIME_BUCKET = max_time_bucket;
            TIME_PER_BUCKET = max_time_bucket / NUM_BUCKETS;
        }
        worker_fx(
            num,
            worker_count,
            iterations,
            payload_size,
            cs_pair,
        );
        return Ok(());
    }

    for i in 1..args.len() {
        match args[i].as_str() {
            "--help" => {
                println!("Usage: binderThroughputTest [OPTIONS]");
                println!("\t-i N    : Specify number of iterations.");
                println!("\t-m N    : Specify expected max latency in microseconds.");
                println!("\t-p      : Split workers into client/server pairs.");
                println!("\t-s N    : Specify payload size.");
                println!("\t-t N    : Run training round.");
                println!("\t-w N    : Specify total number of workers.");
                return Ok(());
            }
            "-w" => {
                workers = args[i + 1].parse().unwrap();
            }
            "-i" => {
                iterations = args[i + 1].parse().unwrap();
            }
            "-s" => {
                payload_size = args[i + 1].parse().unwrap();
            }
            "-p" => {
                // client/server pairs instead of spreading
                // requests to all workers. If true, half
                // the workers become clients and half servers
                cs_pair = true;
            }
            "-t" => {
                // Run one training round before actually collecting data
                // to get an approximation of max latency.
                training_round = true;
            }
            "-m" => {
                // Caller specified the max latency in microseconds.
                // No need to run training round in this case.
                let max_time: u64 = args[i + 1].parse().unwrap();
                unsafe {
                    MAX_TIME_BUCKET = max_time * 1000;
                    TIME_PER_BUCKET = max_time * 1000 / NUM_BUCKETS;
                }
            }
            _ => {}
        }
    }

    if training_round {
        println!("Start training round");
        run_main(iterations, workers, payload_size, cs_pair, true);
        println!("Completed training round\n");
    }

    run_main(iterations, workers, payload_size, cs_pair, false);

    Ok(())
}
