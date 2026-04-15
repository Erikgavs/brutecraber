use crate::backend::CrackingBackend;
use crate::cpu_backend::CpuBackend;
use colored::Colorize;
use indicatif::{ProgressBar, ProgressStyle};
use opencl3::command_queue::{CL_QUEUE_PROFILING_ENABLE, CommandQueue};
use opencl3::context::Context;
use opencl3::device::{CL_DEVICE_TYPE_GPU, Device, get_all_devices};
use opencl3::kernel::{ExecuteKernel, Kernel};
use opencl3::memory::{Buffer, CL_MEM_READ_ONLY, CL_MEM_WRITE_ONLY};
use opencl3::program::Program;
use opencl3::types::{CL_BLOCKING, CL_NON_BLOCKING, cl_event};
use std::ptr;
use std::time::Instant;

const MD5_KERNEL_SOURCE: &str = include_str!("kernels/md5.cl");
const SHA1_KERNEL_SOURCE: &str = include_str!("kernels/sha1.cl");
const SHA256_KERNEL_SOURCE: &str = include_str!("kernels/sha256.cl");
const SHA512_KERNEL_SOURCE: &str = include_str!("kernels/sha512.cl");
const SHA3_256_KERNEL_SOURCE: &str = include_str!("kernels/sha3_256.cl");
const SHA3_512_KERNEL_SOURCE: &str = include_str!("kernels/sha3_512.cl");
const NTLM_KERNEL_SOURCE: &str = include_str!("kernels/ntlm.cl");

pub const GPU_SUPPORTED_HEX_TYPES: &[&str] = &[
    "md5", "sha1", "sha256", "sha512", "sha3-256", "sha3-512", "ntlm",
];

pub fn supports(hash_type: &str) -> bool {
    GPU_SUPPORTED_HEX_TYPES.contains(&hash_type)
}

pub struct GpuBackend {
    device: Device,
    context: Context,
    queue: CommandQueue,
}

impl GpuBackend {
    pub fn new() -> Result<Self, String> {
        let device_ids = get_all_devices(CL_DEVICE_TYPE_GPU)
            .map_err(|e| format!("Failed to query GPU devices: {e}"))?;

        if device_ids.is_empty() {
            return Err("No GPU devices found. Remove --gpu flag to use CPU mode.".to_string());
        }

        // Select GPU with the most compute units
        let mut best_id = device_ids[0];
        let mut best_cu: u32 = 0;

        for &did in &device_ids {
            let dev = Device::new(did);
            if let Ok(cu) = dev.max_compute_units()
                && cu > best_cu
            {
                best_cu = cu;
                best_id = did;
            }
        }

        let device = Device::new(best_id);
        let context = Context::from_device(&device)
            .map_err(|e| format!("Failed to create OpenCL context: {e}"))?;
        let queue = CommandQueue::create_default(&context, CL_QUEUE_PROFILING_ENABLE)
            .map_err(|e| format!("Failed to create command queue: {e}"))?;

        Ok(Self {
            device,
            context,
            queue,
        })
    }

    pub fn print_device_info(&self) {
        let name = self.device.name().unwrap_or_else(|_| "Unknown".into());
        let cu = self.device.max_compute_units().unwrap_or(0);
        let mem_bytes = self.device.global_mem_size().unwrap_or(0);
        let mem_mb = mem_bytes / (1024 * 1024);

        println!(
            "{} GPU: {} | VRAM: {} MB | Compute Units: {}\n",
            "[*]".green(),
            name.trim().yellow(),
            mem_mb,
            cu
        );
    }

    fn gpu_mem_bytes(&self) -> u64 {
        self.device.global_mem_size().unwrap_or(256 * 1024 * 1024)
    }

    /// Generic hash cracking method that works for any algorithm.
    /// All GPU-supported algorithms share the same kernel interface.
    #[allow(clippy::too_many_arguments)]
    fn crack_hash(
        &self,
        hashes: &[&str],
        wordlist: &str,
        kernel_source: &str,
        kernel_fn_name: &str,
        hex_len: usize,
        digest_size: usize,
        algo_name: &str,
    ) -> usize {
        // Parse target hashes from hex to bytes
        let target_bytes: Vec<Vec<u8>> = hashes
            .iter()
            .filter_map(|h| {
                if h.len() != hex_len {
                    return None;
                }
                let mut bytes = vec![0u8; digest_size];
                faster_hex::hex_decode(h.as_bytes(), &mut bytes).ok()?;
                Some(bytes)
            })
            .collect();

        if target_bytes.is_empty() {
            println!("{} No valid {} hex hashes found", "[!]".red(), algo_name);
            return 0;
        }

        // Flatten targets for GPU upload (contiguous digest_size-byte blocks)
        let target_flat: Vec<u8> = target_bytes
            .iter()
            .flat_map(|h| h.iter().copied())
            .collect();
        let num_targets = target_bytes.len() as u32;

        // Build OpenCL program + kernel
        let program = match Program::create_and_build_from_source(&self.context, kernel_source, "")
        {
            Ok(p) => p,
            Err(e) => {
                println!(
                    "{} Failed to build {} OpenCL kernel: {e}",
                    "[!]".red(),
                    algo_name
                );
                return 0;
            }
        };

        let kernel = match Kernel::create(&program, kernel_fn_name) {
            Ok(k) => k,
            Err(e) => {
                println!("{} Failed to create kernel: {e}", "[!]".red());
                return 0;
            }
        };

        // Collect words from wordlist
        let words: Vec<&str> = wordlist.lines().collect();
        let total_words = words.len();
        if total_words == 0 {
            return 0;
        }

        // Calculate batch size based on GPU VRAM
        let usable_mem = (self.gpu_mem_bytes() as f64 * 0.70) as usize;
        let target_mem = target_flat.len() + 64;
        let available = usable_mem.saturating_sub(target_mem);
        // Per word: ~avg_word_len bytes data + 4 (offset) + 4 (length) + 4 (result)
        let per_word_estimate: usize = 16 + 4 + 4 + 4;
        let batch_size = (available / per_word_estimate).max(1024).min(total_words);

        // Progress bar
        let bar = ProgressBar::new(total_words as u64);
        bar.set_style(
            ProgressStyle::default_bar()
                .template("\n[{elapsed_precise}] [{bar:40}] {pos}/{len} ({percent}%) {msg}\n")
                .unwrap()
                .progress_chars("=> "),
        );

        let mut found = 0usize;
        let start_time = Instant::now();

        // Process wordlist in VRAM-aware batches
        for batch_start in (0..total_words).step_by(batch_size) {
            let batch_end = (batch_start + batch_size).min(total_words);
            let batch = &words[batch_start..batch_end];

            // Flatten word data for GPU
            let mut words_data: Vec<u8> = Vec::new();
            let mut offsets: Vec<u32> = Vec::with_capacity(batch.len());
            let mut lengths: Vec<u32> = Vec::with_capacity(batch.len());

            for word in batch {
                offsets.push(words_data.len() as u32);
                lengths.push(word.len() as u32);
                words_data.extend_from_slice(word.as_bytes());
            }

            // OpenCL buffers cannot be zero-sized
            if words_data.is_empty() {
                words_data.push(0);
            }

            match self.execute_hash_batch(
                &kernel,
                &words_data,
                &offsets,
                &lengths,
                batch.len(),
                &target_flat,
                num_targets,
            ) {
                Ok(results) => {
                    for (i, &r) in results.iter().enumerate() {
                        if r != 0xFFFFFFFF {
                            let tidx = r as usize;
                            if tidx < target_bytes.len() {
                                let hex: String = target_bytes[tidx]
                                    .iter()
                                    .map(|b| format!("{:02x}", b))
                                    .collect();
                                bar.println(format!(
                                    "{} hash cracked {} -> {}",
                                    "[*]".green(),
                                    hex,
                                    batch[i]
                                ));
                                found += 1;
                            }
                        }
                    }
                }
                Err(e) => {
                    bar.println(format!("{} GPU batch error: {e}", "[!]".red()));
                }
            }

            bar.inc(batch.len() as u64);

            // Update hash rate in progress bar
            let elapsed = start_time.elapsed().as_secs_f64();
            if elapsed > 0.0 {
                let hps = bar.position() as f64 / elapsed;
                if hps >= 1_000_000.0 {
                    bar.set_message(format!("{:.2} MH/s", hps / 1_000_000.0));
                } else if hps >= 1_000.0 {
                    bar.set_message(format!("{:.2} KH/s", hps / 1_000.0));
                } else {
                    bar.set_message(format!("{:.2} H/s", hps));
                }
            }
        }

        bar.finish();
        found
    }

    /// Generic GPU batch execution — kernel interface is the same for all algorithms.
    #[allow(clippy::too_many_arguments)]
    fn execute_hash_batch(
        &self,
        kernel: &Kernel,
        words_data: &[u8],
        offsets: &[u32],
        lengths: &[u32],
        num_words: usize,
        target_flat: &[u8],
        num_targets: u32,
    ) -> Result<Vec<u32>, String> {
        let err = |e: opencl3::error_codes::ClError| format!("OpenCL error: {e}");

        unsafe {
            // Allocate device buffers
            let mut words_buf = Buffer::<u8>::create(
                &self.context,
                CL_MEM_READ_ONLY,
                words_data.len(),
                ptr::null_mut(),
            )
            .map_err(&err)?;
            let mut offsets_buf = Buffer::<u32>::create(
                &self.context,
                CL_MEM_READ_ONLY,
                offsets.len(),
                ptr::null_mut(),
            )
            .map_err(&err)?;
            let mut lengths_buf = Buffer::<u32>::create(
                &self.context,
                CL_MEM_READ_ONLY,
                lengths.len(),
                ptr::null_mut(),
            )
            .map_err(&err)?;
            let mut targets_buf = Buffer::<u8>::create(
                &self.context,
                CL_MEM_READ_ONLY,
                target_flat.len(),
                ptr::null_mut(),
            )
            .map_err(&err)?;
            let results_buf =
                Buffer::<u32>::create(&self.context, CL_MEM_WRITE_ONLY, num_words, ptr::null_mut())
                    .map_err(&err)?;

            // Upload data to GPU (blocking, in-order queue)
            self.queue
                .enqueue_write_buffer(&mut words_buf, CL_BLOCKING, 0, words_data, &[])
                .map_err(&err)?;
            self.queue
                .enqueue_write_buffer(&mut offsets_buf, CL_BLOCKING, 0, offsets, &[])
                .map_err(&err)?;
            self.queue
                .enqueue_write_buffer(&mut lengths_buf, CL_BLOCKING, 0, lengths, &[])
                .map_err(&err)?;
            self.queue
                .enqueue_write_buffer(&mut targets_buf, CL_BLOCKING, 0, target_flat, &[])
                .map_err(&err)?;

            // Dispatch kernel (1 work-item per word)
            let num_words_arg = num_words as u32;
            let kernel_event = ExecuteKernel::new(kernel)
                .set_arg(&words_buf)
                .set_arg(&offsets_buf)
                .set_arg(&lengths_buf)
                .set_arg(&num_words_arg)
                .set_arg(&targets_buf)
                .set_arg(&num_targets)
                .set_arg(&results_buf)
                .set_global_work_size(num_words)
                .enqueue_nd_range(&self.queue)
                .map_err(&err)?;

            // Read results back (blocking read waits for in-order kernel completion)
            let mut results = vec![0xFFFFFFFFu32; num_words];
            let events: Vec<cl_event> = vec![kernel_event.get()];
            let read_event = self
                .queue
                .enqueue_read_buffer(&results_buf, CL_NON_BLOCKING, 0, &mut results, &events)
                .map_err(&err)?;
            read_event.wait().map_err(&err)?;

            Ok(results)
        }
    }

    /// Benchmark a single algorithm on GPU. Returns (word_count, duration) if successful.
    pub fn benchmark_algorithm(
        &self,
        algo: &str,
        word_count: usize,
    ) -> Option<std::time::Duration> {
        let (kernel_source, kernel_fn, digest_size) = match algo {
            "md5" => (MD5_KERNEL_SOURCE, "md5_crack", 16),
            "sha1" => (SHA1_KERNEL_SOURCE, "sha1_crack", 20),
            "sha256" => (SHA256_KERNEL_SOURCE, "sha256_crack", 32),
            "sha512" => (SHA512_KERNEL_SOURCE, "sha512_crack", 64),
            "sha3-256" => (SHA3_256_KERNEL_SOURCE, "sha3_256_crack", 32),
            "sha3-512" => (SHA3_512_KERNEL_SOURCE, "sha3_512_crack", 64),
            "ntlm" => (NTLM_KERNEL_SOURCE, "ntlm_crack", 16),
            _ => return None,
        };

        let program =
            Program::create_and_build_from_source(&self.context, kernel_source, "").ok()?;
        let kernel = Kernel::create(&program, kernel_fn).ok()?;

        // Generate test words (same word repeated — kernel doesn't branch on content)
        let test_word = b"benchmark_password";
        let mut words_data: Vec<u8> = Vec::with_capacity(test_word.len() * word_count);
        let mut offsets: Vec<u32> = Vec::with_capacity(word_count);
        let mut lengths: Vec<u32> = Vec::with_capacity(word_count);
        for _ in 0..word_count {
            offsets.push(words_data.len() as u32);
            lengths.push(test_word.len() as u32);
            words_data.extend_from_slice(test_word);
        }

        // Dummy non-matching target hash (all zeros)
        let target_flat: Vec<u8> = vec![0u8; digest_size];
        let num_targets = 1u32;

        // VRAM-aware batching
        let usable_mem = (self.gpu_mem_bytes() as f64 * 0.70) as usize;
        let target_mem = target_flat.len() + 64;
        let available = usable_mem.saturating_sub(target_mem);
        let per_word_estimate: usize = 16 + 4 + 4 + 4;
        let batch_size = (available / per_word_estimate).max(1024).min(word_count);

        let start = Instant::now();

        for batch_start in (0..word_count).step_by(batch_size) {
            let batch_end = (batch_start + batch_size).min(word_count);
            let batch_offsets = &offsets[batch_start..batch_end];
            let batch_lengths = &lengths[batch_start..batch_end];
            let batch_len = batch_end - batch_start;

            // Compute data slice for this batch
            let data_start = offsets[batch_start] as usize;
            let data_end = if batch_end < word_count {
                offsets[batch_end] as usize
            } else {
                words_data.len()
            };
            let batch_data = &words_data[data_start..data_end];

            // Adjust offsets to be relative to batch_data start
            let base_offset = offsets[batch_start];
            let adj_offsets: Vec<u32> = batch_offsets.iter().map(|o| o - base_offset).collect();

            let _ = self.execute_hash_batch(
                &kernel,
                batch_data,
                &adj_offsets,
                batch_lengths,
                batch_len,
                &target_flat,
                num_targets,
            );
        }

        Some(start.elapsed())
    }
}

impl CrackingBackend for GpuBackend {
    fn run(&self, hashes: &[&str], wordlist: &str, hash_type: &str, rule: bool) -> usize {
        // Memory-hard algorithms: not suited for GPU
        if hash_type == "bcrypt" {
            println!(
                " {} bcrypt is a memory-hard algorithm not suited for GPU acceleration. Falling back to CPU.",
                "[!]".yellow()
            );
            return CpuBackend.run(hashes, wordlist, hash_type, rule);
        }

        if hash_type == "argon2" {
            println!(
                " {} argon2 is a memory-hard algorithm not suited for GPU acceleration. Falling back to CPU.",
                "[!]".yellow()
            );
            return CpuBackend.run(hashes, wordlist, hash_type, rule);
        }

        // Base64 encoded types: GPU supports hex only
        if hash_type.ends_with("-base64") {
            println!(
                " {} GPU acceleration currently supports hex encoding only. '{}' uses base64. Falling back to CPU.",
                "[!]".yellow(),
                hash_type
            );
            return CpuBackend.run(hashes, wordlist, hash_type, rule);
        }

        // Salted types: not yet supported on GPU
        if hash_type.ends_with("-salt") {
            println!(
                " {} GPU acceleration does not yet support salted hashes. Falling back to CPU.",
                "[!]".yellow()
            );
            return CpuBackend.run(hashes, wordlist, hash_type, rule);
        }

        // Unsupported hex type (check before dual-mode, since dual-mode components are supported)
        let is_dual_mode = hash_type == "sha256/sha3-256" || hash_type == "sha512/sha3-512";
        if !is_dual_mode && !GPU_SUPPORTED_HEX_TYPES.contains(&hash_type) {
            println!(
                " {} GPU acceleration not supported for '{}'. Falling back to CPU.",
                "[!]".yellow(),
                hash_type
            );
            return CpuBackend.run(hashes, wordlist, hash_type, rule);
        }

        // Rules: expand wordlist on CPU, then dispatch to GPU
        let expanded_wordlist: String;
        let effective_wordlist = if rule {
            println!(
                " {} Applying rules on CPU, dispatching expanded wordlist to GPU...",
                "[*]".green()
            );
            expanded_wordlist = wordlist
                .lines()
                .flat_map(crate::rules::apply)
                .collect::<Vec<_>>()
                .join("\n");
            expanded_wordlist.as_str()
        } else {
            wordlist
        };

        match hash_type {
            "md5" => self.crack_hash(
                hashes,
                effective_wordlist,
                MD5_KERNEL_SOURCE,
                "md5_crack",
                32,
                16,
                "MD5",
            ),
            "sha1" => self.crack_hash(
                hashes,
                effective_wordlist,
                SHA1_KERNEL_SOURCE,
                "sha1_crack",
                40,
                20,
                "SHA1",
            ),
            "sha256" => self.crack_hash(
                hashes,
                effective_wordlist,
                SHA256_KERNEL_SOURCE,
                "sha256_crack",
                64,
                32,
                "SHA256",
            ),
            "sha512" => self.crack_hash(
                hashes,
                effective_wordlist,
                SHA512_KERNEL_SOURCE,
                "sha512_crack",
                128,
                64,
                "SHA512",
            ),
            "sha3-256" => self.crack_hash(
                hashes,
                effective_wordlist,
                SHA3_256_KERNEL_SOURCE,
                "sha3_256_crack",
                64,
                32,
                "SHA3-256",
            ),
            "sha3-512" => self.crack_hash(
                hashes,
                effective_wordlist,
                SHA3_512_KERNEL_SOURCE,
                "sha3_512_crack",
                128,
                64,
                "SHA3-512",
            ),
            "ntlm" => self.crack_hash(
                hashes,
                effective_wordlist,
                NTLM_KERNEL_SOURCE,
                "ntlm_crack",
                32,
                16,
                "NTLM",
            ),
            "sha256/sha3-256" => {
                println!(" {} Dual-mode: trying SHA256 on GPU...", "[*]".green());
                let found_sha256 = self.crack_hash(
                    hashes,
                    effective_wordlist,
                    SHA256_KERNEL_SOURCE,
                    "sha256_crack",
                    64,
                    32,
                    "SHA256",
                );
                println!(" {} Dual-mode: trying SHA3-256 on GPU...", "[*]".green());
                let found_sha3 = self.crack_hash(
                    hashes,
                    effective_wordlist,
                    SHA3_256_KERNEL_SOURCE,
                    "sha3_256_crack",
                    64,
                    32,
                    "SHA3-256",
                );
                found_sha256 + found_sha3
            }
            "sha512/sha3-512" => {
                println!(" {} Dual-mode: trying SHA512 on GPU...", "[*]".green());
                let found_sha512 = self.crack_hash(
                    hashes,
                    effective_wordlist,
                    SHA512_KERNEL_SOURCE,
                    "sha512_crack",
                    128,
                    64,
                    "SHA512",
                );
                println!(" {} Dual-mode: trying SHA3-512 on GPU...", "[*]".green());
                let found_sha3 = self.crack_hash(
                    hashes,
                    effective_wordlist,
                    SHA3_512_KERNEL_SOURCE,
                    "sha3_512_crack",
                    128,
                    64,
                    "SHA3-512",
                );
                found_sha512 + found_sha3
            }
            _ => CpuBackend.run(hashes, wordlist, hash_type, rule),
        }
    }
}

// ============================================================================
//  GPU test suite
//
//  All tests are #[ignore] so CI (no GPU hardware) passes without issues.
//  Run manually on a GPU-equipped machine:
//      cargo test --features gpu -- --ignored
// ============================================================================
#[cfg(test)]
mod tests {
    use super::*;
    use crate::backend::CrackingBackend;
    use crate::cpu_backend::CpuBackend;

    fn init_gpu() -> GpuBackend {
        GpuBackend::new().expect("GPU required — run with: cargo test --features gpu -- --ignored")
    }

    fn hex_to_bytes(hex: &str) -> Vec<u8> {
        let mut bytes = vec![0u8; hex.len() / 2];
        faster_hex::hex_decode(hex.as_bytes(), &mut bytes).expect("invalid hex in test vector");
        bytes
    }

    fn bytes_to_hex(bytes: &[u8]) -> String {
        bytes.iter().map(|b| format!("{:02x}", b)).collect()
    }

    /// Run a single word through a GPU kernel against a single target hash.
    /// Returns true if the kernel found a match.
    fn kernel_matches(
        gpu: &GpuBackend,
        kernel_source: &str,
        kernel_fn: &str,
        word: &str,
        target_hex: &str,
        digest_size: usize,
    ) -> bool {
        let program = Program::create_and_build_from_source(&gpu.context, kernel_source, "")
            .expect("Failed to build kernel");
        let kernel = Kernel::create(&program, kernel_fn).expect("Failed to create kernel");

        let words_data = word.as_bytes().to_vec();
        let offsets = vec![0u32];
        let lengths = vec![word.len() as u32];
        let target = hex_to_bytes(target_hex);
        assert_eq!(
            target.len(),
            digest_size,
            "hex length mismatch for digest_size={digest_size}"
        );

        let results = gpu
            .execute_hash_batch(&kernel, &words_data, &offsets, &lengths, 1, &target, 1)
            .expect("GPU batch execution failed");

        results[0] == 0
    }

    /// Run multiple words against multiple target hashes on the GPU.
    /// Returns per-word result: Some(target_index) if matched, None otherwise.
    fn kernel_batch_results(
        gpu: &GpuBackend,
        kernel_source: &str,
        kernel_fn: &str,
        words: &[&str],
        target_hexes: &[&str],
        digest_size: usize,
    ) -> Vec<Option<usize>> {
        let program = Program::create_and_build_from_source(&gpu.context, kernel_source, "")
            .expect("Failed to build kernel");
        let kernel = Kernel::create(&program, kernel_fn).expect("Failed to create kernel");

        let mut words_data = Vec::new();
        let mut offsets = Vec::new();
        let mut lengths = Vec::new();
        for w in words {
            offsets.push(words_data.len() as u32);
            lengths.push(w.len() as u32);
            words_data.extend_from_slice(w.as_bytes());
        }
        if words_data.is_empty() {
            words_data.push(0);
        }

        let mut target_flat = Vec::new();
        for hex in target_hexes {
            let t = hex_to_bytes(hex);
            assert_eq!(t.len(), digest_size);
            target_flat.extend_from_slice(&t);
        }

        let results = gpu
            .execute_hash_batch(
                &kernel,
                &words_data,
                &offsets,
                &lengths,
                words.len(),
                &target_flat,
                target_hexes.len() as u32,
            )
            .expect("GPU batch execution failed");

        results
            .iter()
            .map(|&r| {
                if r == 0xFFFFFFFF {
                    None
                } else {
                    Some(r as usize)
                }
            })
            .collect()
    }

    fn read_fixture(path: &str) -> String {
        std::fs::read_to_string(path)
            .unwrap_or_else(|e| panic!("Failed to read fixture {path}: {e}"))
    }

    // ================================================================
    //  Kernel unit tests — known hash vectors per algorithm
    // ================================================================

    #[test]
    #[ignore]
    fn kernel_md5_known_vectors() {
        let gpu = init_gpu();
        assert!(kernel_matches(
            &gpu,
            MD5_KERNEL_SOURCE,
            "md5_crack",
            "password",
            "5f4dcc3b5aa765d61d8327deb882cf99",
            16,
        ));
        assert!(kernel_matches(
            &gpu,
            MD5_KERNEL_SOURCE,
            "md5_crack",
            "admin",
            "21232f297a57a5a743894a0e4a801fc3",
            16,
        ));
        // Negative: wrong hash must not match
        assert!(!kernel_matches(
            &gpu,
            MD5_KERNEL_SOURCE,
            "md5_crack",
            "password",
            "00000000000000000000000000000000",
            16,
        ));
    }

    #[test]
    #[ignore]
    fn kernel_sha1_known_vectors() {
        let gpu = init_gpu();
        assert!(kernel_matches(
            &gpu,
            SHA1_KERNEL_SOURCE,
            "sha1_crack",
            "password",
            "5baa61e4c9b93f3f0682250b6cf8331b7ee68fd8",
            20,
        ));
        assert!(kernel_matches(
            &gpu,
            SHA1_KERNEL_SOURCE,
            "sha1_crack",
            "admin",
            "d033e22ae348aeb5660fc2140aec35850c4da997",
            20,
        ));
        assert!(!kernel_matches(
            &gpu,
            SHA1_KERNEL_SOURCE,
            "sha1_crack",
            "password",
            "0000000000000000000000000000000000000000",
            20,
        ));
    }

    #[test]
    #[ignore]
    fn kernel_sha256_known_vectors() {
        let gpu = init_gpu();
        assert!(kernel_matches(
            &gpu,
            SHA256_KERNEL_SOURCE,
            "sha256_crack",
            "password",
            "5e884898da28047151d0e56f8dc6292773603d0d6aabbdd62a11ef721d1542d8",
            32,
        ));
        assert!(kernel_matches(
            &gpu,
            SHA256_KERNEL_SOURCE,
            "sha256_crack",
            "admin",
            "8c6976e5b5410415bde908bd4dee15dfb167a9c873fc4bb8a81f6f2ab448a918",
            32,
        ));
        assert!(!kernel_matches(
            &gpu,
            SHA256_KERNEL_SOURCE,
            "sha256_crack",
            "password",
            "0000000000000000000000000000000000000000000000000000000000000000",
            32,
        ));
    }

    #[test]
    #[ignore]
    fn kernel_sha512_known_vectors() {
        let gpu = init_gpu();
        assert!(kernel_matches(
            &gpu,
            SHA512_KERNEL_SOURCE,
            "sha512_crack",
            "password",
            "b109f3bbbc244eb82441917ed06d618b9008dd09b3befd1b5e07394c706a8bb9\
             80b1d7785e5976ec049b46df5f1326af5a2ea6d103fd07c95385ffab0cacbc86",
            64,
        ));
        assert!(kernel_matches(
            &gpu,
            SHA512_KERNEL_SOURCE,
            "sha512_crack",
            "admin",
            "c7ad44cbad762a5da0a452f9e854fdc1e0e7a52a38015f23f3eab1d80b931dd4\
             72634dfac71cd34ebc35d16ab7fb8a90c81f975113d6c7538dc69dd8de9077ec",
            64,
        ));
        assert!(!kernel_matches(
            &gpu,
            SHA512_KERNEL_SOURCE,
            "sha512_crack",
            "password",
            "0000000000000000000000000000000000000000000000000000000000000000\
             0000000000000000000000000000000000000000000000000000000000000000",
            64,
        ));
    }

    #[test]
    #[ignore]
    fn kernel_sha3_256_known_vectors() {
        let gpu = init_gpu();
        assert!(kernel_matches(
            &gpu,
            SHA3_256_KERNEL_SOURCE,
            "sha3_256_crack",
            "password",
            "c0067d4af4e87f00dbac63b6156828237059172d1bbeac67427345d6a9fda484",
            32,
        ));
        assert!(kernel_matches(
            &gpu,
            SHA3_256_KERNEL_SOURCE,
            "sha3_256_crack",
            "admin",
            "fb001dfcffd1c899f3297871406242f097aecf1a5342ccf3ebcd116146188e4b",
            32,
        ));
        assert!(!kernel_matches(
            &gpu,
            SHA3_256_KERNEL_SOURCE,
            "sha3_256_crack",
            "password",
            "0000000000000000000000000000000000000000000000000000000000000000",
            32,
        ));
    }

    #[test]
    #[ignore]
    fn kernel_sha3_512_known_vectors() {
        let gpu = init_gpu();
        assert!(kernel_matches(
            &gpu,
            SHA3_512_KERNEL_SOURCE,
            "sha3_512_crack",
            "password",
            "e9a75486736a550af4fea861e2378305c4a555a05094dee1dca2f68afea49cc3\
             a50e8de6ea131ea521311f4d6fb054a146e8282f8e35ff2e6368c1a62e909716",
            64,
        ));
        assert!(kernel_matches(
            &gpu,
            SHA3_512_KERNEL_SOURCE,
            "sha3_512_crack",
            "admin",
            "5a38afb1a18d408e6cd367f9db91e2ab9bce834cdad3da24183cc174956c20ce\
             35dd39c2bd36aae907111ae3d6ada353f7697a5f1a8fc567aae9e4ca41a9d19d",
            64,
        ));
        assert!(!kernel_matches(
            &gpu,
            SHA3_512_KERNEL_SOURCE,
            "sha3_512_crack",
            "password",
            "0000000000000000000000000000000000000000000000000000000000000000\
             0000000000000000000000000000000000000000000000000000000000000000",
            64,
        ));
    }

    #[test]
    #[ignore]
    fn kernel_ntlm_known_vectors() {
        let gpu = init_gpu();
        assert!(kernel_matches(
            &gpu,
            NTLM_KERNEL_SOURCE,
            "ntlm_crack",
            "password",
            "8846f7eaee8fb117ad06bdd830b7586c",
            16,
        ));
        assert!(kernel_matches(
            &gpu,
            NTLM_KERNEL_SOURCE,
            "ntlm_crack",
            "admin",
            "209c6174da490caeb422f3fa5a7ae634",
            16,
        ));
        assert!(!kernel_matches(
            &gpu,
            NTLM_KERNEL_SOURCE,
            "ntlm_crack",
            "password",
            "00000000000000000000000000000000",
            16,
        ));
    }

    // ================================================================
    //  Batch tests — verify correct word-to-target matching
    // ================================================================

    #[test]
    #[ignore]
    fn kernel_md5_batch_matching() {
        let gpu = init_gpu();
        let words: &[&str] = &["hello", "password", "admin", "xyz"];
        let targets: &[&str] = &[
            "5f4dcc3b5aa765d61d8327deb882cf99", // password → target 0
            "21232f297a57a5a743894a0e4a801fc3", // admin    → target 1
        ];
        let results =
            kernel_batch_results(&gpu, MD5_KERNEL_SOURCE, "md5_crack", words, targets, 16);
        assert_eq!(results[0], None, "hello should not match");
        assert_eq!(results[1], Some(0), "password should match target 0");
        assert_eq!(results[2], Some(1), "admin should match target 1");
        assert_eq!(results[3], None, "xyz should not match");
    }

    #[test]
    #[ignore]
    fn kernel_sha256_batch_matching() {
        let gpu = init_gpu();
        let words: &[&str] = &["abc", "password", "hello", "admin"];
        let targets: &[&str] = &[
            "5e884898da28047151d0e56f8dc6292773603d0d6aabbdd62a11ef721d1542d8", // password → 0
            "8c6976e5b5410415bde908bd4dee15dfb167a9c873fc4bb8a81f6f2ab448a918", // admin    → 1
        ];
        let results = kernel_batch_results(
            &gpu,
            SHA256_KERNEL_SOURCE,
            "sha256_crack",
            words,
            targets,
            32,
        );
        assert_eq!(results[0], None, "abc should not match");
        assert_eq!(results[1], Some(0), "password should match target 0");
        assert_eq!(results[2], None, "hello should not match");
        assert_eq!(results[3], Some(1), "admin should match target 1");
    }

    // ================================================================
    //  CPU vs GPU correctness — same inputs, same cracked count
    // ================================================================

    #[test]
    #[ignore]
    fn correctness_md5_cpu_vs_gpu() {
        let hc = read_fixture("tests/hashes/md5/hashes.txt");
        let hashes: Vec<&str> = hc.lines().collect();
        let wordlist = read_fixture("tests/wordlists/wordlist.txt");

        let cpu = CpuBackend.run(&hashes, &wordlist, "md5", false);
        let gpu_found = init_gpu().run(&hashes, &wordlist, "md5", false);
        assert_eq!(
            cpu, gpu_found,
            "MD5: CPU cracked {cpu} but GPU cracked {gpu_found}"
        );
    }

    #[test]
    #[ignore]
    fn correctness_sha1_cpu_vs_gpu() {
        let hc = read_fixture("tests/hashes/sha1/hashes.txt");
        let hashes: Vec<&str> = hc.lines().collect();
        let wordlist = read_fixture("tests/wordlists/wordlist.txt");

        let cpu = CpuBackend.run(&hashes, &wordlist, "sha1", false);
        let gpu_found = init_gpu().run(&hashes, &wordlist, "sha1", false);
        assert_eq!(
            cpu, gpu_found,
            "SHA1: CPU cracked {cpu} but GPU cracked {gpu_found}"
        );
    }

    #[test]
    #[ignore]
    fn correctness_sha256_cpu_vs_gpu() {
        let hc = read_fixture("tests/hashes/sha256/hashes.txt");
        let hashes: Vec<&str> = hc.lines().collect();
        let wordlist = read_fixture("tests/wordlists/wordlist.txt");

        let cpu = CpuBackend.run(&hashes, &wordlist, "sha256", false);
        let gpu_found = init_gpu().run(&hashes, &wordlist, "sha256", false);
        assert_eq!(
            cpu, gpu_found,
            "SHA256: CPU cracked {cpu} but GPU cracked {gpu_found}"
        );
    }

    #[test]
    #[ignore]
    fn correctness_sha512_cpu_vs_gpu() {
        let hc = read_fixture("tests/hashes/sha512/hashes.txt");
        let hashes: Vec<&str> = hc.lines().collect();
        let wordlist = read_fixture("tests/wordlists/wordlist.txt");

        let cpu = CpuBackend.run(&hashes, &wordlist, "sha512", false);
        let gpu_found = init_gpu().run(&hashes, &wordlist, "sha512", false);
        assert_eq!(
            cpu, gpu_found,
            "SHA512: CPU cracked {cpu} but GPU cracked {gpu_found}"
        );
    }

    #[test]
    #[ignore]
    fn correctness_sha3_256_cpu_vs_gpu() {
        // No fixture file for SHA3-256; generate hashes from known words using CPU
        let words = ["password", "admin", "hello", "abc123"];
        let hashes: Vec<String> = words
            .iter()
            .map(|w| bytes_to_hex(&crate::hashes::sha3_256::crack(w)))
            .collect();
        let hash_refs: Vec<&str> = hashes.iter().map(|s| s.as_str()).collect();
        let wordlist = words.join("\n");

        let cpu = CpuBackend.run(&hash_refs, &wordlist, "sha3-256", false);
        let gpu_found = init_gpu().run(&hash_refs, &wordlist, "sha3-256", false);
        assert_eq!(
            cpu, gpu_found,
            "SHA3-256: CPU cracked {cpu} but GPU cracked {gpu_found}"
        );
        assert_eq!(
            cpu,
            words.len(),
            "SHA3-256: expected all {} hashes cracked",
            words.len()
        );
    }

    #[test]
    #[ignore]
    fn correctness_sha3_512_cpu_vs_gpu() {
        let hc = read_fixture("tests/hashes/sha3-512/hashes.txt");
        let hashes: Vec<&str> = hc.lines().collect();
        let wordlist = read_fixture("tests/wordlists/wordlist.txt");

        let cpu = CpuBackend.run(&hashes, &wordlist, "sha3-512", false);
        let gpu_found = init_gpu().run(&hashes, &wordlist, "sha3-512", false);
        assert_eq!(
            cpu, gpu_found,
            "SHA3-512: CPU cracked {cpu} but GPU cracked {gpu_found}"
        );
    }

    #[test]
    #[ignore]
    fn correctness_ntlm_cpu_vs_gpu() {
        let hc = read_fixture("tests/hashes/ntlm/hashes.txt");
        let hashes: Vec<&str> = hc.lines().collect();
        let wordlist = read_fixture("tests/wordlists/wordlist.txt");

        let cpu = CpuBackend.run(&hashes, &wordlist, "ntlm", false);
        let gpu_found = init_gpu().run(&hashes, &wordlist, "ntlm", false);
        assert_eq!(
            cpu, gpu_found,
            "NTLM: CPU cracked {cpu} but GPU cracked {gpu_found}"
        );
    }
}
