use std::collections::BTreeMap;
#[cfg(unix)]
use std::os::unix::process::ExitStatusExt;
use std::path::PathBuf;
use std::process::{ExitStatus, Stdio};
use std::str::FromStr;
use std::sync::{Arc, Mutex};

use anyhow::{Result, bail};
use async_process::Command;
use async_trait::async_trait;
use futures::io::BufReader as FuturesBufReader;
use futures::{AsyncBufReadExt as _, AsyncWriteExt as _};
use inferno::collapse::Collapse;
use inferno::collapse::dtrace::Folder as DtraceFolder;
use inferno::collapse::perf::Folder as PerfFolder;
use itertools::Itertools;
use serde::{Deserialize, Serialize};
use tempfile::NamedTempFile;
use tokio::io::{AsyncBufReadExt as _, BufReader as TokioBufReader};
use tokio::sync::{mpsc, oneshot};
use tokio_util::compat::FuturesAsyncReadCompatExt;
use tokio_util::io::SyncIoBridge;
use wholesym::debugid::DebugId;
use wholesym::{LookupAddress, MultiArchDisambiguator, SymbolManager, SymbolManagerConfig};

use crate::progress::ProgressTracker;
use crate::rust_crate::flamegraph::handle_fold_data;
use crate::rust_crate::tracing_options::TracingOptions;
use crate::ssh::PrefixFilteredChannel;
use crate::util::prioritized_broadcast;
use crate::{LaunchedBinary, TracingResults};

pub(super) struct TracingDataLocal {
    pub(super) outfile: NamedTempFile,
}

pub struct LaunchedLocalhostBinary {
    child: Mutex<async_process::Child>,
    tracing_config: Option<TracingOptions>,
    tracing_data_local: Option<TracingDataLocal>,
    tracing_results: Option<TracingResults>,
    stdin_sender: mpsc::UnboundedSender<String>,
    stdout_deploy_receivers: Arc<Mutex<Option<oneshot::Sender<String>>>>,
    stdout_receivers: Arc<Mutex<Vec<PrefixFilteredChannel>>>,
    stderr_receivers: Arc<Mutex<Vec<PrefixFilteredChannel>>>,
}

#[cfg(unix)]
impl Drop for LaunchedLocalhostBinary {
    fn drop(&mut self) {
        let mut child = self.child.lock().unwrap();

        if let Ok(Some(_)) = child.try_status() {
            return;
        }

        let pid = child.id();
        if let Err(e) = nix::sys::signal::kill(
            nix::unistd::Pid::from_raw(pid as i32),
            nix::sys::signal::SIGTERM,
        ) {
            ProgressTracker::println(format!("Failed to SIGTERM process {}: {}", pid, e));
        }
    }
}

impl LaunchedLocalhostBinary {
    pub(super) fn new(
        mut child: async_process::Child,
        id: String,
        tracing_config: Option<TracingOptions>,
        tracing_data_local: Option<TracingDataLocal>,
    ) -> Self {
        let (stdin_sender, mut stdin_receiver) = mpsc::unbounded_channel::<String>();
        let mut stdin = child.stdin.take().unwrap();
        tokio::spawn(async move {
            while let Some(line) = stdin_receiver.recv().await {
                if stdin.write_all(line.as_bytes()).await.is_err() {
                    break;
                }

                stdin.flush().await.ok();
            }
        });

        let id_clone = id.clone();
        let (stdout_deploy_receivers, stdout_receivers) = prioritized_broadcast(
            FuturesBufReader::new(child.stdout.take().unwrap()).lines(),
            move |s| ProgressTracker::println(format!("[{id_clone}] {s}")),
        );
        let (_, stderr_receivers) = prioritized_broadcast(
            FuturesBufReader::new(child.stderr.take().unwrap()).lines(),
            move |s| ProgressTracker::println(format!("[{id} stderr] {s}")),
        );

        Self {
            child: Mutex::new(child),
            tracing_config,
            tracing_data_local,
            tracing_results: None,
            stdin_sender,
            stdout_deploy_receivers,
            stdout_receivers,
            stderr_receivers,
        }
    }
}

#[derive(Serialize, Deserialize, Debug)]
pub struct FxProfile {
    threads: Vec<Thread>,
    libs: Vec<Lib>,
}

#[derive(Serialize, Deserialize, Debug)]
pub struct Lib {
    pub path: String,
    #[serde(rename = "breakpadId")]
    pub breakpad_id: String,
}

#[derive(Serialize, Deserialize, Debug)]
pub struct Thread {
    #[serde(rename = "stackTable")]
    pub stack_table: StackTable,
    #[serde(rename = "frameTable")]
    pub frame_table: FrameTable,
    #[serde(rename = "funcTable")]
    pub func_table: FuncTable,
    pub samples: Samples,
    #[serde(rename = "isMainThread")]
    pub is_main_thread: bool,
}

#[derive(Serialize, Deserialize, Debug)]
pub struct Samples {
    pub stack: Vec<Option<usize>>,
    pub weight: Vec<u64>,
}

#[derive(Serialize, Deserialize, Debug)]
pub struct StackTable {
    pub prefix: Vec<Option<usize>>,
    pub frame: Vec<usize>,
}

#[derive(Serialize, Deserialize, Debug)]
pub struct FrameTable {
    pub address: Vec<u64>,
    pub func: Vec<usize>,
}

#[derive(Serialize, Deserialize, Debug)]
pub struct FuncTable {
    pub resource: Vec<usize>,
}

#[async_trait]
impl LaunchedBinary for LaunchedLocalhostBinary {
    fn stdin(&self) -> mpsc::UnboundedSender<String> {
        self.stdin_sender.clone()
    }

    fn deploy_stdout(&self) -> oneshot::Receiver<String> {
        let mut receivers = self.stdout_deploy_receivers.lock().unwrap();

        if receivers.is_some() {
            panic!("Only one deploy stdout receiver is allowed at a time");
        }

        let (sender, receiver) = oneshot::channel::<String>();
        *receivers = Some(sender);
        receiver
    }

    fn stdout(&self) -> mpsc::UnboundedReceiver<String> {
        let mut receivers = self.stdout_receivers.lock().unwrap();
        let (sender, receiver) = mpsc::unbounded_channel::<String>();
        receivers.push((None, sender));
        receiver
    }

    fn stderr(&self) -> mpsc::UnboundedReceiver<String> {
        let mut receivers = self.stderr_receivers.lock().unwrap();
        let (sender, receiver) = mpsc::unbounded_channel::<String>();
        receivers.push((None, sender));
        receiver
    }

    fn stdout_filter(&self, prefix: String) -> mpsc::UnboundedReceiver<String> {
        let mut receivers = self.stdout_receivers.lock().unwrap();
        let (sender, receiver) = mpsc::unbounded_channel::<String>();
        receivers.push((Some(prefix), sender));
        receiver
    }

    fn stderr_filter(&self, prefix: String) -> mpsc::UnboundedReceiver<String> {
        let mut receivers = self.stderr_receivers.lock().unwrap();
        let (sender, receiver) = mpsc::unbounded_channel::<String>();
        receivers.push((Some(prefix), sender));
        receiver
    }

    fn tracing_results(&self) -> Option<&TracingResults> {
        self.tracing_results.as_ref()
    }

    fn exit_code(&self) -> Option<i32> {
        self.child
            .lock()
            .unwrap()
            .try_status()
            .ok()
            .flatten()
            .map(exit_code)
    }

    async fn wait(&mut self) -> Result<i32> {
        Ok(exit_code(self.child.get_mut().unwrap().status().await?))
    }

    async fn stop(&mut self) -> Result<()> {
        if let Err(err) = self.child.get_mut().unwrap().kill() {
            if !matches!(err.kind(), std::io::ErrorKind::InvalidInput) {
                Err(err)?;
            }
        }

        // Run perf post-processing and download perf output.
        if let Some(tracing_config) = self.tracing_config.as_ref() {
            if self.tracing_results.is_none() {
                let tracing_data = self.tracing_data_local.take().unwrap();

                if cfg!(target_os = "macos") || cfg!(target_family = "windows") {
                    if let Some(samply_outfile) = tracing_config.samply_outfile.as_ref() {
                        std::fs::copy(&tracing_data.outfile, samply_outfile)?;
                    }
                } else if cfg!(target_family = "unix") {
                    if let Some(perf_outfile) = tracing_config.perf_raw_outfile.as_ref() {
                        std::fs::copy(&tracing_data.outfile, perf_outfile)?;
                    }
                }

                let fold_data = if cfg!(target_os = "macos") {
                    let loaded = serde_json::from_reader::<_, FxProfile>(std::fs::File::open(
                        tracing_data.outfile.path(),
                    )?)?;

                    let symbol_manager = SymbolManager::with_config(SymbolManagerConfig::default());

                    let mut symbol_maps = vec![];
                    for lib in &loaded.libs {
                        symbol_maps.push(
                            symbol_manager
                                .load_symbol_map_for_binary_at_path(
                                    &PathBuf::from_str(&lib.path).unwrap(),
                                    Some(MultiArchDisambiguator::DebugId(
                                        DebugId::from_breakpad(&lib.breakpad_id).unwrap(),
                                    )),
                                )
                                .await
                                .ok(),
                        );
                    }

                    let mut folded_frames: BTreeMap<Vec<String>, u64> = BTreeMap::new();
                    for thread in loaded.threads.into_iter().filter(|t| t.is_main_thread) {
                        let mut frame_lookuped = vec![];
                        for frame_id in 0..thread.frame_table.address.len() {
                            let address = thread.frame_table.address[frame_id];
                            let func_id = thread.frame_table.func[frame_id];
                            let resource_id = thread.func_table.resource[func_id];
                            let maybe_symbol_map = &symbol_maps[resource_id];

                            if let Some(symbols_map) = maybe_symbol_map {
                                if let Some(lookuped) = symbols_map
                                    .lookup(LookupAddress::Relative(address as u32))
                                    .await
                                {
                                    if let Some(inline_frames) = lookuped.frames {
                                        frame_lookuped.push(
                                            inline_frames
                                                .into_iter()
                                                .rev()
                                                .map(|inline| {
                                                    inline
                                                        .function
                                                        .unwrap_or_else(|| "unknown".to_string())
                                                })
                                                .join(";"),
                                        );
                                    } else {
                                        frame_lookuped.push(lookuped.symbol.name);
                                    }
                                } else {
                                    frame_lookuped.push("unknown".to_string());
                                }
                            } else {
                                frame_lookuped.push("unknown".to_string());
                            }
                        }

                        let all_leaves_grouped = thread
                            .samples
                            .stack
                            .iter()
                            .enumerate()
                            .filter_map(|(idx, s)| s.map(|s| (idx, s)))
                            .map(|(idx, leaf)| (leaf, thread.samples.weight[idx]))
                            .chunk_by(|v| v.0)
                            .into_iter()
                            .map(|(leaf, group)| {
                                let weight = group.map(|t| t.1).sum();
                                (leaf, weight)
                            })
                            .collect::<Vec<(usize, u64)>>();

                        for (leaf, weight) in all_leaves_grouped {
                            let mut cur_stack = Some(leaf);
                            let mut stack = vec![];
                            while let Some(sample) = cur_stack {
                                let frame_id = thread.stack_table.frame[sample];
                                stack.push(frame_lookuped[frame_id].clone());
                                cur_stack = thread.stack_table.prefix[sample];
                            }

                            *folded_frames.entry(stack).or_default() += weight;
                        }
                    }

                    let mut output = String::new();
                    for (stack, weight) in folded_frames {
                        for (i, s) in stack.iter().rev().enumerate() {
                            if i != 0 {
                                output.push(';');
                            }
                            output.push_str(s);
                        }

                        output.push_str(&format!(" {}\n", weight));
                    }

                    output.into()
                } else if cfg!(target_family = "windows") {
                    let mut fold_er = DtraceFolder::from(
                        tracing_config
                            .fold_dtrace_options
                            .clone()
                            .unwrap_or_default(),
                    );

                    let fold_data =
                        ProgressTracker::leaf("fold dtrace output".to_owned(), async move {
                            let mut fold_data = Vec::new();
                            fold_er.collapse_file(Some(tracing_data.outfile), &mut fold_data)?;
                            Result::<_>::Ok(fold_data)
                        })
                        .await?;
                    fold_data
                } else if cfg!(target_family = "unix") {
                    // Run perf script.
                    let mut perf_script = Command::new("perf")
                        .args(["script", "--symfs=/", "-i"])
                        .arg(tracing_data.outfile.path())
                        .stdout(Stdio::piped())
                        .stderr(Stdio::piped())
                        .spawn()?;

                    let stdout = perf_script.stdout.take().unwrap().compat();
                    let mut stderr_lines =
                        TokioBufReader::new(perf_script.stderr.take().unwrap().compat()).lines();

                    let mut fold_er = PerfFolder::from(
                        tracing_config.fold_perf_options.clone().unwrap_or_default(),
                    );

                    // Pattern on `()` to make sure no `Result`s are ignored.
                    let ((), fold_data, ()) = tokio::try_join!(
                        async move {
                            // Log stderr.
                            while let Ok(Some(s)) = stderr_lines.next_line().await {
                                ProgressTracker::println(format!("[perf script stderr] {s}"));
                            }
                            Result::<_>::Ok(())
                        },
                        async move {
                            // Stream `perf script` stdout and fold.
                            tokio::task::spawn_blocking(move || {
                                let mut fold_data = Vec::new();
                                fold_er.collapse(
                                    SyncIoBridge::new(tokio::io::BufReader::new(stdout)),
                                    &mut fold_data,
                                )?;
                                Ok(fold_data)
                            })
                            .await?
                        },
                        async move {
                            // Close stdin and wait for command exit.
                            perf_script.status().await?;
                            Ok(())
                        },
                    )?;
                    fold_data
                } else {
                    bail!(
                        "Unknown OS for perf/dtrace tracing: {}",
                        std::env::consts::OS
                    );
                };

                handle_fold_data(tracing_config, fold_data.clone()).await?;

                self.tracing_results = Some(TracingResults {
                    folded_data: fold_data,
                });
            }
        };

        Ok(())
    }
}

fn exit_code(c: ExitStatus) -> i32 {
    #[cfg(unix)]
    return c.code().or(c.signal()).unwrap();
    #[cfg(not(unix))]
    return c.code().unwrap();
}
