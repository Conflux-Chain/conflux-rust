use log::info;
use pprof::{protos::Message, ProfilerGuard};
use std::{fs, time::Duration};
use tokio::time;

// dump memory profile to file, return the filename
pub async fn dump_memory_profile() -> Result<String, String> {
    // Get jemalloc profiling controller
    let prof_ctl = jemalloc_pprof::PROF_CTL
        .as_ref()
        .ok_or_else(|| "Profiling controller not available".to_string())?;

    let mut prof_ctl = prof_ctl.lock().await;

    // Check if profiling is activated
    if !prof_ctl.activated() {
        return Err("Jemalloc profiling is not activated".to_string());
    }

    // Call dump_pprof() method to generate pprof data
    let pprof_data = prof_ctl
        .dump_pprof()
        .map_err(|e| format!("Failed to dump pprof: {}", e))?;

    // Generate unique filename using timestamp
    let timestamp = chrono::Utc::now().format("%Y%m%d_%H%M%S");
    // TODO enable to specify the file location
    let filename = format!("memory_profile_{}.pb", timestamp);

    // Write pprof data to local file
    fs::write(&filename, pprof_data)
        .map_err(|e| format!("Failed to write profile file: {}", e))?;

    info!("Memory profile dumped to: {}", filename);
    Ok(filename)
}

pub async fn dump_cpu_profile() -> Result<String, String> {
    info!("Starting CPU profiling for 60 seconds...");

    // Create CPU profiler with sampling frequency of 100 Hz
    let guard = ProfilerGuard::new(100)
        .map_err(|e| format!("Failed to create profiler: {}", e))?;

    // Continue sampling for 60 seconds
    time::sleep(Duration::from_secs(60)).await;

    // Generate report
    let report = guard
        .report()
        .build()
        .map_err(|e| format!("Failed to build report: {}", e))?;

    // Generate filename using timestamp
    let timestamp = chrono::Utc::now().format("%Y%m%d_%H%M%S");
    // TODO enable to specify the file location
    let filename = format!("cpu_profile_{}.pb", timestamp);

    // Create file and write pprof data
    let mut file = fs::File::create(&filename)
        .map_err(|e| format!("Failed to create file: {}", e))?;

    report
        .pprof()
        .map_err(|e| format!("Failed to convert to pprof: {}", e))?
        .write_to_writer(&mut file)
        .map_err(|e| format!("Failed to write profile: {}", e))?;

    info!("CPU profile dumped to: {}", filename);
    Ok(filename)
}
