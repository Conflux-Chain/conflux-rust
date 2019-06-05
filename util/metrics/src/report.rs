use crate::is_enabled;
use prometheus;
use std::{
    fs::OpenOptions,
    io::Write,
    path::Path,
    thread,
    time::{Duration, SystemTime, UNIX_EPOCH},
};

pub fn report_file(interval: Duration, path: String) {
    if !is_enabled() {
        return;
    }

    thread::spawn(move || {
        let path = path.as_str();

        loop {
            thread::sleep(interval);

            if let Err(e) = report_file_once(path) {
                eprintln!("Exit metrics reporting due to error: {:?}", e);
                break;
            }
        }
    });
}

fn report_file_once<P: AsRef<Path>>(path: P) -> Result<(), String> {
    let now = SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .map_err(|e| format!("invalid system time {:?}", e))?;

    let mut file = OpenOptions::new()
        .create(true)
        .append(true)
        .open(path)
        .map_err(|e| format!("failed to open file, {:?}", e))?;

    for m in prometheus::default_registry().gather() {
        file.write(format!("{}, {:?}\n", now.as_millis(), m).as_bytes())
            .map_err(|e| format!("failed to write file, {:?}", e))?;
    }

    Ok(())
}
