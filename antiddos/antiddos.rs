use std::collections::HashMap;
use std::fs::OpenOptions;
use std::io::Write;
use std::sync::{Arc, Mutex};
use std::time::{Duration, SystemTime};

#[derive(Debug)]
pub struct AntiDDoSConfig {
    pub max_requests_per_second: u32,
    pub block_duration: Duration,
    pub log_file_path: String,
}

struct AntiDDoSService {
    config: AntiDDoSConfig,
    ip_tracker: HashMap<String, Vec<SystemTime>>,
    block_list: HashMap<String, SystemTime>,
    log_file: Option<std::fs::File>,
}

impl AntiDDoSService {
    fn new(config: AntiDDoSConfig) -> Self {
        let log_file = OpenOptions::new()
            .create(true)
            .append(true)
            .open(&config.log_file_path)
            .ok();

        AntiDDoSService {
            config,
            ip_tracker: HashMap::new(),
            block_list: HashMap::new(),
            log_file,
        }
    }

    fn is_blocked(&mut self, ip: &str) -> bool {
        if let Some(block_time) = self.block_list.get(ip) {
            if SystemTime::now().duration_since(*block_time).unwrap_or_default() < self.config.block_duration {
                return true;
            }
            self.block_list.remove(ip);
        }
        false
    }

    fn track_request(&mut self, ip: &str) {
        let now = SystemTime::now();
        let cutoff = now - Duration::from_secs(1);

        let entries = self.ip_tracker.entry(ip.to_string()).or_insert_with(Vec::new);
        entries.retain(|&t| t > cutoff);
        entries.push(now);

        if entries.len() > self.config.max_requests_per_second as usize {
            self.block_list.insert(ip.to_string(), now);
            self.log(format!("BLOCKED|{}|Excessive requests|Count:{}", ip, entries.len()));
        }
    }

    fn log(&mut self, message: String) {
        let timestamp = chrono::Local::now().format("%Y-%m-%d %H:%M:%S").to_string();
        let log_message = format!("{}|{}
", timestamp, message);

        if let Some(file) = &mut self.log_file {
            let _ = file.write_all(log_message.as_bytes());
        }
        println!("{}", log_message);
    }
}

lazy_static::lazy_static! {
    static ref ANTI_DDOS_SERVICE: Arc<Mutex<AntiDDoSService>> = {
        let config = AntiDDoSConfig {
            max_requests_per_second: 100,
            block_duration: Duration::from_secs(60),
            log_file_path: "/etc/gubinnet/logs/antiddos.log".to_string(),
        };
        Arc::new(Mutex::new(AntiDDoSService::new(config)))
    };
}

#[no_mangle]
pub extern "C" fn is_blocked(ip: *const libc::c_char) -> bool {
    let ip = unsafe { std::ffi::CStr::from_ptr(ip).to_string_lossy().into_owned() };
    let mut service = ANTI_DDOS_SERVICE.lock().unwrap();
    service.is_blocked(&ip)
}

#[no_mangle]
pub extern "C" fn track_request(ip: *const libc::c_char) {
    let ip = unsafe { std::ffi::CStr::from_ptr(ip).to_string_lossy().into_owned() };
    let mut service = ANTI_DDOS_SERVICE.lock().unwrap();
    service.track_request(&ip);
}