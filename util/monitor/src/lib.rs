#[macro_use] extern crate influx_db_client;
#[macro_use] extern crate log;

use influx_db_client::{Client, Point, Value, Precision};
use cfx_types::{H256};
use std::sync::{Once, ONCE_INIT};
use std::{mem, thread};

static ONCE: Once = ONCE_INIT;
static mut SINGLETON: *const Monitor = 0 as *const Monitor;

pub struct Monitor {
    node: String,
    client: Client,   
}

impl Monitor {
    pub fn init(host: Option<String>, db: Option<String>, username: Option<String>, password: Option<String>, node: Option<String>) {
        if host.is_none() || db.is_none() || username.is_none() || password.is_none() || node.is_none() {
            return
        }
        ONCE.call_once(|| {
            let host = host.unwrap();
            let db = db.unwrap();
            let username = username.unwrap();
            let password = password.unwrap();
            let node = node.unwrap();

            // Make it
            let singleton = Monitor {
                node: node,
                client: Client::new(host.clone(), db.clone()).set_authentication(username.clone(), password.clone()),
            };

            // Put it in the heap so it can outlive this call
            unsafe { SINGLETON = mem::transmute(Box::new(singleton)) };
        });
    }

    pub fn update_state(epoch_number: usize, hash: &H256) {
        let node = unsafe {(*SINGLETON).node.clone() };
        let mut point = point!("state");
        point
        .add_field("height", Value::Integer(epoch_number as i64))
        .add_field("hash", Value::Integer((hash.low_u64() & 0x7fffffffffffffff) as i64))
        .add_tag("node", Value::String(node.clone()));
        Monitor::update(point);
    }

    fn update(point: Point) {
        let client = unsafe { &(*SINGLETON).client };
        match client.write_point(point, Some(Precision::Seconds), None) {
            Err(e) => warn!("Failed to update point into monitor, msg: {}", e),
            Ok(()) => {},
        }
    }
}
