#[macro_use]
extern crate influx_db_client;
#[macro_use]
extern crate log;

use cfx_types::H256;
use influx_db_client::{Client, Point, Precision, Value};
use std::{
    mem,
    sync::{
        mpsc::{channel, Sender},
        Once, ONCE_INIT,
    },
    thread,
};

static ONCE: Once = ONCE_INIT;
static mut SINGLETON: *mut Monitor = 0 as *mut Monitor;

pub struct Monitor {
    node: String,
    client: Client,
    thread: Option<thread::JoinHandle<()>>,
    queue: Sender<Msg>,
}

enum Msg {
    Payload(Point),
    Stop,
}

impl Monitor {
    pub fn init(
        host: Option<String>, db: Option<String>, username: Option<String>,
        password: Option<String>, node: Option<String>,
    )
    {
        if host.is_none()
            || db.is_none()
            || username.is_none()
            || password.is_none()
            || node.is_none()
        {
            return;
        }
        ONCE.call_once(|| {
            let host = host.unwrap();
            let db = db.unwrap();
            let username = username.unwrap();
            let password = password.unwrap();
            let node = node.unwrap();
            let client = Client::new(host.clone(), db.clone()).set_authentication(username.clone(), password.clone());
            let (sc, rc) = channel();

            // Make it
            let singleton = Monitor {
                node: node,
                client: client,
                thread: None,
                queue: sc,
            };

            // Put it in the heap so it can outlive this call
            unsafe {
                SINGLETON = mem::transmute(Box::new(singleton)) ;

                let thread = thread::Builder::new()
                .name("monitor".into())
                .spawn(move || {
                    loop {
                        let msg = rc.recv().unwrap();
                        match msg {
                            Msg::Payload(point) => {
                                match (*SINGLETON).client.write_point(point, Some(Precision::Microseconds), None) {
                                    Err(e) => warn!("Failed to update point into monitor, msg: {}", e),
                                    Ok(()) => {},
                                }
                            },
                            Msg::Stop => break,
                        }
                    }
                }).expect("Failed to init Monitor with Configuration"); 

                (*SINGLETON).thread = Some(thread);
            }
        });
    }

    pub fn stop() {
        if let Some(ctx) = Monitor::context() {
            ctx.queue.send(Msg::Stop).unwrap();
        }
    }

    #[allow(deprecated)]
    pub fn update_state(epoch_number: usize, hash: &H256) {
        if let Some(ctx) = Monitor::context() {
            let mut point = point!("state");
            point
                .add_field("height", Value::Integer(epoch_number as i64))
                .add_field(
                    "hash",
                    Value::Integer(
                        (hash.low_u64() & 0x7fffffffffffffff) as i64,
                    ),
                )
                .add_tag("node", Value::String(ctx.node.clone()));
            ctx.queue.send(Msg::Payload(point)).unwrap();
        }
    }

    pub fn update_upside_network_packets(size: usize) {
        if let Some(ctx) = Monitor::context() {
            let mut point = point!("upside_stream");
            point
                .add_field("size", Value::Integer(size as i64))
                .add_tag("node", Value::String(ctx.node.clone()));
            ctx.queue.send(Msg::Payload(point)).unwrap();
        }
    }

    fn context<'a>() -> Option<&'a mut Monitor> {
        unsafe {
            if SINGLETON == 0 as *mut Monitor {
                return None;
            }
            return Some(&mut (*SINGLETON));
        }
    }
}
