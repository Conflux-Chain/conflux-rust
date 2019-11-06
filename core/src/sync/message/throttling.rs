// Copyright 2019 Conflux Foundation. All rights reserved.
// Conflux is free software and distributed under GNU General Public License.
// See http://www.gnu.org/licenses/

use crate::{
    message::{Message, MsgId, RequestId},
    sync::{
        message::{Context, Handleable},
        Error, ErrorKind,
    },
};
use rlp_derive::{RlpDecodable, RlpEncodable};
use std::time::{Duration, Instant};
use throttling::token_bucket::ThrottleResult;

#[derive(Debug, RlpDecodable, RlpEncodable)]
pub struct Throttled {
    pub msg_id: MsgId,
    pub wait_time_nanos: u64,
    // resend request to another peer if throttled
    pub request_id: Option<RequestId>,
}

impl Handleable for Throttled {
    fn handle(self, ctx: &Context) -> Result<(), Error> {
        let peer = match ctx.manager.syn.peers.read().get(&ctx.peer) {
            Some(peer) => peer.clone(),
            None => return Ok(()),
        };

        peer.write().set_throttled(
            self.msg_id,
            Instant::now() + Duration::from_nanos(self.wait_time_nanos),
        );

        if let Some(request_id) = self.request_id {
            let request = ctx.match_request(request_id)?;
            ctx.manager
                .request_manager
                .send_request_again(ctx.io, &request);
        }

        Ok(())
    }
}

pub trait Throttle {
    fn throttle(&self, ctx: &Context) -> Result<(), Error>;
}

impl<T: Message> Throttle for T {
    fn throttle(&self, ctx: &Context) -> Result<(), Error> {
        let peer = match ctx.manager.syn.peers.read().get(&ctx.peer) {
            Some(peer) => peer.clone(),
            None => return Ok(()),
        };

        let bucket_name = self.msg_name().to_string();
        let bucket = match peer.read().throttling.get(&bucket_name) {
            Some(bucket) => bucket,
            None => return Ok(()),
        };

        let result = bucket.lock().throttle();

        match result {
            ThrottleResult::Success => Ok(()),
            ThrottleResult::Throttled(wait_time) => {
                let throttled = Throttled {
                    msg_id: self.msg_id(),
                    wait_time_nanos: wait_time.as_nanos() as u64,
                    request_id: self.get_request_id(),
                };

                Err(ErrorKind::Throttled(self.msg_name(), throttled).into())
            }
            ThrottleResult::AlreadyThrottled => {
                Err(ErrorKind::AlreadyThrottled(self.msg_name()).into())
            }
        }
    }
}
