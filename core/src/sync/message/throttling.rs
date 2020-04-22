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

// TODO: It seems better to distinguish request, response, and different kind of
// TODO: requests, as here in this class it tries to resend request to another
// TODO: peer. This class is implemented to all Message type. But the resend
// TODO: functionality applies only to AnyCast request.
#[derive(Debug, RlpDecodable, RlpEncodable)]
pub struct Throttled {
    pub msg_id: MsgId,
    pub wait_time_nanos: u64,
    // resend request to another peer if throttled
    pub request_id: Option<RequestId>,
}

impl Handleable for Throttled {
    fn handle(self, ctx: &Context) -> Result<(), Error> {
        let peer = match ctx.manager.syn.peers.read().get(&ctx.node_id) {
            Some(peer) => peer.clone(),
            None => return Ok(()),
        };

        peer.write().throttled_msgs.set_throttled(
            self.msg_id,
            Instant::now() + Duration::from_nanos(self.wait_time_nanos),
        );

        if let Some(request_id) = self.request_id {
            let request = ctx.match_request(request_id)?;
            ctx.manager
                .request_manager
                .resend_request_to_another_peer(ctx.io, &request);
        }

        Ok(())
    }
}

pub trait Throttle {
    fn throttle(&self, ctx: &Context) -> Result<(), Error>;
}

impl<T: Message> Throttle for T {
    fn throttle(&self, ctx: &Context) -> Result<(), Error> {
        let peer = match ctx.manager.syn.peers.read().get(&ctx.node_id) {
            Some(peer) => peer.clone(),
            None => return Ok(()),
        };

        let bucket_name = self.msg_name().to_string();
        let bucket = match peer.read().throttling.get(&bucket_name) {
            Some(bucket) => bucket,
            None => return Ok(()),
        };

        let (cpu_cost, message_size_cost) = self.throttle_token_cost();
        let result = bucket.lock().throttle(cpu_cost, message_size_cost);

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
