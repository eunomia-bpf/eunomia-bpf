use std::io::{Cursor, Seek, SeekFrom};
use std::sync::{Arc, Mutex};
use std::{
    thread,
    time::{Duration, Instant},
};

use actix::{Actor, ActorContext, AsyncContext, StreamHandler};
use actix_web::web;
use actix_web_actors::ws;
use log::info;

use super::server::AppState;

/// How often heartbeat pings are sent
const HEARTBEAT_INTERVAL: Duration = Duration::from_secs(5);

/// How long before lack of client response causes a timeout
const CLIENT_TIMEOUT: Duration = Duration::from_secs(10);

pub struct LogWs {
    pub data: web::Data<AppState>,
    pub hb: Instant,
}

impl Actor for LogWs {
    type Context = ws::WebsocketContext<Self>;
    fn started(&mut self, ctx: &mut Self::Context) {
        self.hb(ctx);
    }
}

impl LogWs {
    fn hb(&self, ctx: &mut ws::WebsocketContext<Self>) {
        ctx.run_interval(HEARTBEAT_INTERVAL, |act, ctx| {
            // check client heartbeats
            if Instant::now().duration_since(act.hb) > CLIENT_TIMEOUT {
                // heartbeat timed out
                println!("Websocket Client heartbeat failed, disconnecting!");

                // stop actor
                ctx.stop();

                // don't try to send a ping
                return;
            }

            ctx.ping(b"");
        });
    }
}

const BUFFER_SIZE: usize = 64;

struct MsgBuf {
    buffer: [u8; BUFFER_SIZE],
    count: usize,
}

impl MsgBuf {
    fn new() -> Self {
        Self {
            buffer: [0u8; BUFFER_SIZE],
            count: 0,
        }
    }

    fn msg_filled(&mut self, message: &u8) -> bool {
        let remaining_space = BUFFER_SIZE - self.count;

        if remaining_space == 0 {
            self.count = 0;
            return true;
        }

        self.buffer[self.count] = *message;
        self.count += 1;
        false
    }
}

impl ToString for MsgBuf {
    fn to_string(&self) -> String {
        String::from_utf8(self.buffer.to_vec()).expect("unexpected char")
    }
}

impl StreamHandler<Result<ws::Message, ws::ProtocolError>> for LogWs {
    fn handle(&mut self, msg: Result<ws::Message, ws::ProtocolError>, ctx: &mut Self::Context) {
        let msg = match msg {
            Err(_) => {
                ctx.stop();
                return;
            }
            Ok(msg) => msg,
        };

        log::debug!("WEBSOCKET MESSAGE: {msg:?}");

        match msg {
            ws::Message::Ping(msg) => {
                self.hb = Instant::now();
                ctx.pong(&msg);
            }
            ws::Message::Pong(_) => {
                self.hb = Instant::now();
            }
            ws::Message::Text(text) => {
                let json_msg: serde_json::Value = serde_json::from_str(text.trim()).unwrap();

                let prog_id = usize::try_from(json_msg["id"].as_i64().unwrap()).unwrap();

                let follow = bool::try_from(json_msg["follow"].as_bool().unwrap()).unwrap();

                let prog_type = crate::config::ProgramType::WasmModule;

                // let prog_type = self.data;

                match prog_type {
                    crate::config::ProgramType::WasmModule => {
                        if follow {
                            for _ in 0..5 {
                                thread::sleep(Duration::from_secs(3));

                                info!("hey");

                                // let stdout = self
                                //     .data
                                //     .wasm_tasks
                                //     .get(&prog_id)
                                //     .unwrap()
                                //     .log_msg
                                //     .stdout
                                //     .clone();

                                // let stdout = stdout.get_read_lock();
                                // let mut buffer = MsgBuf::new();
                                // let log = String::from_utf8(stdout.get_ref().to_vec());
                                // ctx.text(log.unwrap());
                                // drop(stdout)
                            }
                            // loop {
                            // thread::sleep(Duration::from_secs(3));
                            // info!("sendding");
                            // ctx.text("testAFIAJELIGJLIAEGLVFA")
                            // }
                        } else {
                            // let stdout = self
                            //     .data
                            //     .wasm_tasks
                            //     .get(&prog_id)
                            //     .unwrap()
                            //     .log_msg
                            //     .stdout
                            //     .read_log_all();
                            // ctx.text(stdout.unwrap());
                            ctx.close(Some(ws::CloseReason {
                                code: ws::CloseCode::Normal,
                                description: Some("Transport complete".to_string()),
                            }));
                            ctx.stop();
                        }
                    }
                    _ => todo!(),
                }
            }
            ws::Message::Binary(_) => println!("Unexpected binary"),
            ws::Message::Close(reason) => {
                ctx.close(reason);
                ctx.stop();
            }
            ws::Message::Continuation(_) => {
                ctx.stop();
            }
            ws::Message::Nop => (),
        }
    }
}
