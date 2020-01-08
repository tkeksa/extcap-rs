use std::fmt::Display;
use std::fs::OpenOptions;
use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::{Arc, Mutex};
use std::thread;
use std::time::{Duration, SystemTime, UNIX_EPOCH};

use extcap::*;
use futures::channel::mpsc::Sender;
use futures::prelude::*;
use log::{debug, LevelFilter};
use pcap_file::{pcap::PcapHeader, DataLink, PcapWriter};
use simplelog::{Config, SimpleLogger, WriteLogger};
use tokio;

struct TestControlDump {}

struct CaptureCtx {
    pcap_writer: PcapWriter<ExtcapWriter>,
    pipe_out: Option<Sender<ControlMsg>>,
}

impl ExtcapListener for TestControlDump {
    fn init_log(&mut self, _extcap: &Extcap, debug: bool, debug_file: Option<&str>) {
        let lvl = if debug {
            LevelFilter::Debug
        } else {
            LevelFilter::Warn
        };
        if let Some(file) = debug_file {
            let _ = WriteLogger::init(
                lvl,
                Config::default(),
                OpenOptions::new()
                    .create(true)
                    .append(true)
                    .open(file)
                    .unwrap(),
            );
        } else {
            let _ = SimpleLogger::init(lvl, Config::default());
        }
    }

    fn capture_header(&mut self, _extcap: &Extcap, _ifc: &IFace) -> PcapHeader {
        debug!("capture_header()");

        PcapHeader {
            datalink: DataLink::USER10,
            ..Default::default()
        }
    }

    fn capture(
        &mut self,
        _extcap: &Extcap,
        _ifc: &IFace,
        pcap_writer: PcapWriter<ExtcapWriter>,
        ctrl_pipes: Option<CtrlPipes>,
    ) -> ExtcapResult<()> {
        debug!("capture()");

        let (pipe_in, pipe_out) = if let Some((pi, po)) = ctrl_pipes {
            (Some(pi), Some(po))
        } else {
            (None, None)
        };
        let ctx = CaptureCtx {
            pcap_writer,
            pipe_out,
        };
        let ctx = Arc::new(Mutex::new(ctx));
        let running = Arc::new(AtomicBool::new(true));

        write_log(&ctx, "Begin");
        write_msg(&ctx, "Begin");

        if let Some(pi) = pipe_in {
            let cx = ctx.clone();
            let r = running.clone();
            let task = pi.for_each(move |msg| {
                debug!("capture() ctrl msg received {:?}", msg);
                write_msg(&cx, &format!("{:?}", msg));
                write_log(&cx, &format!("{:?}", msg));
                if let ControlCmd::Set = msg.get_command() {
                    if msg.get_ctrl_num() == 3 {
                        debug!("Stop pressed");
                        r.store(false, Ordering::SeqCst);
                    }
                }
                future::ready(())
            });
            tokio::spawn(task);
        }

        loop {
            if !running.load(Ordering::SeqCst) {
                debug!("Stop command received");
                break;
            }
            thread::sleep(Duration::from_millis(50));
        }

        write_log(&ctx, "End");
        write_msg(&ctx, "End");

        debug!("capture() finished");
        Ok(())
    }
}

fn write_msg(ctx: &Arc<Mutex<CaptureCtx>>, msg: &str) {
    debug!("write_msg() {}", msg);
    let pcap_writer = &mut ctx.lock().unwrap().pcap_writer;
    let ts = SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .expect("SystemTime before UNIX EPOCH");
    let _ = pcap_writer.write(
        ts.as_secs() as u32,
        ts.subsec_micros(),
        msg.as_bytes(),
        msg.as_bytes().len() as u32,
    );
}

fn write_log<T: Display>(ctx: &Arc<Mutex<CaptureCtx>>, msg: T) {
    if let Some(po) = ctx.lock().unwrap().pipe_out.as_mut() {
        let line = format!("{}\n", msg);
        let _ = po.try_send(ControlMsg::new(4, ControlCmd::Add, line.as_bytes()));
    }
}

#[tokio::main]
async fn main() -> Result<(), Box<dyn std::error::Error>> {
    let mut ex = Extcap::new("test_control_dump");
    ex.version("0.0.1");
    ex.about("Test extcap controls (Rust extcap example)");
    ex.help("http://abcd");

    // Interfaces
    let mut tcdump1 = IFace::new("tcdump1")
        .description("Test extcap controls No.1")
        .dlt(DataLink::USER10.into());
    tcdump1.config_debug();
    ex.add_interface(tcdump1);
    let mut tcdump2 = IFace::new("tcdump2")
        .description("Test extcap controls No.2")
        .dlt(DataLink::USER10.into());
    tcdump2.config_debug();
    ex.add_interface(tcdump2);

    // Controls
    ex.add_control(
        Control::new_boolean()
            .display("Boolean 0")
            .tooltip("Checkbox 0"),
    );
    ex.add_control(
        Control::new_string()
            .display("String 1")
            .tooltip("Text 1")
            .placeholder("Enter something ..."),
    );

    let mut sel2 = Control::new_selector().display("Select 2");
    sel2.add_val(ControlVal::new("V1"));
    sel2.add_val(ControlVal::new("V2").display("Val2"));
    sel2.add_val(ControlVal::new("V3"));
    ex.add_control(sel2);

    ex.add_control(
        Control::new_button(ButtonRole::Control)
            .display("Stop 3")
            .tooltip("Stop capture"),
    );
    ex.add_control(Control::new_button(ButtonRole::Logger).display("Log 4"));
    ex.add_control(Control::new_button(ButtonRole::Help).display("Help 5"));
    ex.add_control(Control::new_button(ButtonRole::Restore).display("Restore 6"));

    let user = TestControlDump {};
    ex.run(user)?;

    debug!("DONE");

    Ok(())
}
