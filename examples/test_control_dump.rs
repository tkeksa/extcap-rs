use std::fmt::Display;
use std::fs::OpenOptions;
use std::time::{SystemTime, UNIX_EPOCH};

use extcap::*;
use futures::channel::mpsc::{self, Receiver, Sender};
use futures::prelude::*;
use log::{debug, LevelFilter};
use pcap_file::{pcap::Packet, pcap::PcapHeader, DataLink};
use simplelog::{Config, SimpleLogger, WriteLogger};

struct TestControlDump {}

struct CaptureCtx {
    extcap_sender: Sender<Packet<'static>>,
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

    fn capture_async_with_ctrl(
        &mut self,
        _extcap: &Extcap,
        _ifc: &IFace,
        ctrl_pipes: Option<CtrlPipes>,
    ) -> ExtcapResult<ExtcapReceiver> {
        debug!("capture_async()");

        let (pipe_in, pipe_out) = if let Some((pi, po)) = ctrl_pipes {
            (Some(pi), Some(po))
        } else {
            (None, None)
        };

        let (snd, rcv) = mpsc::channel(128);

        let ctx = CaptureCtx {
            extcap_sender: snd,
            pipe_out,
        };

        tokio::spawn(task(ctx, pipe_in));

        debug!("capture_async() started");
        Ok(rcv)
    }
}

async fn task(mut ctx: CaptureCtx, pipe_in: Option<Receiver<ControlMsg>>) {
    write_log(&mut ctx, "Begin").await;
    write_msg(&mut ctx.extcap_sender, "Begin").await;

    if let Some(mut pi) = pipe_in {
        while let Some(msg) = pi.next().await {
            debug!("capture() ctrl msg received {:?}", msg);
            write_msg(&mut ctx.extcap_sender, &format!("{:?}", msg)).await;
            write_log(&mut ctx, &format!("{:?}", msg)).await;
            if let ControlCmd::Set = msg.get_command() {
                if msg.get_ctrl_num() == 3 {
                    debug!("Stop pressed");
                    break;
                }
            }
        }
    }

    write_log(&mut ctx, "End").await;
    write_msg(&mut ctx.extcap_sender, "End").await;
}

async fn write_msg(snd: &mut Sender<Packet<'static>>, msg: &str) {
    debug!("write_msg() {}", msg);
    let ts = SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .expect("SystemTime before UNIX EPOCH");
    let pkt = Packet::new_owned(
        ts.as_secs() as u32,
        ts.subsec_micros(),
        msg.as_bytes().to_vec(),
        msg.as_bytes().len() as u32,
    );
    let _ = snd.send(pkt).await;
}

async fn write_log<T: Display>(ctx: &mut CaptureCtx, msg: T) {
    if let Some(po) = &mut ctx.pipe_out {
        let line = format!("{}\n", msg);
        let _ = po
            .send(ControlMsg::new(4, ControlCmd::Add, line.as_bytes()))
            .await;
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
    ex.run_async(user).await?;

    debug!("DONE");

    Ok(())
}
