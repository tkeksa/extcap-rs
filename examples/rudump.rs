use std::fs::OpenOptions;
use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::Arc;
use std::time::{SystemTime, UNIX_EPOCH};

use extcap::*;
use log::{debug, warn, LevelFilter};
use pcap_file::{pcap::PcapHeader, DataLink, PcapWriter};
use simplelog::{Config, SimpleLogger, WriteLogger};
use std::net::{SocketAddr, UdpSocket};

const USAGE_STR: &str = r#"rudump --extcap-interfaces
    rudump --extcap-interface=randpkt --extcap-dlts
    rudump --extcap-interface=randpkt --extcap-config
    rudump --extcap-interface=randpkt --dlt 150 --port 5566 --fifo=FILENAME --capture"#;

const AFTER_HELP_STR: &str = r#"Notes:
  just example"#;

const OPT_PORT: &str = "port";
const OPT_PORT_DEFAULT: u16 = 5555;
const OPT_PORT_RANGE: &str = "1,65535";
const OPT_DLT: &str = "dlt";
const OPT_DLT_DEFAULT: u32 = 147;

const BUF_LEN: usize = 4096;

struct RUdpDump {}

impl ExtcapListener for RUdpDump {
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

    fn capture_header(&mut self, extcap: &Extcap, _ifc: &IFace) -> PcapHeader {
        let dlt = extcap
            .get_matches()
            .value_of(OPT_DLT)
            .and_then(|s| s.parse::<u32>().ok())
            .unwrap_or(OPT_DLT_DEFAULT);

        debug!("capture_header() dlt={}", dlt);

        PcapHeader {
            datalink: DataLink::from(dlt),
            ..Default::default()
        }
    }

    fn capture(
        &mut self,
        extcap: &Extcap,
        _ifc: &IFace,
        mut pcap_writer: PcapWriter<ExtcapWriter>,
        _ctrl_pipes: Option<CtrlPipes>,
    ) {
        let port = extcap
            .get_matches()
            .value_of(OPT_PORT)
            .and_then(|s| s.parse::<u16>().ok())
            .unwrap_or(OPT_PORT_DEFAULT);

        debug!("capture() port={}", port);

        let sa = SocketAddr::from(([0, 0, 0, 0], port));
        let socket = UdpSocket::bind(sa).expect("couldn't bind to address");
        let mut buf = [0; BUF_LEN];
        let running = Arc::new(AtomicBool::new(true));
        let r = running.clone();
        ctrlc::set_handler(move || {
            r.store(false, Ordering::SeqCst);
        })
        .expect("Error setting Ctrl-C handler");
        loop {
            if !running.load(Ordering::SeqCst) {
                debug!("Ctrl+C or SIGINT signal received");
                break;
            }

            let rcv_len = match socket.recv_from(&mut buf) {
                Ok((len, _)) => len,
                Err(e) => {
                    warn!("recv_from() failed {}", e);
                    continue;
                }
            };
            let ts = SystemTime::now()
                .duration_since(UNIX_EPOCH)
                .expect("SystemTime before UNIX EPOCH");
            let _ = pcap_writer.write(
                ts.as_secs() as u32,
                ts.subsec_micros(),
                &buf[..rcv_len],
                rcv_len as u32,
            );
        }

        debug!("capture() finished");
    }
}

fn main() -> Result<(), Box<dyn std::error::Error>> {
    let mut ex = Extcap::new("rudump");
    ex.version("0.0.1");
    ex.about("UDP Listener remote capture (Rust extcap example)");
    ex.help("http://abcd");
    ex.usage(USAGE_STR);
    ex.after_help(AFTER_HELP_STR);

    // Interface
    let mut rudump = IFace::new("rudump")
        .description("Rust UDP Listener remote capture")
        .dlt(OPT_DLT_DEFAULT)
        .dltdescription("DLT_USER0 or non-default value");
    // Interface arguments
    rudump.add_arg(
        IfArg::new_unsigned(OPT_PORT)
            .display("Listen port")
            .default(&OPT_PORT_DEFAULT)
            .range(&OPT_PORT_RANGE)
            .tooltip("The port the receiver listens on"),
    );
    let mut arg_dlt = IfArg::new_selector(OPT_DLT)
        .display("DLT number")
        .default(&OPT_DLT_DEFAULT)
        .tooltip("DLT_USER0-DLT_USER15");
    for dlt in u32::from(DataLink::USER0)..=u32::from(DataLink::USER15) {
        arg_dlt.add_val(
            IfArgVal::new(dlt).display(&format!("DLT_USER{}", dlt - u32::from(DataLink::USER0))),
        );
    }
    rudump.add_arg(arg_dlt);

    rudump.config_debug();
    ex.add_interface(rudump);

    let user = RUdpDump {};
    ex.run(user)?;

    debug!("DONE");

    Ok(())
}
