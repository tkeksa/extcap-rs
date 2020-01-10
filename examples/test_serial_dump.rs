use std::fs::OpenOptions;
use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::{Arc, Mutex};
use std::thread;
use std::time::{Duration, SystemTime, UNIX_EPOCH};

use extcap::*;
use futures::prelude::*;
use log::{debug, warn, LevelFilter};
use pcap_file::{pcap::PcapHeader, DataLink, PcapWriter};
use serialport::available_ports;
use simplelog::{Config, SimpleLogger, WriteLogger};
use tokio_serial::{Serial, SerialPortSettings};
use tokio_util::codec::{Decoder, LinesCodec};

const GRP_SERIAL: &str = "Serial";
const OPT_PORT: &str = "port";
const OPT_BAUD: &str = "baud";
const BAUD_RATES: &[u32] = &[9_600, 14_400, 115_200];

struct TestSerialDump {}

struct CaptureCtx {
    pcap_writer: PcapWriter<ExtcapWriter>,
}

impl ExtcapListener for TestSerialDump {
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
        extcap: &Extcap,
        _ifc: &IFace,
        pcap_writer: PcapWriter<ExtcapWriter>,
    ) -> ExtcapResult<()> {
        debug!("capture()");

        // Log list of available ports (already used earlier but now it can be written into log file)
        match available_ports() {
            Ok(ports) => debug!("available_ports: {:?}", ports),
            Err(err) => warn!("available_ports retrieving failed: {:?}", err),
        }

        let port = extcap.get_matches().value_of(OPT_PORT).unwrap();
        debug!("port={}", port);
        let mut settings = SerialPortSettings::default();
        if let Some(baud) = extcap
            .get_matches()
            .value_of(OPT_BAUD)
            .and_then(|s| s.parse::<u32>().ok())
        {
            debug!("baud={}", baud);
            settings.baud_rate = baud;
        }
        let port = Serial::from_path(port, &settings).unwrap();

        let ctx = CaptureCtx { pcap_writer };
        let ctx = Arc::new(Mutex::new(ctx));
        let running = Arc::new(AtomicBool::new(true));

        let r = running.clone();
        ctrlc::set_handler(move || {
            r.store(false, Ordering::SeqCst);
        })
        .expect("Error setting Ctrl-C handler");

        let reader = LinesCodec::new().framed(port);

        let r = running.clone();
        let task = reader.for_each(move |res| {
            match res {
                Ok(msg) => {
                    debug!("line received: '{:?}'", msg);
                    write_pkt(&ctx, &msg);
                }
                Err(err) => {
                    debug!("error during receiving: {:?}", err);
                    r.store(false, Ordering::SeqCst);
                }
            }
            future::ready(())
        });
        tokio::spawn(task);

        loop {
            if !running.load(Ordering::SeqCst) {
                debug!("Error during receiving or Ctrl+C or SIGINT signal received");
                break;
            }
            thread::sleep(Duration::from_millis(50));
        }

        debug!("capture() finished");
        Ok(())
    }
}

fn write_pkt(ctx: &Arc<Mutex<CaptureCtx>>, msg: &str) {
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

#[tokio::main]
async fn main() -> Result<(), Box<dyn std::error::Error>> {
    let mut ex = Extcap::new("test_serial_dump");
    ex.version("0.0.1");
    ex.about("Test serial input (Rust extcap example)");

    // Interface
    let mut tser1 = IFace::new("tser1")
        .description("Test serial input")
        .dlt(DataLink::USER10.into());

    // Interface arguments
    let mut arg_port = IfArg::new_selector(OPT_PORT)
        .display("Port name")
        .tooltip("COM port name")
        .group(GRP_SERIAL);
    let mut ports = available_ports()?;
    ports.sort_by(|a, b| a.port_name.cmp(&b.port_name));
    for p in ports {
        arg_port.add_val(IfArgVal::new(p.port_name));
    }
    tser1.add_arg(arg_port);

    let mut arg_baud = IfArg::new_selector(OPT_BAUD)
        .display("Baud rate")
        .tooltip("COM baud rate")
        .group(GRP_SERIAL);
    for b in BAUD_RATES {
        arg_baud.add_val(IfArgVal::new(b))
    }
    tser1.add_arg(arg_baud);

    tser1.config_debug();
    ex.add_interface(tser1);

    let user = TestSerialDump {};
    ex.run(user)?;

    debug!("DONE");

    Ok(())
}
