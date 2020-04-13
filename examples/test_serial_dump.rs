use std::fs::OpenOptions;
use std::time::{SystemTime, UNIX_EPOCH};

use extcap::*;
use futures::channel::mpsc::{self, Sender};
use futures::prelude::*;
use log::{debug, warn, LevelFilter};
use pcap_file::{pcap::Packet, pcap::PcapHeader, DataLink};
use serialport::available_ports;
use simplelog::{Config, SimpleLogger, WriteLogger};
use tokio_serial::{Serial, SerialPortSettings};
use tokio_util::codec::{FramedRead, LinesCodec};

const GRP_SERIAL: &str = "Serial";
const OPT_PORT: &str = "port";
const OPT_BAUD: &str = "baud";
const BAUD_RATES: &[u32] = &[9_600, 14_400, 115_200];

struct TestSerialDump {}

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

    fn capture_async(&mut self, extcap: &Extcap, _ifc: &IFace) -> ExtcapResult<ExtcapReceiver> {
        debug!("capture_async()");

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

        let (snd, rcv) = mpsc::channel(128);

        tokio::spawn(task(port, snd));

        debug!("capture_async() started");
        Ok(rcv)
    }
}

async fn task(port: Serial, mut sender: Sender<Packet<'static>>) {
    let mut reader = FramedRead::new(port, LinesCodec::new());
    while let Some(res) = reader.next().await {
        match res {
            Ok(msg) => {
                debug!("line received: '{:?}'", msg);
                write_pkt(&mut sender, &msg).await;
            }
            Err(err) => {
                debug!("error during receiving: {:?}", err);
                break;
            }
        }
    }
}

async fn write_pkt(snd: &mut Sender<Packet<'static>>, msg: &str) {
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
    ex.run_async(user).await?;

    debug!("DONE");

    Ok(())
}
