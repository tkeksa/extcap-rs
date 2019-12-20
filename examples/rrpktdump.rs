use std::fs::OpenOptions;
use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::Arc;
use std::thread;
use std::time::{Duration, SystemTime, UNIX_EPOCH};

use extcap::*;
use log::{debug, LevelFilter};
use pcap_file::{pcap::PcapHeader, DataLink, PcapWriter};
use rand::Rng;
use simplelog::{Config, SimpleLogger, WriteLogger};

const USAGE_STR: &str = r#"rrpktdump --extcap-interfaces
    rrpktdump --extcap-interface=randpkt --extcap-dlts
    rrpktdump --extcap-interface=randpkt --extcap-config
    rrpktdump --extcap-interface=randpkt --dlt 150 dns --count 10 --fifo=FILENAME --capture"#;

const AFTER_HELP_STR: &str = r#"Notes:
  just example"#;

const OPT_MAXBYTES: &str = "maxbytes";
const OPT_MAXBYTES_DEFAULT: usize = 5000;
const OPT_MAXBYTES_RANGE: &str = "1,5000";
const OPT_COUNT: &str = "count";
const OPT_COUNT_DEFAULT: i32 = 1000;
const OPT_DELAY: &str = "delay";
const OPT_DELAY_DEFAULT: i32 = 0;
const OPT_DLT: &str = "dlt";
const OPT_DLT_DEFAULT: u32 = 147;

struct RRPktDump {}

impl ExtcapListener for RRPktDump {
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
        _ctrp_pipes: Option<CtrlPipes>,
    ) {
        let maxbytes = extcap
            .get_matches()
            .value_of(OPT_MAXBYTES)
            .and_then(|s| s.parse::<usize>().ok())
            .unwrap_or(OPT_MAXBYTES_DEFAULT);
        let count = extcap
            .get_matches()
            .value_of(OPT_COUNT)
            .and_then(|s| s.parse::<i32>().ok())
            .unwrap_or(OPT_COUNT_DEFAULT);
        let delay = extcap
            .get_matches()
            .value_of(OPT_DELAY)
            .and_then(|s| s.parse::<i32>().ok())
            .unwrap_or(OPT_DELAY_DEFAULT);

        debug!(
            "capture() maxbytes={} count={} delay={}",
            maxbytes, count, delay
        );

        let mut rng = rand::thread_rng();
        let delay = Duration::from_millis(if delay > 0 { delay as u64 } else { 0 });
        let running = Arc::new(AtomicBool::new(true));
        let r = running.clone();
        ctrlc::set_handler(move || {
            r.store(false, Ordering::SeqCst);
        })
        .expect("Error setting Ctrl-C handler");
        let mut cnt = 0u32;
        loop {
            if !running.load(Ordering::SeqCst) {
                debug!("Ctrl+C or SIGINT signal received");
                break;
            }
            if (count >= 0) && (cnt == (count as u32)) {
                debug!("count {} reached", cnt);
                break;
            }

            let len = rng.gen_range(1, maxbytes + 1);
            let mut data = vec![0u8; len];
            rng.fill(data.as_mut_slice());
            let ts = SystemTime::now()
                .duration_since(UNIX_EPOCH)
                .expect("SystemTime before UNIX EPOCH");
            let _ = pcap_writer.write(
                ts.as_secs() as u32,
                ts.subsec_micros(),
                &data,
                data.len() as u32,
            );

            cnt += 1;
            thread::sleep(delay);
        }

        debug!("capture() finished");
    }
}

fn main() -> Result<(), Box<dyn std::error::Error>> {
    let mut ex = Extcap::new("rrpktdump");
    ex.version("0.0.1");
    ex.about("Random packets generator (Rust extcap example)");
    ex.help("http://abcd");
    ex.usage(USAGE_STR);
    ex.after_help(AFTER_HELP_STR);
    ex.config_debug();

    // Interface
    let mut rrpkt = IFace::new("rrpkt")
        .description("Rust random packet generator")
        .dlt(OPT_DLT_DEFAULT)
        .dltdescription("DLT_USER0 or non-default value");
    // Interface arguments
    rrpkt.add_arg(
        IfArg::new_unsigned(OPT_MAXBYTES)
            .display("Max bytes in a packet")
            .default(&OPT_MAXBYTES_DEFAULT)
            .range(&OPT_MAXBYTES_RANGE)
            .tooltip("The max number of bytes in a packet"),
    );
    rrpkt.add_arg(
        IfArg::new_long(OPT_COUNT)
            .display("Number of packets")
            .default(&OPT_COUNT_DEFAULT)
            .tooltip("Number of packets to generate (-1 for infinite)"),
    );
    rrpkt.add_arg(
        IfArg::new_integer(OPT_DELAY)
            .display("Packet delay (ms)")
            .default(&OPT_DELAY_DEFAULT)
            .tooltip("Milliseconds to wait after writing each packet"),
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
    rrpkt.add_arg(arg_dlt);

    rrpkt.config_debug();
    ex.add_interface(rrpkt);

    let user = RRPktDump {};
    ex.run(user)?;

    debug!("DONE");

    Ok(())
}
