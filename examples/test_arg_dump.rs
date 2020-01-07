use std::fs::OpenOptions;
use std::time::{SystemTime, UNIX_EPOCH};

use extcap::*;
use log::{debug, LevelFilter};
use pcap_file::{pcap::PcapHeader, DataLink, PcapWriter};
use simplelog::{Config, SimpleLogger, WriteLogger};

const OPT_SERVER: &str = "server";
const OPT_SERVER_VALID: &str = "\\\\b(?:(?:25[0-5]|2[0-4][0-9]|[01]?[0-9][0-9]?)\\\\.){3}(?:25[0-5]|2[0-4][0-9]|[01]?[0-9][0-9]?)\\\\b";
const OPT_DLT_MAX: &str = "dlt-max";
const OPT_DLT_MAX_DEFAULT: u32 = 162;
const OPT_DLT: &str = "dlt";
const OPT_DLT_DEFAULT: u32 = 147;

struct TestArgDump {}

impl ExtcapListener for TestArgDump {
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

    fn reload_option(
        &mut self,
        extcap: &Extcap,
        _ifc: &IFace,
        _arg: &IfArg,
    ) -> Option<Vec<IfArgVal>> {
        let dlt_max = extcap
            .get_matches()
            .value_of(OPT_DLT_MAX)
            .and_then(|s| s.parse::<u32>().ok())
            .unwrap_or(OPT_DLT_MAX_DEFAULT);
        debug!("reload_option() dlt_max={}", dlt_max);
        let vals = (u32::from(DataLink::USER0)..=dlt_max)
            .map(|dlt| {
                IfArgVal::new(dlt).display(&format!("DLT_USER{}", dlt - u32::from(DataLink::USER0)))
            })
            .collect::<Vec<_>>();
        Some(vals)
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
        let mut msg = "Test arguments:\n".to_string();
        for a in &[OPT_SERVER, OPT_DLT_MAX, OPT_DLT] {
            if let Some(v) = extcap.get_matches().value_of(a) {
                msg += &format!("{}={}\n", a, v);
            }
        }

        debug!("capture() {}", msg);

        let ts = SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .expect("SystemTime before UNIX EPOCH");
        let _ = pcap_writer.write(
            ts.as_secs() as u32,
            ts.subsec_micros(),
            msg.as_bytes(),
            msg.as_bytes().len() as u32,
        );

        debug!("capture() finished");
    }
}

fn main() -> Result<(), Box<dyn std::error::Error>> {
    let mut ex = Extcap::new("test_arg_dump");
    ex.version("0.0.1");
    ex.about("Test extcap arguments (Rust extcap example)");

    // Interface
    let mut tadump = IFace::new("tadump")
        .description("Test extcap arguments")
        .dlt(OPT_DLT_DEFAULT)
        .dltdescription("DLT_USER0 or non-default value");
    // Interface arguments
    tadump.add_arg(
        IfArg::new_string(OPT_SERVER)
            .display("Server IP")
            .validation(&OPT_SERVER_VALID),
    );
    let mut arg_dlt_max = IfArg::new_selector(OPT_DLT_MAX)
        .display("Max. DLT number")
        .default(&OPT_DLT_MAX_DEFAULT)
        .tooltip("DLT_USER0-DLT_USER15");
    for dlt in u32::from(DataLink::USER0)..=u32::from(DataLink::USER15) {
        arg_dlt_max.add_val(
            IfArgVal::new(dlt).display(&format!("DLT_USER{}", dlt - u32::from(DataLink::USER0))),
        );
    }
    tadump.add_arg(arg_dlt_max);
    let arg_dlt = IfArg::new_selector(OPT_DLT)
        .display("DLT number")
        .default(&OPT_DLT_DEFAULT)
        .reload(true)
        .placeholder("Load DLTs...")
        .tooltip("DLT_USER0-DLT_USERmax");
    tadump.add_arg(arg_dlt);

    tadump.config_debug();
    ex.add_interface(tadump);

    let user = TestArgDump {};
    ex.run(user)?;

    debug!("DONE");

    Ok(())
}
