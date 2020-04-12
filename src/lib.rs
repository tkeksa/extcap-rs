//!
//! This crate helps writing [extcap][wireshark-extcap] plugins for [Wireshark][wireshark].
//!
//! See [Extcap: Developer Guide][wireshark-extcap-dev] also.
//!
//! [wireshark]: https://www.wireshark.org/
//! [wireshark-extcap]: https://www.wireshark.org/docs/man-pages/extcap.html
//! [wireshark-extcap-dev]:https://www.wireshark.org/docs/wsdg_html_chunked/ChCaptureExtcap.html
//!
//! ## Quick Example
//! ```
//! use extcap::{Extcap, ExtcapListener, ExtcapResult, ExtcapWriter, IFace};
//! use pcap_file::{pcap::PcapHeader, DataLink, PcapWriter};
//!
//! struct HelloDump {}
//!
//! impl ExtcapListener for HelloDump {
//!     fn capture_header(&mut self, extcap: &Extcap, ifc: &IFace) -> PcapHeader {
//!         PcapHeader { datalink: DataLink::USER10, ..Default::default() }
//!     }
//!
//!     fn capture(&mut self, extcap: &Extcap, ifc: &IFace, mut pcap_writer: PcapWriter<ExtcapWriter>) -> ExtcapResult<()> {
//!         let pkt = b"Hello Extcap!";
//!         pcap_writer.write(0, 0, pkt, pkt.len() as u32);
//!         Ok(())
//!     }
//! }
//!
//! fn main() -> Result<(), Box<dyn std::error::Error>> {
//!     let mut ex = Extcap::new("hellodump");
//!     ex.add_interface(IFace::new("helloif"));
//!     ex.run(HelloDump {});
//!     Ok(())
//! }
//! ```
//! More examples can be found in the `examples` directory
//!

#![deny(missing_docs)]
#![deny(warnings)]

use std::collections::HashSet;
use std::fmt::Display;
use std::fs::File;
use std::io::{self, Stdout, Write};

use clap::{App, AppSettings, Arg, ArgGroup, ArgMatches};
use log::{debug, warn};
use pcap_file::pcap::{PcapHeader, PcapWriter};

mod error;
pub use crate::error::ExtcapError;

mod iface;
pub use crate::iface::IFace;

mod arg;
pub use crate::arg::{IfArg, IfArgType, IfArgVal};

mod control;
pub use crate::control::{ButtonRole, Control, ControlType, ControlVal};

#[cfg(feature = "ctrl_pipe")]
mod control_pipe;
#[cfg(feature = "ctrl_pipe")]
use crate::control_pipe::ControlPipe;
#[cfg(feature = "ctrl_pipe")]
pub use crate::control_pipe::{ControlCmd, ControlMsg, CtrlPipes};

#[cfg(feature = "ctrl_pipe")]
mod control_pipe_runtime;

const OPT_EXTCAP_VERSION: &str = "extcap-version";
const OPT_EXTCAP_INTERFACES: &str = "extcap-interfaces";
const OPT_EXTCAP_INTERFACE: &str = "extcap-interface";
const OPT_EXTCAP_DTLS: &str = "extcap-dlts";
const OPT_EXTCAP_CONFIG: &str = "extcap-config";
const OPT_EXTCAP_RELOAD_OPTION: &str = "extcap-reload-option";
const OPT_CAPTURE: &str = "capture";
const OPT_EXTCAP_CAPTURE_FILTER: &str = "extcap-capture-filter";
const OPT_FIFO: &str = "fifo";
const OPT_EXTCAP_CONTROL_IN: &str = "extcap-control-in";
const OPT_EXTCAP_CONTROL_OUT: &str = "extcap-control-out";
const OPT_DEBUG: &str = "debug";
const OPT_DEBUG_FILE: &str = "debug-file";

fn print_opt_value<T: Display>(name: &str, value: &Option<T>) {
    if let Some(val) = value {
        print!("{{{}={}}}", name, val);
    }
}

/// Possible writers for `PcapWriter`
pub enum ExtcapWriter {
    /// Writer to stdout
    EWStdout(Stdout),
    /// Writer to file
    EWFile(File),
}

impl Write for ExtcapWriter {
    fn write(&mut self, buf: &[u8]) -> io::Result<usize> {
        match self {
            ExtcapWriter::EWStdout(sout) => sout.write(buf),
            ExtcapWriter::EWFile(file) => file.write(buf),
        }
    }

    fn flush(&mut self) -> io::Result<()> {
        match self {
            ExtcapWriter::EWStdout(sout) => sout.flush(),
            ExtcapWriter::EWFile(file) => file.flush(),
        }
    }
}

#[cfg(feature = "ctrl_pipe")]
fn create_control_pipe(ctrl_in: &str, ctrl_out: &str) -> io::Result<ControlPipe> {
    Ok(ControlPipe::new(
        File::open(ctrl_in)?,
        File::create(ctrl_out)?,
    ))
}

fn create_pcap_writer(fifo: &str, pcap_header: PcapHeader) -> io::Result<PcapWriter<ExtcapWriter>> {
    let writer = if fifo == "-" {
        ExtcapWriter::EWStdout(io::stdout())
    } else {
        ExtcapWriter::EWFile(File::create(fifo)?)
    };
    PcapWriter::with_header(pcap_header, writer)
        .map_err(|e| io::Error::new(io::ErrorKind::Other, format!("{:?}", e)))
}

/// A trait for Extcap callbacks
pub trait ExtcapListener {
    /// Log initialization
    fn init_log(&mut self, _extcap: &Extcap, _debug: bool, _debug_file: Option<&str>) {}

    /// Interfaces update if it depends on passed options
    fn update_interfaces(&mut self, _extcap: &mut Extcap) {}

    /// Interface config reload required for some argument(s)
    fn reload_option(
        &mut self,
        _extcap: &Extcap,
        _ifc: &IFace,
        _arg: &IfArg,
    ) -> Option<Vec<IfArgVal>> {
        None
    }

    /// Get capture header from listener
    fn capture_header(&mut self, extcap: &Extcap, ifc: &IFace) -> PcapHeader;

    /// Main capture loop
    fn capture(
        &mut self,
        _extcap: &Extcap,
        _ifc: &IFace,
        _pcap_writer: PcapWriter<ExtcapWriter>,
    ) -> ExtcapResult<()> {
        unimplemented!()
    }

    /// Main capture loop with optional `CtrlPipes`
    #[cfg(feature = "ctrl_pipe")]
    fn capture_with_ctrl(
        &mut self,
        extcap: &Extcap,
        ifc: &IFace,
        pcap_writer: PcapWriter<ExtcapWriter>,
        _ctrl_pipes: Option<CtrlPipes>,
    ) -> ExtcapResult<()> {
        self.capture(extcap, ifc, pcap_writer)
    }
}

/// Extcap steps
#[derive(Debug)]
pub enum ExtcapStep {
    /// Not determined
    None,
    /// Query for available interfaces
    QueryIfaces,
    /// Ask for DLT’s to each interface
    QueryDlts,
    /// The extcap configuration interface
    ConfigIface {
        /// Reload of some argument invoked
        reload: bool,
    },
    /// The capture process
    Capture {
        /// Control pipes available
        ctrl_pipe: bool,
    },
}

impl Default for ExtcapStep {
    fn default() -> Self {
        ExtcapStep::None
    }
}

/// Extcap specific result
pub type ExtcapResult<T> = Result<T, ExtcapError>;

enum TillCaptureOutcome<T> {
    Finish(T),
    Capture { ifidx: usize },
}

type TillCaptureResult<T> = Result<TillCaptureOutcome<T>, ExtcapError>;

/// Exctcap representation
#[derive(Default)]
pub struct Extcap<'a> {
    step: ExtcapStep,
    app: Option<App<'a, 'a>>,
    app_args: HashSet<String>, // optional user arguments added from interfaces
    matches: Option<ArgMatches<'a>>,
    version: Option<String>,
    helppage: Option<String>,
    ws_version: Option<String>,
    interfaces: Vec<IFace<'a>>,
    reload_opt: bool,
    ifc_debug: bool,
    control: bool,
    controls: Vec<Control>,
}

impl<'a> Extcap<'a> {
    /// Creates a new instance of an `Extcap` requiring a name.
    pub fn new(name: &'a str) -> Self {
        let app = App::new(name)
            .setting(AppSettings::UnifiedHelpMessage)
            .setting(AppSettings::AllowNegativeNumbers)
            //.template(HELP_TEMPLATE)
            .arg(
                Arg::with_name(OPT_EXTCAP_VERSION)
                    .long(OPT_EXTCAP_VERSION)
                    .help("Wireshark version")
                    .takes_value(true)
                    .value_name("ver"),
            )
            .arg(
                Arg::with_name(OPT_EXTCAP_INTERFACES)
                    .long(OPT_EXTCAP_INTERFACES)
                    .help("List the extcap Interfaces"),
            )
            .arg(
                Arg::with_name(OPT_EXTCAP_INTERFACE)
                    .long(OPT_EXTCAP_INTERFACE)
                    .help("Specify the extcap interface")
                    .takes_value(true)
                    .value_name("iface")
                    .conflicts_with(OPT_EXTCAP_INTERFACES),
            )
            .arg(
                Arg::with_name(OPT_EXTCAP_DTLS)
                    .long(OPT_EXTCAP_DTLS)
                    .help("List the DLTs"),
            )
            .arg(
                Arg::with_name(OPT_EXTCAP_CONFIG)
                    .long(OPT_EXTCAP_CONFIG)
                    .help("List the additional configuration for an interface"),
            )
            .arg(
                Arg::with_name(OPT_CAPTURE)
                    .long(OPT_CAPTURE)
                    .help("Run the capture")
                    .requires(OPT_FIFO),
            )
            .group(
                ArgGroup::with_name("if_action")
                    .args(&[OPT_EXTCAP_DTLS, OPT_EXTCAP_CONFIG, OPT_CAPTURE])
                    .multiple(false)
                    .requires(OPT_EXTCAP_INTERFACE),
            )
            .arg(
                Arg::with_name(OPT_EXTCAP_CAPTURE_FILTER)
                    .long(OPT_EXTCAP_CAPTURE_FILTER)
                    .help("The capture filter")
                    .takes_value(true)
                    .value_name("filter")
                    .requires(OPT_CAPTURE),
            )
            .arg(
                Arg::with_name(OPT_FIFO)
                    .long(OPT_FIFO)
                    .help("Dump data to file or fifo")
                    .takes_value(true)
                    .value_name("file")
                    .requires(OPT_CAPTURE),
            );

        Self {
            app: Some(app),
            ..Default::default()
        }
    }

    /// Get current step for which it has been invoked from Wireshark
    pub fn get_step(&self) -> &ExtcapStep {
        &self.step
    }

    fn take_app(&mut self) -> App<'a, 'a> {
        self.app.take().expect("Extcap invalid state: already run")
    }

    fn update_app<F>(&mut self, f: F)
    where
        F: FnOnce(App<'a, 'a>) -> App<'a, 'a>,
    {
        self.app = Some(f(self.take_app()));
    }

    fn app_arg(&mut self, arg: Arg<'a, 'a>) {
        self.app = Some(self.take_app().arg(arg));
    }

    /// Get parsed command line arguments. Provided by `clap::App`.
    pub fn get_matches(&self) -> &ArgMatches<'a> {
        self.matches
            .as_ref()
            .expect("Extcap invalid state: not run yet")
    }

    /// Sets the version string
    pub fn version(&mut self, ver: &'a str) {
        self.version = Some(ver.to_owned());
        self.update_app(|a| a.version(ver));
    }

    /// Sets the help URI
    pub fn help(&mut self, helppage: &'a str) {
        self.helppage = Some(String::from(helppage));
    }

    /// Sets the author string
    pub fn author(&mut self, author: &'a str) {
        self.update_app(|a| a.author(author));
    }

    /// Sets the about string
    pub fn about(&mut self, about: &'a str) {
        self.update_app(|a| a.about(about));
    }

    /// Sets the usage string
    pub fn usage(&mut self, usage: &'a str) {
        self.update_app(|a| a.usage(usage));
    }

    /// Sets the after-help string
    pub fn after_help(&mut self, help: &'a str) {
        self.update_app(|a| a.after_help(help));
    }

    /// Adds an interface
    pub fn add_interface(&mut self, ifc: IFace<'a>) {
        if ifc.has_reloadable_arg() && !self.reload_opt {
            self.config_reload_opt();
        }
        if ifc.has_debug() && !self.ifc_debug {
            self.config_debug();
        }
        for ifa in ifc.get_args() {
            self.config_arg(ifa)
        }
        self.interfaces.push(ifc);
    }

    fn get_if_idx(&self, ifc: &str) -> Option<usize> {
        self.interfaces
            .iter()
            .position(|x| x.get_interface() == ifc)
    }

    fn get_if(&self, ifidx: usize) -> &IFace {
        &self.interfaces[ifidx]
    }

    fn get_if_mut(&mut self, ifidx: usize) -> &mut IFace<'a> {
        &mut self.interfaces[ifidx]
    }

    pub(crate) fn config_arg(&mut self, ifa: &IfArg<'a>) {
        if self.app_args.contains(ifa.get_name()) {
            return;
        }

        let mut arg = Arg::with_name(&ifa.get_name()).long(&ifa.get_name());
        if let Some(hlp) = ifa.get_display() {
            arg = arg.help(hlp);
        }
        arg = arg.takes_value(if let IfArgType::Boolflag = ifa.get_type() {
            false
        } else {
            true
        });
        self.app_arg(arg);

        self.app_args.insert(ifa.get_name().to_owned());
    }

    pub(crate) fn config_reload_opt(&mut self) {
        if self.reload_opt {
            return;
        }
        self.reload_opt = true;
        self.app_arg(
            Arg::with_name(OPT_EXTCAP_RELOAD_OPTION)
                .long(OPT_EXTCAP_RELOAD_OPTION)
                .help("Reload values for the given argument")
                .takes_value(true)
                .value_name("option")
                .requires(OPT_EXTCAP_INTERFACE)
                .requires(OPT_EXTCAP_CONFIG),
        );
        self.app_args.insert(OPT_EXTCAP_RELOAD_OPTION.to_owned());
    }

    pub(crate) fn config_control(&mut self) {
        if self.control {
            return;
        }
        self.control = true;
        self.app_arg(
            Arg::with_name(OPT_EXTCAP_CONTROL_IN)
                .long(OPT_EXTCAP_CONTROL_IN)
                .help("The pipe for control messages from toolbar")
                .takes_value(true)
                .value_name("in-pipe")
                .requires(OPT_CAPTURE),
        );
        self.app_arg(
            Arg::with_name(OPT_EXTCAP_CONTROL_OUT)
                .long(OPT_EXTCAP_CONTROL_OUT)
                .help("The pipe for control messages to toolbar")
                .takes_value(true)
                .value_name("out-pipe")
                .requires(OPT_CAPTURE),
        );
        self.app_args.insert(OPT_EXTCAP_CONTROL_IN.to_owned());
        self.app_args.insert(OPT_EXTCAP_CONTROL_OUT.to_owned());
    }

    fn config_debug(&mut self) {
        if self.ifc_debug {
            return;
        }
        self.ifc_debug = true;
        self.app_arg(
            Arg::with_name(OPT_DEBUG)
                .long(OPT_DEBUG)
                .help("Print additional messages"),
        );
        self.app_arg(
            Arg::with_name(OPT_DEBUG_FILE)
                .long(OPT_DEBUG_FILE)
                .help("Print debug messages to file")
                .takes_value(true)
                .value_name("file"),
        );
        self.app_args.insert(OPT_DEBUG.to_owned());
        self.app_args.insert(OPT_DEBUG_FILE.to_owned());
    }

    /// Adds a control
    pub fn add_control(&mut self, mut control: Control) {
        if !self.control {
            self.config_control();
        }
        control.set_number(self.controls.len());
        self.controls.push(control);
    }

    fn print_version(&self) {
        print!(
            "extcap {{version={}}}",
            self.version.as_ref().map_or("unknown", String::as_ref)
        );
        print_opt_value("help", &self.helppage);
        println!();
    }

    fn print_iface_list(&self) {
        self.interfaces.iter().for_each(IFace::print_iface);
    }

    fn print_control_list(&self) {
        self.controls.iter().for_each(Control::print_control);
    }

    /// Starts main capture loop
    pub fn run<T: ExtcapListener>(mut self, mut listener: T) -> ExtcapResult<()> {
        match self.run_till_capture(&mut listener)? {
            TillCaptureOutcome::Finish(_) => Ok(()),
            TillCaptureOutcome::Capture { ifidx } => {
                self.capture(&mut listener, self.get_if(ifidx))
            }
        }
    }

    fn run_till_capture<T: ExtcapListener>(&mut self, listener: &mut T) -> TillCaptureResult<()> {
        // Save matches for listener
        self.matches = Some(self.take_app().get_matches_safe()?);

        // Determine the step
        self.step = if self.get_matches().is_present(OPT_EXTCAP_INTERFACES) {
            ExtcapStep::QueryIfaces
        } else if self.get_matches().is_present(OPT_EXTCAP_DTLS) {
            ExtcapStep::QueryDlts
        } else if self.get_matches().is_present(OPT_EXTCAP_CONFIG) {
            let reload = self.get_matches().is_present(OPT_EXTCAP_RELOAD_OPTION);
            ExtcapStep::ConfigIface { reload }
        } else if self.get_matches().is_present(OPT_CAPTURE) {
            let ctrl_pipe = self.get_matches().is_present(OPT_EXTCAP_CONTROL_IN)
                && self.get_matches().is_present(OPT_EXTCAP_CONTROL_OUT);
            ExtcapStep::Capture { ctrl_pipe }
        } else {
            ExtcapStep::None
        };

        // Log initialization
        let debug = self.get_matches().is_present(OPT_DEBUG);
        let debug_file = self.get_matches().value_of(OPT_DEBUG_FILE).and_then(|s| {
            if s.trim().is_empty() {
                None
            } else {
                Some(s)
            }
        });
        listener.init_log(&self, debug, debug_file);
        debug!("=======================");
        debug!(
            "Log initialized debug={} debug_file={}",
            debug,
            debug_file.unwrap_or_default()
        );
        debug!("step = {:?}", self.step);
        debug!("env::args = {:?}", std::env::args());

        // Save version for listener
        self.ws_version = self
            .get_matches()
            .value_of(OPT_EXTCAP_VERSION)
            .map(String::from);
        debug!(
            "Wireshark version {}",
            self.ws_version
                .as_ref()
                .map_or("-not provided-", String::as_str)
        );

        // Call listener interfaces update if it depends on passed options
        listener.update_interfaces(self);

        if let ExtcapStep::QueryIfaces = self.get_step() {
            debug!("list of interfaces required");
            self.print_version();
            self.print_iface_list();
            self.print_control_list();
            return Ok(TillCaptureOutcome::Finish(()));
        }

        let ifidx = self
            .get_matches()
            .value_of(OPT_EXTCAP_INTERFACE)
            .map_or_else(
                || Err(ExtcapError::missing_interface()),
                |ifnm| {
                    self.get_if_idx(ifnm)
                        .ok_or_else(|| ExtcapError::invalid_interface(ifnm))
                },
            )?;

        debug!("interface = {}", self.get_if(ifidx).get_interface());
        match self.get_step() {
            ExtcapStep::QueryDlts => {
                debug!("interface DLTs required");
                self.get_if(ifidx).print_dlt_list();
                Ok(TillCaptureOutcome::Finish(()))
            }
            ExtcapStep::ConfigIface { .. } => {
                if let Some(arg) = self.get_matches().value_of(OPT_EXTCAP_RELOAD_OPTION) {
                    let arg = arg.to_owned(); // ends self immutable borrow
                    debug!("interface config reload required for '{}' argument", arg);
                    self.reload_option(listener, ifidx, &arg);
                } else {
                    debug!("interface config required");
                    self.get_if(ifidx).print_arg_list();
                }
                Ok(TillCaptureOutcome::Finish(()))
            }
            ExtcapStep::Capture { .. } => Ok(TillCaptureOutcome::Capture { ifidx }),
            _ => Err(ExtcapError::unknown_step()),
        }
    }

    fn reload_option<T: ExtcapListener>(&mut self, listener: &mut T, ifidx: usize, arg: &str) {
        let ifc = self.get_if(ifidx);
        let aidx = if let Some(aidx) = ifc.get_arg_idx(arg) {
            aidx
        } else {
            warn!(
                "reload_option() arg '{}' not available for interface '{}'",
                arg,
                ifc.get_interface()
            );
            return;
        };

        if let Some(nargs) = listener.reload_option(self, ifc, ifc.get_arg(aidx)) {
            debug!(
                "reload_option() arg '{}' for interface '{}' has got {} values",
                arg,
                ifc.get_interface(),
                nargs.len()
            );
            let arg = self.get_if_mut(ifidx).get_arg_mut(aidx);
            arg.reload_option(nargs);
        } else {
            debug!(
                "reload_option() arg '{}' for interface '{}' nothing has changed",
                arg,
                ifc.get_interface()
            );
        };

        self.get_if(ifidx).get_arg(aidx).print_arg();
    }

    fn capture<T: ExtcapListener>(&self, listener: &mut T, ifc: &IFace) -> ExtcapResult<()> {
        let fifo = self.get_matches().value_of(OPT_FIFO).unwrap();
        let capture_filter = self.get_matches().value_of(OPT_EXTCAP_CAPTURE_FILTER);
        debug!(
            "capture required fifo={} capture_filter={}",
            fifo,
            capture_filter.unwrap_or_default()
        );
        #[cfg(feature = "ctrl_pipe")]
        let mut control_pipe = {
            let control_in = self.get_matches().value_of(OPT_EXTCAP_CONTROL_IN);
            let control_out = self.get_matches().value_of(OPT_EXTCAP_CONTROL_OUT);
            if let (Some(ctrl_in), Some(ctrl_out)) = (control_in, control_out) {
                debug!("capture with control in={} out={}", ctrl_in, ctrl_out);
                match create_control_pipe(ctrl_in, ctrl_out) {
                    Ok(ctrl_pipe) => Some(ctrl_pipe),
                    Err(e) => {
                        warn!(
                            "create_control_pipe(ctrl_in={}, ctrl_out={}), failed with error {}",
                            ctrl_in, ctrl_out, e
                        );
                        None
                    }
                }
            } else {
                None
            }
        };
        let ph = listener.capture_header(self, ifc);
        debug!("capture pcap header: {:?}", ph);
        let pw = create_pcap_writer(fifo, ph)?;
        #[cfg(feature = "ctrl_pipe")]
        let res = {
            let ctrl_pipe = control_pipe.as_mut().map(control_pipe::ControlPipe::start);
            debug!(
                "capture starting {} ctrl pipes",
                if ctrl_pipe.is_some() {
                    "with"
                } else {
                    "without"
                }
            );
            let res = listener.capture_with_ctrl(self, ifc, pw, ctrl_pipe);
            if let Some(cp) = control_pipe {
                cp.stop();
            }
            res
        };
        #[cfg(not(feature = "ctrl_pipe"))]
        let res = {
            debug!("capture starting");
            listener.capture(self, ifc, pw)
        };
        debug!("capture finished: {:?}", res);

        res
    }
}
