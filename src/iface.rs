use pcap_file::DataLink;

use crate::arg::IfArg;
use crate::print_opt_value;

/// Interface representation
#[derive(Default)]
pub struct IFace<'a> {
    interface: String,
    descr: Option<String>,
    dlt: u32,
    dltname: Option<String>,
    dltdescr: Option<String>,
    args: Vec<IfArg<'a>>,
    debug: bool,
}

impl<'a> IFace<'a> {
    /// Creates a new instance of `IFace` using a string name
    pub fn new(interface: &str) -> Self {
        Self {
            interface: interface.to_owned(),
            dlt: DataLink::USER0.into(), // DLT_USER0 default
            ..Default::default()
        }
    }

    /// Gets interface name
    pub fn get_interface(&self) -> &str {
        &self.interface
    }

    /// Sets the description
    pub fn description(mut self, descr: &str) -> Self {
        self.descr = Some(descr.to_owned());
        self
    }

    /// Sets the DLT
    pub fn dlt(mut self, dlt: u32) -> Self {
        self.dlt = dlt;
        self
    }

    /// Sets the DLT name
    pub fn dltname(mut self, dltname: &str) -> Self {
        self.dltname = Some(dltname.to_owned());
        self
    }

    /// Sets the DLT description
    pub fn dltdescription(mut self, dltdescr: &str) -> Self {
        self.dltdescr = Some(dltdescr.to_owned());
        self
    }

    /// Adds argument
    pub fn add_arg(&mut self, mut arg: IfArg<'a>) {
        arg.set_number(self.args.len());
        self.args.push(arg);
    }

    pub(crate) fn get_args(&self) -> &[IfArg<'a>] {
        &self.args
    }

    pub(crate) fn get_arg_idx(&self, arg: &str) -> Option<usize> {
        self.args.iter().position(|x| x.get_name() == arg)
    }

    pub(crate) fn get_arg(&self, aidx: usize) -> &IfArg {
        &self.args[aidx]
    }

    pub(crate) fn get_arg_mut(&mut self, aidx: usize) -> &mut IfArg<'a> {
        &mut self.args[aidx]
    }

    pub(crate) fn has_reloadable_arg(&self) -> bool {
        self.args.iter().any(IfArg::has_reload)
    }

    pub(crate) fn has_debug(&self) -> bool {
        self.debug
    }

    /// Configures debug arguments `debug` and `debug-file`
    pub fn config_debug(&mut self) {
        if self.debug {
            return;
        }
        self.debug = true;
        self.add_arg(
            IfArg::new_boolflag("debug")
                .display("Run in debug mode")
                .default(&"false")
                .tooltip("Print debug messages")
                .group("Debug"),
        );
        self.add_arg(
            IfArg::new_string("debug-file")
                .display("Use a file for debug")
                .tooltip("Set a file where the debug messages are written")
                .group("Debug"),
        );
    }

    pub(crate) fn print_iface(&self) {
        print!("interface {{value={}}}", self.interface);
        print_opt_value("display", &self.descr);
        println!();
    }

    pub(crate) fn print_dlt_list(&self) {
        print!(
            "dlt {{number={}}}{{name={}}}",
            self.dlt,
            self.dltname.as_ref().unwrap_or(&self.interface)
        );
        print_opt_value("display", &self.dltdescr);
        println!();
    }

    pub(crate) fn print_arg_list(&self) {
        self.args.iter().for_each(IfArg::print_arg);
    }
}
