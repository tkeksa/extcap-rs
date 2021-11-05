use crate::print_opt_value;

/// Extcap Argument types
#[derive(Copy, Clone)]
pub enum IfArgType {
    /// None or unknown
    None,
    /// EXTCAP_ARG_INTEGER
    Integer,
    /// EXTCAP_ARG_UNSIGNED
    Unsigned,
    /// EXTCAP_ARG_LONG
    Long,
    /// EXTCAP_ARG_DOUBLE
    Double,
    /// EXTCAP_ARG_STRING
    String,
    /// EXTCAP_ARG_PASSWORD
    Password,
    /// EXTCAP_ARG_BOOLEAN
    Boolean,
    /// EXTCAP_ARG_BOOLFLAG
    Boolflag,
    /// EXTCAP_ARG_FILESELECT
    Fileselect,
    /// EXTCAP_ARG_SELECTOR
    Selector,
    /// EXTCAP_ARG_RADIO
    Radio,
    /// EXTCAP_ARG_MULTICHECK
    Multicheck,
    /// EXTCAP_ARG_TIMESTAMP
    Timestamp,
}

impl Default for IfArgType {
    fn default() -> Self {
        IfArgType::None
    }
}

impl IfArgType {
    fn type_str(&self) -> &'static str {
        match self {
            IfArgType::None => "none",
            IfArgType::Integer => "integer",
            IfArgType::Unsigned => "unsigned",
            IfArgType::Long => "long",
            IfArgType::Double => "double",
            IfArgType::String => "string",
            IfArgType::Password => "password",
            IfArgType::Boolean => "boolean",
            IfArgType::Boolflag => "boolflag",
            IfArgType::Fileselect => "fileselect",
            IfArgType::Selector => "selector",
            IfArgType::Radio => "radio",
            IfArgType::Multicheck => "multicheck",
            IfArgType::Timestamp => "timestamp",
        }
    }
}

/// Argument representation
#[derive(Default, Clone)]
pub struct IfArg<'a> {
    number: usize,
    name: &'a str,
    display: Option<&'a str>,
    atype: IfArgType,
    default: Option<String>,
    range: Option<String>,
    validation: Option<String>,
    mustexist: Option<bool>,
    reload: Option<bool>,
    placeholder: Option<String>,
    tooltip: Option<String>,
    group: Option<String>,
    vals: Vec<IfArgVal>,
}

impl<'a> IfArg<'a> {
    fn new(atype: IfArgType, name: &'a str) -> Self {
        Self {
            number: usize::max_value(),
            name,
            atype,
            ..Default::default()
        }
    }

    pub(crate) fn set_number(&mut self, number: usize) {
        self.number = number;
        for val in self.vals.iter_mut() {
            val.set_arg(number);
        }
    }

    pub(crate) fn get_name(&self) -> &'a str {
        self.name
    }

    pub(crate) fn get_display(&self) -> Option<&'a str> {
        self.display
    }

    pub(crate) fn get_type(&self) -> &IfArgType {
        &self.atype
    }

    /// Creates a new instance of `IfArg` with 'IfArgType::Integer' type using a string name
    pub fn new_integer(name: &'a str) -> Self {
        IfArg::new(IfArgType::Integer, name)
    }

    /// Creates a new instance of `IfArg` with 'IfArgType::Unsigned' type using a string name
    pub fn new_unsigned(name: &'a str) -> Self {
        IfArg::new(IfArgType::Unsigned, name)
    }

    /// Creates a new instance of `IfArg` with 'IfArgType::Long' type using a string name
    pub fn new_long(name: &'a str) -> Self {
        IfArg::new(IfArgType::Long, name)
    }

    /// Creates a new instance of `IfArg` with 'IfArgType::Double' type using a string name
    pub fn new_double(name: &'a str) -> Self {
        IfArg::new(IfArgType::Double, name)
    }

    /// Creates a new instance of `IfArg` with 'IfArgType::String' type using a string name
    pub fn new_string(name: &'a str) -> Self {
        IfArg::new(IfArgType::String, name)
    }

    /// Creates a new instance of `IfArg` with 'IfArgType::Password' type using a string name
    pub fn new_password(name: &'a str) -> Self {
        IfArg::new(IfArgType::Password, name)
    }

    /// Creates a new instance of `IfArg` with 'IfArgType::Boolean' type using a string name
    pub fn new_boolean(name: &'a str) -> Self {
        IfArg::new(IfArgType::Boolean, name)
    }

    /// Creates a new instance of `IfArg` with 'IfArgType::Boolflag' type using a string name
    pub fn new_boolflag(name: &'a str) -> Self {
        IfArg::new(IfArgType::Boolflag, name)
    }

    /// Creates a new instance of `IfArg` with 'IfArgType::Fileselect' type using a string name
    pub fn new_fileselect(name: &'a str) -> Self {
        IfArg::new(IfArgType::Fileselect, name)
    }

    /// Creates a new instance of `IfArg` with 'IfArgType::Selector' type using a string name
    pub fn new_selector(name: &'a str) -> Self {
        IfArg::new(IfArgType::Selector, name)
    }

    /// Creates a new instance of `IfArg` with 'IfArgType::Radio' type using a string name
    pub fn new_radio(name: &'a str) -> Self {
        IfArg::new(IfArgType::Radio, name)
    }

    /// Creates a new instance of `IfArg` with 'IfArgType::Multicheck' type using a string name
    pub fn new_multicheck(name: &'a str) -> Self {
        IfArg::new(IfArgType::Multicheck, name)
    }

    /// Creates a new instance of `IfArg` with 'IfArgType::Timestamp' type using a string name
    pub fn new_timestamp(name: &'a str) -> Self {
        IfArg::new(IfArgType::Timestamp, name)
    }

    /// Sets the display string
    pub fn display(mut self, display: &'a str) -> Self {
        self.display = Some(display);
        self
    }

    /// Sets the default value
    pub fn default<T: ToString>(mut self, default: &T) -> Self {
        self.default = Some(default.to_string());
        self
    }

    /// Sets the range string
    pub fn range<T: ToString>(mut self, range: &T) -> Self {
        self.range = Some(range.to_string());
        self
    }

    /// Sets the validation regular expression string
    pub fn validation<T: ToString>(mut self, validation: &T) -> Self {
        self.validation = Some(validation.to_string());
        self
    }

    /// Sets the `mustexist` flag for `Fileselect`
    pub fn mustexist(mut self, mustexist: bool) -> Self {
        self.mustexist = Some(mustexist);
        self
    }

    /// Sets the `reload` flag
    pub fn reload(mut self, reload: bool) -> Self {
        self.reload = Some(reload);
        self
    }

    pub(crate) fn has_reload(&self) -> bool {
        self.reload.unwrap_or_default()
    }

    /// Sets the placeholder string
    pub fn placeholder(mut self, placeholder: &str) -> Self {
        self.placeholder = Some(placeholder.to_owned());
        self
    }

    /// Sets the tooltip string
    pub fn tooltip(mut self, tooltip: &str) -> Self {
        self.tooltip = Some(tooltip.to_owned());
        self
    }

    /// Sets the group
    pub fn group(mut self, group: &str) -> Self {
        self.group = Some(group.to_owned());
        self
    }

    /// Adds a value
    pub fn add_val(&mut self, val: IfArgVal) {
        self.vals.push(val);
    }

    pub(crate) fn reload_option(&mut self, vals: Vec<IfArgVal>) {
        self.vals.clear();
        let anum = self.number;
        self.vals.extend(vals.into_iter().map(|mut v| {
            v.set_arg(anum);
            v
        }));
    }

    pub(crate) fn print_arg(&self) {
        print!(
            "arg {{number={}}}{{call=--{}}}{{display={}}}{{type={}}}",
            self.number,
            self.name,
            self.display.unwrap_or(self.name),
            self.atype.type_str()
        );
        print_opt_value("default", &self.default);
        print_opt_value("range", &self.range);
        print_opt_value("validation", &self.validation);
        print_opt_value("mustexist", &self.mustexist);
        print_opt_value("reload", &self.reload);
        print_opt_value("placeholder", &self.placeholder);
        print_opt_value("tooltip", &self.tooltip);
        print_opt_value("group", &self.group);
        println!();

        self.vals.iter().for_each(IfArgVal::print_value);
    }
}

/// Argument value representation
#[derive(Default, Clone)]
pub struct IfArgVal {
    arg: usize,
    value: String,
    display: Option<String>,
    default: Option<bool>,
}

impl IfArgVal {
    /// Creates a new instance of `IfArgVal` using a string value
    pub fn new<T: ToString>(value: T) -> Self {
        IfArgVal {
            arg: usize::max_value(),
            value: value.to_string(),
            ..Default::default()
        }
    }

    fn set_arg(&mut self, arg: usize) {
        self.arg = arg;
    }

    /// Sets the display string
    pub fn display(mut self, display: &str) -> Self {
        self.display = Some(display.to_owned());
        self
    }

    /// Sets the default flag
    pub fn default(mut self, default: bool) -> Self {
        self.default = Some(default);
        self
    }

    fn print_value(&self) {
        print!(
            "value {{arg={}}}{{value={}}}{{display={}}}",
            self.arg,
            self.value,
            self.display.as_ref().unwrap_or(&self.value)
        );
        print_opt_value("default", &self.default);
        println!();
    }
}
