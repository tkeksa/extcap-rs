use crate::print_opt_value;

pub enum IfArgType {
    None,
    Integer,
    Unsigned,
    Long,
    Double,
    String,
    Password,
    Boolean,
    Boolflag,
    Fileselect,
    Selector,
    Radio,
    Multicheck,
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

#[derive(Default)]
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

    pub fn get_name(&self) -> &'a str {
        &self.name
    }

    pub fn get_display(&self) -> Option<&'a str> {
        self.display
    }

    pub fn get_type(&self) -> &IfArgType {
        &self.atype
    }

    pub fn new_integer(name: &'a str) -> Self {
        IfArg::new(IfArgType::Integer, name)
    }

    pub fn new_unsigned(name: &'a str) -> Self {
        IfArg::new(IfArgType::Unsigned, name)
    }

    pub fn new_long(name: &'a str) -> Self {
        IfArg::new(IfArgType::Long, name)
    }

    pub fn new_double(name: &'a str) -> Self {
        IfArg::new(IfArgType::Double, name)
    }

    pub fn new_string(name: &'a str) -> Self {
        IfArg::new(IfArgType::String, name)
    }

    pub fn new_password(name: &'a str) -> Self {
        IfArg::new(IfArgType::Password, name)
    }

    pub fn new_boolean(name: &'a str) -> Self {
        IfArg::new(IfArgType::Boolean, name)
    }

    pub fn new_boolflag(name: &'a str) -> Self {
        IfArg::new(IfArgType::Boolflag, name)
    }

    pub fn new_fileselect(name: &'a str) -> Self {
        IfArg::new(IfArgType::Fileselect, name)
    }

    pub fn new_selector(name: &'a str) -> Self {
        IfArg::new(IfArgType::Selector, name)
    }

    pub fn new_radio(name: &'a str) -> Self {
        IfArg::new(IfArgType::Radio, name)
    }

    pub fn new_multicheck(name: &'a str) -> Self {
        IfArg::new(IfArgType::Multicheck, name)
    }

    pub fn new_timestamp(name: &'a str) -> Self {
        IfArg::new(IfArgType::Timestamp, name)
    }

    pub fn display(mut self, display: &'a str) -> Self {
        self.display = Some(display);
        self
    }

    pub fn default<T: ToString>(mut self, default: &T) -> Self {
        self.default = Some(default.to_string());
        self
    }

    pub fn range<T: ToString>(mut self, range: &T) -> Self {
        self.range = Some(range.to_string());
        self
    }

    pub fn validation<T: ToString>(mut self, validation: &T) -> Self {
        self.validation = Some(validation.to_string());
        self
    }

    pub fn mustexist(mut self, mustexist: bool) -> Self {
        self.mustexist = Some(mustexist);
        self
    }

    pub fn reload(mut self, reload: bool) -> Self {
        self.reload = Some(reload);
        self
    }

    pub(crate) fn has_reload(&self) -> bool {
        self.reload.unwrap_or_default()
    }

    pub fn placeholder(mut self, placeholder: &str) -> Self {
        self.placeholder = Some(placeholder.to_owned());
        self
    }

    pub fn tooltip(mut self, tooltip: &str) -> Self {
        self.tooltip = Some(tooltip.to_owned());
        self
    }

    pub fn group(mut self, group: &str) -> Self {
        self.group = Some(group.to_owned());
        self
    }

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

#[derive(Default)]
pub struct IfArgVal {
    arg: usize,
    value: String,
    display: Option<String>,
    default: Option<bool>,
}

impl IfArgVal {
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

    pub fn display(mut self, display: &str) -> Self {
        self.display = Some(display.to_owned());
        self
    }

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
