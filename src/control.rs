use crate::print_opt_value;

pub enum ButtonRole {
    Control,
    Logger,
    Help,
    Restore,
}

impl ButtonRole {
    fn role_str(&self) -> &'static str {
        match self {
            ButtonRole::Control => "control",
            ButtonRole::Logger => "logger",
            ButtonRole::Help => "help",
            ButtonRole::Restore => "restore",
        }
    }
}

pub enum ControlType {
    None,
    Boolean,
    Button(ButtonRole),
    Selector,
    String,
}

impl Default for ControlType {
    fn default() -> Self {
        ControlType::None
    }
}

impl ControlType {
    fn type_str(&self) -> &'static str {
        match self {
            ControlType::None => "none",
            ControlType::Boolean => "boolean",
            ControlType::Button(_) => "button",
            ControlType::Selector => "selector",
            ControlType::String => "string",
        }
    }
}

#[derive(Default)]
pub struct Control {
    number: usize,
    ctype: ControlType,
    display: Option<String>,
    default: Option<String>,
    range: Option<String>,
    validation: Option<String>,
    tooltip: Option<String>,
    placeholder: Option<String>,
    vals: Vec<ControlVal>,
}

impl Control {
    fn new(ctype: ControlType) -> Self {
        Self {
            number: usize::max_value(),
            ctype,
            ..Default::default()
        }
    }

    pub(crate) fn set_number(&mut self, number: usize) {
        self.number = number;
        for val in self.vals.iter_mut() {
            val.set_control(number);
        }
    }

    pub fn new_boolean() -> Self {
        Control::new(ControlType::Boolean)
    }

    pub fn new_button(role: ButtonRole) -> Self {
        Control::new(ControlType::Button(role))
    }

    pub fn new_selector() -> Self {
        Control::new(ControlType::Selector)
    }

    pub fn new_string() -> Self {
        Control::new(ControlType::String)
    }

    pub fn display(mut self, display: &str) -> Self {
        self.display = Some(display.to_owned());
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

    pub fn tooltip(mut self, tooltip: &str) -> Self {
        self.tooltip = Some(tooltip.to_owned());
        self
    }

    pub fn placeholder(mut self, placeholder: &str) -> Self {
        self.placeholder = Some(placeholder.to_owned());
        self
    }

    pub fn add_val(&mut self, val: ControlVal) {
        self.vals.push(val);
    }

    pub(crate) fn print_control(&self) {
        print!(
            "control {{number={}}}{{type={}}}",
            self.number,
            self.ctype.type_str()
        );
        if let ControlType::Button(role) = &self.ctype {
            print!("{{role={}}}", role.role_str());
        };
        print_opt_value("display", &self.display);
        print_opt_value("default", &self.default);
        print_opt_value("range", &self.range);
        print_opt_value("validation", &self.validation);
        print_opt_value("tooltip", &self.tooltip);
        print_opt_value("placeholder", &self.placeholder);
        println!();

        self.vals.iter().for_each(ControlVal::print_value);
    }
}

#[derive(Default)]
pub struct ControlVal {
    control: usize,
    value: String,
    display: Option<String>,
    default: Option<bool>,
}

impl ControlVal {
    pub fn new<T: ToString>(value: T) -> Self {
        ControlVal {
            control: usize::max_value(),
            value: value.to_string(),
            ..Default::default()
        }
    }

    fn set_control(&mut self, control: usize) {
        self.control = control;
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
            "value {{control={}}}{{value={}}}{{display={}}}",
            self.control,
            self.value,
            self.display.as_ref().unwrap_or(&self.value)
        );
        print_opt_value("default", &self.default);
        println!();
    }
}
