use crate::print_opt_value;

/// Button roles
pub enum ButtonRole {
    /// INTERFACE_ROLE_CONTROL
    Control,
    /// INTERFACE_ROLE_LOGGER
    Logger,
    /// INTERFACE_ROLE_HELP
    Help,
    /// INTERFACE_ROLE_RESTORE
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

/// Interface toolbar Control types
pub enum ControlType {
    /// None or unknown
    None,
    /// INTERFACE_TYPE_BOOLEAN
    Boolean,
    /// INTERFACE_TYPE_BUTTON
    Button(ButtonRole),
    /// INTERFACE_TYPE_SELECTOR
    Selector,
    /// INTERFACE_TYPE_STRING
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

/// Control representation
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
            number: usize::MAX,
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

    /// Creates a new instance of `Control` with 'ControlType::Boolean' type
    pub fn new_boolean() -> Self {
        Control::new(ControlType::Boolean)
    }

    /// Creates a new instance of `Control` with 'ControlType::Button' type
    pub fn new_button(role: ButtonRole) -> Self {
        Control::new(ControlType::Button(role))
    }

    /// Creates a new instance of `Control` with 'ControlType::Selector' type
    pub fn new_selector() -> Self {
        Control::new(ControlType::Selector)
    }

    /// Creates a new instance of `Control` with 'ControlType::String' type
    pub fn new_string() -> Self {
        Control::new(ControlType::String)
    }

    /// Sets the display string
    pub fn display(mut self, display: &str) -> Self {
        self.display = Some(display.to_owned());
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

    /// Sets the tooltip string
    pub fn tooltip(mut self, tooltip: &str) -> Self {
        self.tooltip = Some(tooltip.to_owned());
        self
    }

    /// Sets the placeholder string
    pub fn placeholder(mut self, placeholder: &str) -> Self {
        self.placeholder = Some(placeholder.to_owned());
        self
    }

    /// Adds a value
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

/// Control value representation
#[derive(Default)]
pub struct ControlVal {
    control: usize,
    value: String,
    display: Option<String>,
    default: Option<bool>,
}

impl ControlVal {
    /// Creates a new instance of `ControlVal` using a string value
    pub fn new<T: ToString>(value: T) -> Self {
        ControlVal {
            control: usize::MAX,
            value: value.to_string(),
            ..Default::default()
        }
    }

    fn set_control(&mut self, control: usize) {
        self.control = control;
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
            "value {{control={}}}{{value={}}}{{display={}}}",
            self.control,
            self.value,
            self.display.as_ref().unwrap_or(&self.value)
        );
        print_opt_value("default", &self.default);
        println!();
    }
}
