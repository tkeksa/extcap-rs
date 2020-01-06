use std::fs::File;

use futures::channel::mpsc::{Receiver, Sender};

#[cfg(feature = "ctrl_pipe")]
use crate::control_pipe_runtime::ControlPipeRuntime;

/// Interface toolbar Control commands
#[derive(Debug)]
pub enum ControlCmd {
    /// commandControlInitialized
    Initialized,
    /// commandControlSet
    Set,
    /// commandControlAdd
    Add,
    /// commandControlRemove
    Remove,
    /// commandControlEnable
    Enable,
    /// commandControlDisable
    Disable,
    /// commandStatusMessage
    StatusbarMessage,
    /// commandInformationMessage
    InformationMessage,
    /// commandWarningMessage
    WarningMessage,
    /// commandErrorMessage
    ErrorMessage,
    /// Unknown
    Unknown(u8),
}

impl From<u8> for ControlCmd {
    fn from(val: u8) -> Self {
        match val {
            0 => ControlCmd::Initialized,
            1 => ControlCmd::Set,
            2 => ControlCmd::Add,
            3 => ControlCmd::Remove,
            4 => ControlCmd::Enable,
            5 => ControlCmd::Disable,
            6 => ControlCmd::StatusbarMessage,
            7 => ControlCmd::InformationMessage,
            8 => ControlCmd::WarningMessage,
            9 => ControlCmd::ErrorMessage,
            v => ControlCmd::Unknown(v),
        }
    }
}

impl From<&ControlCmd> for u8 {
    fn from(val: &ControlCmd) -> Self {
        match val {
            ControlCmd::Initialized => 0,
            ControlCmd::Set => 1,
            ControlCmd::Add => 2,
            ControlCmd::Remove => 3,
            ControlCmd::Enable => 4,
            ControlCmd::Disable => 5,
            ControlCmd::StatusbarMessage => 6,
            ControlCmd::InformationMessage => 7,
            ControlCmd::WarningMessage => 8,
            ControlCmd::ErrorMessage => 9,
            ControlCmd::Unknown(v) => *v,
        }
    }
}

/// Control protocol message
#[derive(Debug)]
pub struct ControlMsg {
    ctrl_num: u8,
    command: ControlCmd,
    data: Vec<u8>,
}

impl ControlMsg {
    /// Creates a new instance of `ControlMsg`
    pub fn new(ctrl_num: u8, command: ControlCmd, data: &[u8]) -> Self {
        Self {
            ctrl_num,
            command,
            data: data.into(),
        }
    }

    /// Get the Control number
    pub fn get_ctrl_num(&self) -> u8 {
        self.ctrl_num
    }

    /// Get the Control command type
    pub fn get_command(&self) -> &ControlCmd {
        &self.command
    }

    /// Get the data
    pub fn get_data(&self) -> &[u8] {
        &self.data
    }
}

/// Control pipes
pub type CtrlPipes = (Receiver<ControlMsg>, Sender<ControlMsg>);

pub struct ControlPipe {
    #[cfg(feature = "ctrl_pipe")]
    runtime: ControlPipeRuntime,
}

impl ControlPipe {
    #[cfg_attr(not(feature = "ctrl_pipe"), allow(unused_variables))]
    pub(crate) fn new(pipe_in: File, pipe_out: File) -> Self {
        #[cfg(feature = "ctrl_pipe")]
        {
            Self {
                runtime: ControlPipeRuntime::new(pipe_in, pipe_out),
            }
        }
        #[cfg(not(feature = "ctrl_pipe"))]
        {
            panic!("ctrl_pipe feature not enabled");
        }
    }

    pub(crate) fn start(&mut self) -> CtrlPipes {
        #[cfg(feature = "ctrl_pipe")]
        {
            self.runtime.start()
        }
        #[cfg(not(feature = "ctrl_pipe"))]
        {
            panic!("ctrl_pipe feature not enabled");
        }
    }

    pub(crate) fn stop(self) {
        #[cfg(feature = "ctrl_pipe")]
        {
            self.runtime.stop();
        }
        #[cfg(not(feature = "ctrl_pipe"))]
        {
            panic!("ctrl_pipe feature not enabled");
        }
    }
}
