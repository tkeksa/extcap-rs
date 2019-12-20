use std::fs::File;
use std::io::{self, Cursor};

use bytes::buf::BufMut;
use bytes::{Buf, BytesMut, IntoBuf};
use futures::future::{lazy, Future};
use futures::sink::Sink;
use futures::stream::Stream;
use futures::sync::mpsc::{self, Receiver, Sender};
use futures::sync::oneshot;
use log::{debug, error};
use tokio::runtime::{Runtime, TaskExecutor};
use tokio_io::codec::{Decoder, Encoder};

use crate::control_pipe::{ControlMsg, CtrlPipes};

const PIPE_LEN: usize = 128;

#[derive(Default)]
pub struct ControlPipeRuntime {
    pipe_in: Option<File>,
    pipe_out: Option<File>,
    stop_in: Option<oneshot::Sender<()>>,
    stop_out: Option<oneshot::Sender<()>>,
    runtime: Option<Runtime>,
}

impl ControlPipeRuntime {
    pub(crate) fn new(pipe_in: File, pipe_out: File) -> Self {
        Self {
            pipe_in: Some(pipe_in),
            pipe_out: Some(pipe_out),
            ..Default::default()
        }
    }

    pub(crate) fn start(&mut self) -> CtrlPipes {
        debug!("start()");

        self.runtime = Runtime::new().ok();
        let exec = self.runtime.as_mut().unwrap().executor();

        let (snd, rcv_in) = mpsc::channel(PIPE_LEN);
        let (stop_tx, stop_rx) = oneshot::channel::<()>();
        self.stop_in = Some(stop_tx);
        let pipe = self.pipe_in.take().unwrap();
        spawn_in(&exec, stop_rx, pipe, snd);

        let (snd_out, rcv) = mpsc::channel(PIPE_LEN);
        let (stop_tx, stop_rx) = oneshot::channel::<()>();
        self.stop_out = Some(stop_tx);
        let pipe = self.pipe_out.take().unwrap();
        spawn_out(&exec, stop_rx, pipe, rcv);

        debug!("start() done");
        (rcv_in, snd_out)
    }

    pub(crate) fn stop(mut self) {
        debug!("stop()");
        if let Some(tx) = self.stop_in.take() {
            tx.send(()).unwrap();
        }
        if let Some(tx) = self.stop_out.take() {
            tx.send(()).unwrap();
        }
        if let Some(rt) = self.runtime.take() {
            // Shutdown the runtime
            rt.shutdown_on_idle().wait().unwrap();
        }
        debug!("stop() done");
    }
}

fn spawn_in(
    exec: &TaskExecutor,
    stop: oneshot::Receiver<()>,
    pipe: File,
    sender: Sender<ControlMsg>,
) {
    let start = lazy::<_, Result<(), ()>>(|| {
        debug!("cp_thread_in started");
        Ok(())
    });
    let tpipe = tokio::fs::File::from_std(pipe);
    let (_, strm) = ControlMsgCodec::new().framed(tpipe).split();
    let task = strm
        .map_err(|e| error!("cp_thread_in stream error {:?}", e))
        .inspect(|msg| debug!("cp_thread_in received {:?}", msg))
        .forward(sender.sink_map_err(|e| error!("cp_thread_in sink error {:?}", e)))
        .map(|_| ());
    exec.spawn(
        start
            .then(|_| stop.map_err(|_| ()).select(task))
            .map_err(|_| debug!("cp_thread_in stopped with err"))
            .map(|_| debug!("cp_thread_in stopped")),
    );
}

fn spawn_out(
    exec: &TaskExecutor,
    stop: oneshot::Receiver<()>,
    pipe: File,
    receiver: Receiver<ControlMsg>,
) {
    let start = lazy::<_, Result<(), ()>>(|| {
        debug!("cp_thread_out started");
        Ok(())
    });
    let tpipe = tokio::fs::File::from_std(pipe);
    let (strm, _) = ControlMsgCodec::new().framed(tpipe).split();
    let task = receiver
        .map_err(|e| error!("cp_thread_out stream error {:?}", e))
        .inspect(|msg| debug!("cp_thread_out received {:?}", msg))
        .forward(strm.sink_map_err(|e| error!("cp_thread_out sink error {:?}", e)))
        .map(|_| ());
    exec.spawn(
        start
            .then(|_| stop.map_err(|_| ()).select(task))
            .map_err(|_| debug!("cp_thread_out stopped with err"))
            .map(|_| debug!("cp_thread_out stopped")),
    );
}

struct ControlMsgCodec(());

impl ControlMsgCodec {
    pub fn new() -> Self {
        Self(())
    }
}

impl Decoder for ControlMsgCodec {
    type Item = ControlMsg;
    type Error = io::Error;

    fn decode(&mut self, buf: &mut BytesMut) -> Result<Option<ControlMsg>, io::Error> {
        if buf.len() < 4 {
            return Ok(None);
        }
        let mut hdr = Cursor::new(&buf[0..4]);
        if hdr.get_u8() != b'T' {
            return Err(io::Error::new(
                io::ErrorKind::InvalidData,
                "Sync Pipe Indication != 'T'",
            ));
        }
        let msg_len = hdr.get_uint_be(3) as usize;
        if msg_len < 2 {
            return Err(io::Error::new(
                io::ErrorKind::InvalidData,
                "Message Length < 2",
            ));
        }
        if buf.len() < (4 + msg_len) {
            return Ok(None);
        }
        let mut pdu = buf.split_to(4 + msg_len).into_buf();
        pdu.advance(4);
        let cnum = pdu.get_u8();
        let cmd = pdu.get_u8();
        Ok(Some(ControlMsg::new(cnum, cmd.into(), pdu.bytes())))
    }
}

impl Encoder for ControlMsgCodec {
    type Item = ControlMsg;
    type Error = io::Error;

    fn encode(&mut self, msg: ControlMsg, buf: &mut BytesMut) -> Result<(), io::Error> {
        buf.reserve(6 + msg.get_data().len());
        buf.put(b'T');
        buf.put_uint_be(2 + msg.get_data().len() as u64, 3);
        buf.put(msg.get_ctrl_num());
        buf.put(u8::from(msg.get_command()));
        buf.put(msg.get_data());
        debug!("encode() {:?}", buf);
        Ok(())
    }
}
