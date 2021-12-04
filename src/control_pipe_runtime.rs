use std::fs::File;
use std::future::Future;
use std::io::{self, Cursor};

use bytes::buf::BufMut;
use bytes::{Buf, BytesMut};
use futures::channel::mpsc::{self, Receiver, Sender};
use futures::channel::oneshot;
use futures::future::{self, lazy, BoxFuture, FutureExt};
use futures::sink::SinkExt;
use futures::stream::{StreamExt, TryStreamExt};
use log::{debug, error};
use tokio_util::codec::{Decoder, Encoder, FramedRead, FramedWrite};

use crate::control_pipe::{ControlMsg, CtrlPipes};

const PIPE_LEN: usize = 128;

#[derive(Debug)]
enum State {
    New {
        pipe_in: File,
        pipe_out: File,
    },
    Started {
        stop_in: oneshot::Sender<()>,
        stop_out: oneshot::Sender<()>,
    },
}

pub(crate) struct ControlPipeRuntime {
    state: Option<State>,
    tsk: Option<BoxFuture<'static, ()>>,
}

impl ControlPipeRuntime {
    pub(crate) fn new(pipe_in: File, pipe_out: File) -> Self {
        Self {
            state: Some(State::New { pipe_in, pipe_out }),
            tsk: None,
        }
    }

    pub(crate) fn start(&mut self) -> CtrlPipes {
        debug!("start() state={:?}", self.state);

        let (pipe_in, pipe_out) = if let Some(State::New { pipe_in, pipe_out }) = self.state.take()
        {
            (pipe_in, pipe_out)
        } else {
            error!("start() called in wrong state");
            panic!("start() called in wrong state");
        };

        let (snd, rcv_in) = mpsc::channel(PIPE_LEN);
        let (stop_in, stop_in_rx) = oneshot::channel::<()>();

        let (snd_out, rcv) = mpsc::channel(PIPE_LEN);
        let (stop_out, stop_out_rx) = oneshot::channel::<()>();

        self.state = Some(State::Started { stop_in, stop_out });

        let tsk = futures::future::join(
            thread_in(stop_in_rx, pipe_in, snd),
            thread_out(stop_out_rx, pipe_out, rcv),
        )
        .map(|_| ());

        self.tsk = Some(tsk.boxed::<'static>());

        debug!("start() done state={:?}", self.state);
        (rcv_in, snd_out)
    }

    pub(crate) fn run_task(&mut self) -> impl Future<Output = ()> {
        self.tsk.take().unwrap()
    }

    pub(crate) fn stop(mut self) {
        debug!("stop() state={:?}", self.state);
        if let Some(State::Started { stop_in, stop_out }) = self.state.take() {
            stop_in.send(()).unwrap();
            stop_out.send(()).unwrap();
        } else {
            error!("stop() called in wrong state");
            return;
        }
        debug!("stop() done");
    }
}

async fn thread_in(
    stop: oneshot::Receiver<()>,
    pipe: File,
    sender: Sender<ControlMsg>,
) -> Result<(), ()> {
    debug!("thread_in starting ...");
    lazy::<_, Result<(), ()>>(|_| {
        debug!("thread_in started");
        Ok(())
    })
    .await?;
    let tpipe = tokio::fs::File::from_std(pipe);
    let strm = FramedRead::new(tpipe, ControlMsgCodec);
    let task = strm
        .inspect(|msg| debug!("thread_in received {:?}", msg))
        .map_err(|e| error!("thread_in stream_err {:?}", e))
        .forward(sender.sink_map_err(|e| error!("thread_in sink_err {:?}", e)));
    future::select(stop, task).await;
    debug!("thread_in stopped");
    Ok(())
}

async fn thread_out(
    stop: oneshot::Receiver<()>,
    pipe: File,
    mut receiver: Receiver<ControlMsg>,
) -> Result<(), ()> {
    debug!("thread_out starting ...");
    lazy::<_, Result<(), ()>>(|_| {
        debug!("thread_out started");
        Ok(())
    })
    .await?;
    let tpipe = tokio::fs::File::from_std(pipe);
    let mut strm = FramedWrite::new(tpipe, ControlMsgCodec);
    let task = async {
        while let Some(msg) = receiver.next().await {
            debug!("thread_out received {:?}", msg);
            if let Err(e) = strm.send(msg).await {
                error!("thread_out strm_err {:?}", e);
            }
        }
    };
    future::select(stop, task.boxed()).await;
    debug!("thread_out stopped");
    Ok(())
}

struct ControlMsgCodec;

impl Decoder for ControlMsgCodec {
    type Item = ControlMsg;
    type Error = io::Error;

    fn decode(&mut self, buf: &mut BytesMut) -> Result<Option<Self::Item>, Self::Error> {
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
        let msg_len = hdr.get_uint(3) as usize;
        if msg_len < 2 {
            return Err(io::Error::new(
                io::ErrorKind::InvalidData,
                "Message Length < 2",
            ));
        }
        if buf.len() < (4 + msg_len) {
            return Ok(None);
        }
        let mut pdu = buf.split_to(4 + msg_len);
        pdu.advance(4);
        let cnum = pdu.get_u8();
        let cmd = pdu.get_u8();
        Ok(Some(ControlMsg::new(cnum, cmd.into(), pdu.chunk())))
    }
}

impl Encoder<ControlMsg> for ControlMsgCodec {
    type Error = io::Error;

    fn encode(&mut self, msg: ControlMsg, buf: &mut BytesMut) -> Result<(), Self::Error> {
        buf.reserve(6 + msg.get_data().len());
        buf.put_u8(b'T');
        buf.put_uint(2 + msg.get_data().len() as u64, 3);
        buf.put_u8(msg.get_ctrl_num());
        buf.put_u8(u8::from(msg.get_command()));
        buf.put(msg.get_data());
        debug!("encode() {:?}", buf);
        Ok(())
    }
}
