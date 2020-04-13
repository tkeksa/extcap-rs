use std::fs::File;
use std::io::{self, Cursor};

use bytes::buf::BufMut;
use bytes::{Buf, BytesMut};
use futures::channel::mpsc::{self, Receiver, Sender};
use futures::channel::oneshot;
use futures::future::{self, lazy, FutureExt};
use futures::sink::SinkExt;
use futures::stream::{StreamExt, TryStreamExt};
use log::{debug, error};
use tokio_util::codec::{Decoder, Encoder, FramedRead, FramedWrite};

use crate::control_pipe::{ControlMsg, CtrlPipes};

const PIPE_LEN: usize = 128;

#[derive(Default)]
pub struct ControlPipeRuntime {
    pipe_in: Option<File>,
    pipe_out: Option<File>,
    stop_in: Option<oneshot::Sender<()>>,
    stop_out: Option<oneshot::Sender<()>>,
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

        let (snd, rcv_in) = mpsc::channel(PIPE_LEN);
        let (stop_tx, stop_rx) = oneshot::channel::<()>();
        self.stop_in = Some(stop_tx);
        let pipe = self.pipe_in.take().unwrap();
        tokio::spawn(thread_in(stop_rx, pipe, snd));

        let (snd_out, rcv) = mpsc::channel(PIPE_LEN);
        let (stop_tx, stop_rx) = oneshot::channel::<()>();
        self.stop_out = Some(stop_tx);
        let pipe = self.pipe_out.take().unwrap();
        tokio::spawn(thread_out(stop_rx, pipe, rcv));

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
        .map_err(|e| {
            error!("thread_in stream_err {:?}", e);
        })
        .forward(sender.sink_map_err(|e| {
            error!("thread_in sink_err {:?}", e);
        }));
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
        Ok(Some(ControlMsg::new(cnum, cmd.into(), pdu.bytes())))
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
