use mio_misc::channel;
use std::{any, error, fmt, io};

pub enum NotifyError<T> {
    Io(io::Error),
    Full(T),
    Closed(Option<T>),
    NotificationQueueFull,
}

impl<M> fmt::Debug for NotifyError<M> {
    fn fmt(&self, fmt: &mut fmt::Formatter) -> fmt::Result {
        match *self {
            NotifyError::Io(ref e) => {
                write!(fmt, "NotifyError::Io({:?})", e)
            }
            NotifyError::Full(..) => {
                write!(fmt, "NotifyError::Full(..)")
            }
            NotifyError::Closed(..) => {
                write!(fmt, "NotifyError::Closed(..)")
            }
            NotifyError::NotificationQueueFull => {
                write!(fmt, "NotifyError::NotificationQueueFull")
            }
        }
    }
}

impl<M> fmt::Display for NotifyError<M> {
    fn fmt(&self, fmt: &mut fmt::Formatter) -> fmt::Result {
        match *self {
            NotifyError::Io(ref e) => {
                write!(fmt, "IO error: {}", e)
            }
            NotifyError::Full(..) => write!(fmt, "Full"),
            NotifyError::Closed(..) => write!(fmt, "Closed"),
            NotifyError::NotificationQueueFull => {
                write!(fmt, "Notification queue is full")
            }
        }
    }
}

impl<M: any::Any> error::Error for NotifyError<M> {
    fn description(&self) -> &str {
        match *self {
            NotifyError::Io(ref err) => err.description(),
            NotifyError::Closed(..) => "The receiving end has hung up",
            NotifyError::Full(..) => "Queue is full",
            NotifyError::NotificationQueueFull => "Notification queue is full",
        }
    }

    fn cause(&self) -> Option<&dyn error::Error> {
        match *self {
            NotifyError::Io(ref err) => Some(err),
            _ => None,
        }
    }
}

impl<M> From<channel::TrySendError<M>> for NotifyError<M> {
    fn from(src: channel::TrySendError<M>) -> NotifyError<M> {
        match src {
            channel::TrySendError::Io(e) => NotifyError::Io(e),
            channel::TrySendError::Full(v) => NotifyError::Full(v),
            channel::TrySendError::Disconnected(v) => {
                NotifyError::Closed(Some(v))
            }
            channel::TrySendError::NotificationQueueFull => {
                NotifyError::NotificationQueueFull
            }
        }
    }
}
