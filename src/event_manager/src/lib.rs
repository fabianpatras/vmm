
use std::io;

use kqueue::Watcher;
use kqueue::Ident;
use kqueue::Ident::Fd;
use kqueue::EventFilter;
use kqueue::FilterFlag;

pub struct EventManager {
    watcher: Watcher
}

pub enum Error {
    Kqueue(io::Error),
    // only Fd devices for now
    DeviceTypeNotSupported,
}

impl EventManager {
    pub fn new() -> Result<Self, Error> {
        Ok(EventManager {
            watcher: Watcher::new().map_err(Error::Kqueue)?,
        })
    }
    
    /// adds a device identified by a Fd
    pub fn add_device(&mut self, device_ident: Ident) -> Result<(), Error> {
        match device_ident {
            Fd(raw_fd) => {
                self.watcher.add_fd(raw_fd, EventFilter::EVFILT_READ, FilterFlag::NOTE_FFNOP).map_err(Error::Kqueue)?;
            }
            _ => {
                return Err(Error::DeviceTypeNotSupported);
            }
        }

        Ok(())
    }

    pub fn listen(&self) -> Result <(), Error> {
        match self.watcher.poll_forever(None) {
            Some(_ev) => {
                println!("got event");
            }
            None => {}
        }


        Ok(())
    }
}

#[cfg(test)]
mod tests {
    #[test]
    fn it_works() {
        let result = 2 + 2;
        assert_eq!(result, 4);
    }
}
