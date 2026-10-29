#![deny(unsafe_op_in_unsafe_fn)]
//! The only unsafe code in the PQ-VPN core: taking ownership of descriptors Python hands over.
//! Python passes `os.dup()` copies; `check` validates one without owning it, and only once every
//! descriptor has passed does `own` take it, so ownership is all-or-nothing.

use std::io;
use std::os::fd::{AsRawFd, BorrowedFd, FromRawFd, OwnedFd, RawFd};

use nix::fcntl::{FcntlArg, OFlag, fcntl};
use nix::sys::socket::{AddressFamily, SockType, SockaddrLike, SockaddrStorage, getsockname, getsockopt, sockopt};
use nix::sys::stat::{SFlag, fstat, major, minor};

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Kind {
    /// An AF_INET datagram socket.
    Udp,
    /// /dev/net/tun (character device 10:200).
    Tun,
    /// The `--dev-emulated-tun` stand-in: an AF_UNIX datagram socketpair end.
    EmulatedTun,
}

/// A descriptor that passed `check`; only `own` consumes it.
#[derive(Debug)]
pub struct Checked(RawFd);

/// Checks `fd` is open and of the expected kind, and makes it non-blocking. Takes no ownership.
pub fn check(fd: RawFd, kind: Kind) -> io::Result<Checked> {
    // SAFETY: F_GETFD takes no pointer argument, so any integer is a valid input; the kernel
    // answers EBADF for a descriptor that is not open.
    if unsafe { libc::fcntl(fd, libc::F_GETFD) } == -1 {
        return Err(io::Error::last_os_error());
    }
    // SAFETY: F_GETFD just confirmed `fd` is open, and the borrow lives only for this call,
    // during which the caller (which handed it over) does not close it.
    let borrowed = unsafe { BorrowedFd::borrow_raw(fd) };
    if !is(borrowed, kind)? {
        return Err(io::Error::new(io::ErrorKind::InvalidInput, format!("descriptor is not a {kind:?}")));
    }
    let flags = OFlag::from_bits_truncate(fcntl(borrowed, FcntlArg::F_GETFL)?);
    fcntl(borrowed, FcntlArg::F_SETFL(flags | OFlag::O_NONBLOCK))?;
    Ok(Checked(fd))
}

/// Takes sole ownership; the descriptor closes when the `OwnedFd` drops.
pub fn own(checked: Checked) -> OwnedFd {
    // SAFETY: `check` confirmed the descriptor is open, and the caller hands over sole ownership
    // (an os.dup() copy nothing else uses or closes), so this OwnedFd is its only owner.
    unsafe { OwnedFd::from_raw_fd(checked.0) }
}

fn is(fd: BorrowedFd<'_>, kind: Kind) -> io::Result<bool> {
    let stat = fstat(fd)?;
    let format = SFlag::from_bits_truncate(stat.st_mode) & SFlag::S_IFMT;
    if kind == Kind::Tun {
        return Ok(format == SFlag::S_IFCHR && major(stat.st_rdev) == 10 && minor(stat.st_rdev) == 200);
    }
    if format != SFlag::S_IFSOCK || getsockopt(&fd, sockopt::SockType)? != SockType::Datagram {
        return Ok(false);
    }
    let family = getsockname::<SockaddrStorage>(fd.as_raw_fd())?.family();
    Ok(family == Some(if kind == Kind::Udp { AddressFamily::Inet } else { AddressFamily::Unix }))
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::net::UdpSocket;
    use std::os::unix::net::{UnixDatagram, UnixStream};

    #[test]
    fn accepts_matching_kinds_and_sets_nonblocking() {
        let udp = UdpSocket::bind("127.0.0.1:0").unwrap();
        let owned = own(check(udp.as_raw_fd(), Kind::Udp).unwrap());
        std::mem::forget(udp); // `owned` now closes it
        assert!(OFlag::from_bits_truncate(fcntl(&owned, FcntlArg::F_GETFL).unwrap()).contains(OFlag::O_NONBLOCK));
        let (tun, _peer) = UnixDatagram::pair().unwrap();
        check(tun.as_raw_fd(), Kind::EmulatedTun).unwrap();
    }

    #[test]
    fn rejects_wrong_kinds_and_closed_fds_without_owning_them() {
        let (stream, _peer) = UnixStream::pair().unwrap();
        assert!(check(stream.as_raw_fd(), Kind::EmulatedTun).is_err());
        let (dgram, _peer) = UnixDatagram::pair().unwrap();
        assert!(check(dgram.as_raw_fd(), Kind::Udp).is_err());
        let udp = UdpSocket::bind("127.0.0.1:0").unwrap();
        assert!(check(udp.as_raw_fd(), Kind::Tun).is_err());
        let file = std::fs::File::open("/dev/null").unwrap();
        assert!(check(file.as_raw_fd(), Kind::Tun).is_err(), "a char device that is not /dev/net/tun");
        // A closed number could be reused by a parallel test; -1 is never open.
        assert_eq!(check(-1, Kind::Udp).unwrap_err().raw_os_error(), Some(libc::EBADF));
        // Rejections left every descriptor with its original owner, still open.
        assert!(udp.local_addr().is_ok() && stream.peer_addr().is_ok());
    }
}
