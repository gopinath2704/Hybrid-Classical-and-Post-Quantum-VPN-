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
    // O_NONBLOCK lives on the open-file description, which the dup shares with Python's original.
    // Harmless: the originals are already non-blocking (setblocking(False), O_NONBLOCK TUN), Python's
    // timeout sockets poll before reading anyway, and once the worker starts Python never reads them.
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

/// `struct ifreq` as TUNSETIFF reads it: the name, then the flags at the start of the 24-byte union.
#[repr(C)]
#[derive(Default)]
struct IfReqFlags {
    name: [u8; libc::IFNAMSIZ],
    flags: libc::c_short,
    _rest: [u8; 22],
}
const _: () = assert!(std::mem::size_of::<IfReqFlags>() == 40, "struct ifreq on 64-bit Linux");

/// Opens a TUN interface the way `TUNInterface.open` does (IFF_TUN | IFF_NO_PI, non-blocking, close-on-exec),
/// for `pqvpnd`, which has no Python to hand a descriptor over. Returns the name the kernel assigned.
pub fn open_tun(name: &str) -> io::Result<(OwnedFd, String)> {
    if name.is_empty() || name.len() >= libc::IFNAMSIZ || name.bytes().any(|b| b == 0 || b == b'/') {
        return Err(io::Error::new(io::ErrorKind::InvalidInput, "TUN name must be 1-15 bytes without NUL or '/'"));
    }
    use std::os::unix::fs::OpenOptionsExt;
    // std opens with O_CLOEXEC; no unsafe is needed to own the descriptor.
    let file = std::fs::OpenOptions::new().read(true).write(true).custom_flags(libc::O_NONBLOCK).open("/dev/net/tun")?;
    let mut request = IfReqFlags::default();
    request.name[..name.len()].copy_from_slice(name.as_bytes());
    request.flags = (libc::IFF_TUN | libc::IFF_NO_PI) as libc::c_short;
    // SAFETY: `file` is an open /dev/net/tun descriptor for the whole call, and `request` is a live,
    // exclusively borrowed `struct ifreq`-sized buffer (40 bytes) that TUNSETIFF reads and writes back.
    if unsafe { libc::ioctl(file.as_raw_fd(), libc::TUNSETIFF, &mut request as *mut IfReqFlags) } == -1 {
        return Err(io::Error::last_os_error());
    }
    let len = request.name.iter().position(|&b| b == 0).unwrap_or(request.name.len());
    let assigned = String::from_utf8_lossy(&request.name[..len]).into_owned();
    Ok((OwnedFd::from(file), assigned))
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
    use std::os::fd::AsFd;
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

    #[test]
    fn tun_name_checks() {
        for bad in ["", "a-name-of-16-byt", "a\0b", "a/b"] {
            assert_eq!(open_tun(bad).unwrap_err().kind(), io::ErrorKind::InvalidInput, "{bad:?}");
        }
    }

    /// Needs CAP_NET_ADMIN, e.g. `unshare -rn cargo test`; without it TUNSETIFF fails and the test only checks that.
    #[test]
    fn open_tun_creates_a_check_compatible_interface() {
        match open_tun("pqfdtest0") {
            Ok((fd, name)) => {
                assert_eq!(name, "pqfdtest0");
                assert!(is(fd.as_fd(), Kind::Tun).unwrap());
                assert!(OFlag::from_bits_truncate(fcntl(&fd, FcntlArg::F_GETFL).unwrap()).contains(OFlag::O_NONBLOCK));
                let cloexec = fcntl(&fd, FcntlArg::F_GETFD).unwrap();
                assert!(nix::fcntl::FdFlag::from_bits_truncate(cloexec).contains(nix::fcntl::FdFlag::FD_CLOEXEC));
            }
            Err(error) => assert!(matches!(error.raw_os_error(), Some(libc::EPERM | libc::ENOENT | libc::EACCES)), "{error}"),
        }
    }
}
