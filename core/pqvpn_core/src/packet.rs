//! Inner-packet checks after decryption, mirroring vpn/runtime.py.

/// `validate_client_packet` structure rules: a complete IPv4 packet.
fn well_formed_ipv4(packet: &[u8]) -> bool {
    if packet.len() < 20 || packet[0] >> 4 != 4 {
        return false;
    }
    let ihl = usize::from(packet[0] & 0x0F) * 4;
    let total = usize::from(u16::from_be_bytes([packet[2], packet[3]]));
    ihl >= 20 && ihl <= packet.len() && total >= ihl && total == packet.len()
}

/// Server inbound (`_handle_datagram`): fits the MTU and the source is the session's lease.
pub fn server_accepts(packet: &[u8], lease: [u8; 4], mtu: usize) -> bool {
    packet.len() <= mtu && well_formed_ipv4(packet) && packet[12..16] == lease
}

/// Client inbound (`_forward_data`): fits the MTU and the destination is our assigned address.
pub fn client_accepts(packet: &[u8], assigned: [u8; 4], mtu: usize) -> bool {
    packet.len() <= mtu && well_formed_ipv4(packet) && packet[16..20] == assigned
}

#[cfg(test)]
mod tests {
    use super::*;

    fn ipv4(src: [u8; 4], dst: [u8; 4], payload: &[u8]) -> Vec<u8> {
        let total = u16::try_from(20 + payload.len()).unwrap().to_be_bytes();
        [&[0x45, 0, total[0], total[1]][..], &[0; 8], &src, &dst, payload].concat()
    }

    #[test]
    fn source_and_destination_rules() {
        let (lease, other) = ([10, 8, 0, 2], [10, 8, 0, 3]);
        assert!(server_accepts(&ipv4(lease, [1, 1, 1, 1], b""), lease, 1380));
        assert!(!server_accepts(&ipv4(other, [1, 1, 1, 1], b""), lease, 1380));
        assert!(!server_accepts(b"malformed", lease, 1380));
        assert!(!server_accepts(&[0x60; 40], lease, 1380));
        assert!(client_accepts(&ipv4([1, 1, 1, 1], lease, b""), lease, 1380));
        assert!(!client_accepts(&ipv4([1, 1, 1, 1], other, b""), lease, 1380));
        assert!(!client_accepts(&ipv4([1, 1, 1, 1], lease, &[0; 100]), lease, 100));
    }
}
