/// Handle ICMP echo request by generating an echo reply.
/// Returns Some(reply_bytes) if the packet was an ICMP echo request, None otherwise.
/// This allows pings to TUN-routed IPs to respond instantly (<1ms) without proxying.
pub fn handle_icmp_echo(packet: &[u8]) -> Option<Vec<u8>> {
    if packet.is_empty() {
        return None;
    }
    let version = packet[0] >> 4;
    match version {
        4 => handle_icmpv4_echo(packet),
        6 => handle_icmpv6_echo(packet),
        _ => None,
    }
}

/// Handle IPv4 ICMP echo request → echo reply.
fn handle_icmpv4_echo(pkt: &[u8]) -> Option<Vec<u8>> {
    // IPv4 header: minimum 20 bytes, ICMP header: 8 bytes
    if pkt.len() < 28 {
        return None;
    }

    let ihl = (pkt[0] & 0x0f) as usize * 4;
    if ihl < 20 || pkt.len() < ihl + 8 {
        return None;
    }

    // Check IP protocol field == ICMP (1)
    if pkt[9] != 1 {
        return None;
    }

    // Check ICMP type == echo request (8)
    let icmp_off = ihl;
    if pkt[icmp_off] != 8 {
        return None;
    }

    // Build reply: copy entire packet, swap addresses, change type
    let mut reply = pkt.to_vec();

    // Swap src ↔ dst IP (offsets 12..16 and 16..20)
    let (src, dst) = pkt.split_at(16);
    reply[12..16].copy_from_slice(&dst[..4]);
    reply[16..20].copy_from_slice(&src[12..16]);

    // Recalculate IPv4 header checksum
    reply[10] = 0;
    reply[11] = 0;
    let ip_csum = internet_checksum(&reply[..ihl]);
    reply[10] = (ip_csum >> 8) as u8;
    reply[11] = ip_csum as u8;

    // Set ICMP type to echo reply (0)
    reply[icmp_off] = 0;

    // Recalculate ICMP checksum
    reply[icmp_off + 2] = 0;
    reply[icmp_off + 3] = 0;
    let icmp_csum = internet_checksum(&reply[icmp_off..]);
    reply[icmp_off + 2] = (icmp_csum >> 8) as u8;
    reply[icmp_off + 3] = icmp_csum as u8;

    Some(reply)
}

/// Handle ICMPv6 echo request → echo reply.
fn handle_icmpv6_echo(pkt: &[u8]) -> Option<Vec<u8>> {
    // IPv6 header: 40 bytes, ICMPv6 header: 8 bytes minimum
    if pkt.len() < 48 {
        return None;
    }

    // Check Next Header == ICMPv6 (58)
    if pkt[6] != 58 {
        return None;
    }

    // Check ICMPv6 type == echo request (128)
    let icmp_off = 40;
    if pkt[icmp_off] != 128 {
        return None;
    }

    // Build reply
    let mut reply = pkt.to_vec();

    // Swap src ↔ dst IPv6 addresses (offsets 8..24 and 24..40)
    let (src_range, dst_range) = pkt.split_at(24);
    reply[8..24].copy_from_slice(&dst_range[..16]);
    reply[24..40].copy_from_slice(&src_range[8..24]);

    // Set ICMPv6 type to echo reply (129)
    reply[icmp_off] = 129;

    // Recalculate ICMPv6 checksum (includes pseudo-header)
    reply[icmp_off + 2] = 0;
    reply[icmp_off + 3] = 0;
    let csum = icmpv6_checksum(&reply[8..24], &reply[24..40], &reply[icmp_off..]);
    reply[icmp_off + 2] = (csum >> 8) as u8;
    reply[icmp_off + 3] = csum as u8;

    Some(reply)
}

/// Compute the Internet checksum (RFC 1071).
fn internet_checksum(data: &[u8]) -> u16 {
    let mut sum: u32 = 0;
    let mut i = 0;
    while i + 1 < data.len() {
        sum += (data[i] as u32) << 8 | data[i + 1] as u32;
        i += 2;
    }
    if data.len() % 2 == 1 {
        sum += (data[data.len() - 1] as u32) << 8;
    }
    while sum > 0xffff {
        sum = (sum >> 16) + (sum & 0xffff);
    }
    !sum as u16
}

/// Compute ICMPv6 checksum with pseudo-header.
fn icmpv6_checksum(src_ip: &[u8], dst_ip: &[u8], icmp_data: &[u8]) -> u16 {
    let mut sum: u32 = 0;

    // Pseudo-header: src address
    let mut i = 0;
    while i + 1 < src_ip.len() {
        sum += (src_ip[i] as u32) << 8 | src_ip[i + 1] as u32;
        i += 2;
    }

    // Pseudo-header: dst address
    i = 0;
    while i + 1 < dst_ip.len() {
        sum += (dst_ip[i] as u32) << 8 | dst_ip[i + 1] as u32;
        i += 2;
    }

    // Pseudo-header: payload length (32-bit, big-endian)
    let plen = icmp_data.len() as u32;
    sum += plen >> 16;
    sum += plen & 0xffff;

    // Pseudo-header: next header (58 = ICMPv6)
    sum += 58;

    // ICMPv6 data
    i = 0;
    while i + 1 < icmp_data.len() {
        sum += (icmp_data[i] as u32) << 8 | icmp_data[i + 1] as u32;
        i += 2;
    }
    if icmp_data.len() % 2 == 1 {
        sum += (icmp_data[icmp_data.len() - 1] as u32) << 8;
    }

    while sum > 0xffff {
        sum = (sum >> 16) + (sum & 0xffff);
    }
    !sum as u16
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_icmpv4_echo_reply() {
        // Minimal IPv4 ICMP echo request (20-byte IP header + 8-byte ICMP)
        let mut pkt = vec![0u8; 28];
        pkt[0] = 0x45; // version 4, IHL 5
        pkt[9] = 1;    // protocol = ICMP
        // src IP: 10.0.0.2
        pkt[12..16].copy_from_slice(&[10, 0, 0, 2]);
        // dst IP: 8.8.8.8
        pkt[16..20].copy_from_slice(&[8, 8, 8, 8]);
        // ICMP type = 8 (echo request), code = 0
        pkt[20] = 8;
        pkt[21] = 0;
        // ICMP id = 1, seq = 1
        pkt[24] = 0;
        pkt[25] = 1;
        pkt[26] = 0;
        pkt[27] = 1;
        // Set valid checksums
        pkt[10] = 0;
        pkt[11] = 0;
        let ip_csum = internet_checksum(&pkt[..20]);
        pkt[10] = (ip_csum >> 8) as u8;
        pkt[11] = ip_csum as u8;
        pkt[22] = 0;
        pkt[23] = 0;
        let icmp_csum = internet_checksum(&pkt[20..]);
        pkt[22] = (icmp_csum >> 8) as u8;
        pkt[23] = icmp_csum as u8;

        let reply = handle_icmp_echo(&pkt).expect("should handle ICMP echo");
        // Check it's a reply
        assert_eq!(reply[20], 0, "ICMP type should be 0 (echo reply)");
        // Check IPs are swapped
        assert_eq!(&reply[12..16], &[8, 8, 8, 8], "src should be 8.8.8.8");
        assert_eq!(&reply[16..20], &[10, 0, 0, 2], "dst should be 10.0.0.2");
        // Verify checksums are valid
        assert_eq!(internet_checksum(&reply[..20]), 0, "IP checksum should be valid");
        assert_eq!(internet_checksum(&reply[20..]), 0, "ICMP checksum should be valid");
    }

    #[test]
    fn test_non_icmp_ignored() {
        let mut pkt = vec![0u8; 28];
        pkt[0] = 0x45;
        pkt[9] = 6; // TCP, not ICMP
        assert!(handle_icmp_echo(&pkt).is_none());
    }

    #[test]
    fn test_icmpv6_echo_reply() {
        // IPv6 header (40 bytes) + ICMPv6 echo request (8 bytes)
        let mut pkt = vec![0u8; 48];
        pkt[0] = 0x60; // version 6
        pkt[4] = 0;    // payload length high
        pkt[5] = 8;    // payload length low = 8
        pkt[6] = 58;   // next header = ICMPv6
        pkt[7] = 64;   // hop limit
        // src IPv6: ::1
        pkt[23] = 1;
        // dst IPv6: ::2
        pkt[39] = 2;
        // ICMPv6 type = 128 (echo request)
        pkt[40] = 128;
        pkt[41] = 0;
        // ID and seq
        pkt[44] = 0;
        pkt[45] = 1;
        pkt[46] = 0;
        pkt[47] = 1;
        // Calculate correct checksum
        pkt[42] = 0;
        pkt[43] = 0;
        let csum = icmpv6_checksum(&pkt[8..24], &pkt[24..40], &pkt[40..]);
        pkt[42] = (csum >> 8) as u8;
        pkt[43] = csum as u8;

        let reply = handle_icmp_echo(&pkt).expect("should handle ICMPv6 echo");
        assert_eq!(reply[40], 129, "ICMPv6 type should be 129 (echo reply)");
        // Check IPs are swapped: src should be ::2, dst should be ::1
        assert_eq!(reply[23], 2, "src should be ::2");
        assert_eq!(reply[39], 1, "dst should be ::1");
        // Verify checksum
        let verify = icmpv6_checksum(&reply[8..24], &reply[24..40], &reply[40..]);
        // A valid checksum means computing over the data with checksum field set produces 0
        // Actually, since we set the checksum correctly, computing over it should give 0
        // But our function zeroes the checksum field before computing. Let's verify differently:
        let mut check_pkt = reply.clone();
        check_pkt[42] = 0;
        check_pkt[43] = 0;
        let recomputed = icmpv6_checksum(&check_pkt[8..24], &check_pkt[24..40], &check_pkt[40..]);
        assert_eq!(
            recomputed,
            (reply[42] as u16) << 8 | reply[43] as u16,
            "ICMPv6 checksum should be valid"
        );
    }

    #[test]
    fn test_too_short_packet() {
        assert!(handle_icmp_echo(&[]).is_none());
        assert!(handle_icmp_echo(&[0x45]).is_none());
        assert!(handle_icmp_echo(&[0x60; 10]).is_none());
    }
}
