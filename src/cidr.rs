use std::net::{IpAddr, Ipv4Addr, Ipv6Addr};

/// IP-адрес или подсеть в формате CIDR.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct Cidr {
    addr: IpAddr,
    prefix: u8,
}

impl Cidr {
    pub fn parse(value: &str) -> Result<Self, String> {
        let value = value.trim();
        let (addr, prefix) = match value.split_once('/') {
            Some((addr, prefix)) => (addr, Some(prefix)),
            None => (value, None),
        };

        let addr = addr
            .parse::<IpAddr>()
            .map_err(|_| format!("invalid IP address {addr:?}"))?;

        let max_prefix = match addr {
            IpAddr::V4(_) => 32,
            IpAddr::V6(_) => 128,
        };

        let prefix = match prefix {
            Some(prefix) => prefix
                .parse::<u8>()
                .map_err(|_| format!("invalid prefix length {prefix:?}"))?,
            None => max_prefix,
        };

        if prefix > max_prefix {
            return Err(format!("prefix length {prefix} exceeds {max_prefix}"));
        }

        Ok(Self { addr, prefix })
    }

    pub fn contains(&self, ip: IpAddr) -> bool {
        match (self.addr, ip) {
            (IpAddr::V4(network), IpAddr::V4(ip)) => {
                mask_v4(network, self.prefix) == mask_v4(ip, self.prefix)
            }
            (IpAddr::V6(network), IpAddr::V6(ip)) => {
                mask_v6(network, self.prefix) == mask_v6(ip, self.prefix)
            }
            _ => false,
        }
    }
}

fn mask_v4(addr: Ipv4Addr, prefix: u8) -> u32 {
    let bits = u32::from(addr);

    if prefix == 0 {
        0
    } else {
        bits & (u32::MAX << (32 - prefix))
    }
}

fn mask_v6(addr: Ipv6Addr, prefix: u8) -> u128 {
    let bits = u128::from(addr);

    if prefix == 0 {
        0
    } else {
        bits & (u128::MAX << (128 - prefix))
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn ip(value: &str) -> IpAddr {
        value.parse().unwrap()
    }

    #[test]
    fn parses_single_address() {
        let cidr = Cidr::parse("192.168.1.10").unwrap();

        assert!(cidr.contains(ip("192.168.1.10")));
        assert!(!cidr.contains(ip("192.168.1.11")));
    }

    #[test]
    fn parses_ipv4_subnet() {
        let cidr = Cidr::parse("192.168.1.0/24").unwrap();

        assert!(cidr.contains(ip("192.168.1.1")));
        assert!(cidr.contains(ip("192.168.1.255")));
        assert!(!cidr.contains(ip("192.168.2.1")));
    }

    #[test]
    fn ignores_host_bits_in_network_address() {
        let cidr = Cidr::parse("192.168.1.130/24").unwrap();

        assert!(cidr.contains(ip("192.168.1.1")));
        assert!(!cidr.contains(ip("192.168.2.1")));
    }

    #[test]
    fn parses_ipv6_subnet() {
        let cidr = Cidr::parse("2001:db8::/32").unwrap();

        assert!(cidr.contains(ip("2001:db8::1")));
        assert!(cidr.contains(ip("2001:db8:ffff::1")));
        assert!(!cidr.contains(ip("2001:db9::1")));
    }

    #[test]
    fn zero_prefix_matches_all_addresses_of_same_family() {
        let cidr = Cidr::parse("0.0.0.0/0").unwrap();

        assert!(cidr.contains(ip("127.0.0.1")));
        assert!(cidr.contains(ip("203.0.113.7")));
        assert!(!cidr.contains(ip("::1")));
    }

    #[test]
    fn different_families_do_not_match() {
        let cidr = Cidr::parse("0.0.0.0/0").unwrap();

        assert!(!cidr.contains(ip("::1")));
    }

    #[test]
    fn rejects_invalid_ip() {
        assert!(Cidr::parse("not-an-ip").unwrap_err().contains("invalid IP"));
    }

    #[test]
    fn rejects_invalid_prefix() {
        assert!(
            Cidr::parse("192.168.1.0/abc")
                .unwrap_err()
                .contains("invalid prefix")
        );
    }

    #[test]
    fn rejects_prefix_larger_than_address_width() {
        assert!(
            Cidr::parse("192.168.1.0/33")
                .unwrap_err()
                .contains("exceeds 32")
        );
        assert!(
            Cidr::parse("2001:db8::/129")
                .unwrap_err()
                .contains("exceeds 128")
        );
    }
}
