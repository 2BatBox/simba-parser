#pragma once

#include <linux/if_ether.h>
#include <arpa/inet.h>

#include "../ip.h"

namespace proto_ip {

class Ethernet {
public:

	using Header = ethhdr;

	/**
	 * @param pkt
	 * @return true if 'pkt' has a valid Ethernet protocol packet
	 */
	static inline bool validate_packet(const pcap::Frame& pkt) noexcept {
		// Ethernet IEEE 802.3 standard defines the minimum Ethernet frame size_addr as 64 bytes.
		// However, it's possible to get an Ethernet frame with size less than 64 bytes
		// from a modified PCAP dump file for example.
		// return pkt.available(sizeof(Header));
		return pkt.available(64); // Should be used in case of following the standard accurately.
	}

	/**
	 * The method MUST NOT be called for the certain packet without validating it with
	 * validate_packet().
	 * Skip the header of the protocol and return the next protocol identifier.
	 * @param pkt
	 * @return the next protocol identifier or Protocol::END in case of unknown payload type.
	 */
	static Protocol next(pcap::Frame& pkt) noexcept {
		Protocol result = Protocol::END;

		const Header* hdr;
		if(pkt.assign(hdr)) {
			switch(ntohs(hdr->h_proto)) {
				case ETH_P_IP:
					result = Protocol::L3_IPv4;
					break;
				case ETH_P_IPV6:
					result = Protocol::L3_IPv6;
					break;
				case ETH_P_8021Q:
					result = Protocol::L2_VLAN;
					break;
				default:
					break;
			}
		}

		return result;
	}

};

}; // namespace ip

