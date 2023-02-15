#pragma once

#include <arpa/inet.h>
#include <linux/if_ether.h>

#include "../ip.h"

namespace proto_ip {

// see Ethernet.h for more details

class Vlan {
public:

	struct Header {

		union {
			uint16_t vlan_tci;

			struct {
				uint16_t vid : 12;
				uint16_t dei : 1;
				uint16_t pcp : 3;
			} tci_detailed;
		};
		uint16_t nextProto;
	} __attribute__ ((__packed__));


	static inline bool validate_packet(const pcap::Frame& pkt) noexcept {
		return pkt.available(sizeof(Header));
	}

	static Protocol next(pcap::Frame& pkt) noexcept {
		Protocol result = Protocol::END;

		const Header* hdr;
		if(pkt.assign(hdr)) {
			switch(ntohs(hdr->nextProto)) {
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

