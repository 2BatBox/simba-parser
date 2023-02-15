#pragma once

#include <arpa/inet.h>
#include <netinet/udp.h>

#include "../ip.h"

namespace proto_ip {

// see Ethernet.h for more details

class Udp {
public:

	using Header = udphdr;

	static bool validate_packet(pcap::Frame& pkt) noexcept {
		const Header* hdr;
		if(pkt.assign_stay(hdr)) {
			const auto packet_nb = ntohs(hdr->len);
			const auto available = pkt.available();

			if(size_t(packet_nb) < sizeof(Header) || available < packet_nb) {
				return false;
			}

			// Padding adjustment.
			return pkt.tail_move_back(available - packet_nb);
		}
		return false;
	}

	inline static Protocol next(pcap::Frame& pkt) noexcept {
		pkt.head_move(sizeof(Header));
		return Protocol::END;
	}

};

}; // namespace ip

