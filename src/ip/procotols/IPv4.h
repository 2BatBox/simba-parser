#pragma once

#include <cstdlib>
#include <netinet/ip.h>
#include <cstring>

#include "../ip.h"

namespace proto_ip {

// see Ethernet.h for more details

class IPv4 {
public:

	using Header = iphdr;
	using Addr = uint32_t;
	struct Net {
		Addr addr;
		Addr mask;
	};

	static constexpr uint16_t FRAG_MASK = 0x3FFF;
	static constexpr uint8_t PROTO_UDP = 17;

	static bool validate_packet(pcap::Frame& pkt) noexcept {
		const Header* hdr;
		if(pkt.assign_stay(hdr)) {
			const auto available = pkt.available();
			u_int16_t header_nb = hdr_len(hdr);
			u_int16_t packet_nb = pkt_len(hdr);
			if(
				available >= header_nb
				&& available >= packet_nb
				&& hdr->version == 4/*IP_V4*/
				&& not flag_rf(hdr)
				) {

				// adjust padding if necessary
				return pkt.tail_move_back(available - packet_nb);;
			}
		}
		return false;
	}

	static Protocol next(pcap::Frame& pkt) noexcept {
		Protocol result = Protocol::END;

		const Header* hdr;
		if(pkt.assign(hdr)) {

			switch(hdr->protocol) {
				case PROTO_UDP:
					result = Protocol::L4_UDP;
					break;
			}

			if(fragmented(hdr)) {
				result = Protocol::END;
			}

		}
		return result;
	}

	// header manipulation

	static inline uint16_t pkt_len(const Header* hdr) noexcept {
		return ntohs(hdr->tot_len);
	}

	static inline uint16_t hdr_len(const Header* hdr) noexcept {
		return uint16_t(hdr->ihl << 2u);
	}

	static inline uint16_t payload_len(const Header* hdr) noexcept {
		return ntohs(hdr->tot_len) - uint16_t(hdr->ihl << 2u);
	}

	static inline bool fragmented(const Header* hdr) noexcept {
		return (ntohs(hdr->frag_off) & FRAG_MASK) > 0;
	}

	static inline uint16_t offset(const Header* hdr) noexcept {
		return (uint16_t(ntohs(hdr->frag_off) & uint16_t(IP_OFFMASK)) << 3u);
	}

	// bit 0: Evil Bit. see rfc-3514
	inline static bool flag_rf(const Header* hdr) noexcept {
		return (ntohs(hdr->frag_off) & uint16_t(IP_RF)) > 0u;
	}

};

}; // namespace ip

