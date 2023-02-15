#pragma once

#include <cstdlib>
#include <cstring>
#include <cstdint>

#include "../ip.h"

namespace proto_ip {

// see Ethernet.h for more details

class IPv6 {
public:

	struct Addr {
		union {
			uint8_t addr8[16];
			uint16_t addr16[8];
			uint32_t addr32[4];
			uint64_t addr64[2];
		};
	} __attribute__ ((__packed__));

	struct Header {
		union {
			struct {
#if __BYTE_ORDER == __LITTLE_ENDIAN
				uint8_t traffic_class0 : 4;
				uint8_t version : 4;
#elif __BYTE_ORDER == __BIG_ENDIAN
				uint8_t version : 4;
				uint8_t traffic_class0 : 4;
#else
# error	"qlib::proto::IPv6"
#endif
			};
			uint8_t vtc;
		};
		union {
			struct {
#if __BYTE_ORDER == __LITTLE_ENDIAN
				uint8_t flow_label0 : 4;
				uint8_t traffic_class1 : 4;
#elif __BYTE_ORDER == __BIG_ENDIAN
				uint8_t traffic_class1 : 4;
				uint8_t flow_label0 : 4;
#else
# error	"qlib::proto::IPv6"
#endif
			};
			uint8_t tcfl;
		};
		uint16_t flow_label1;
		uint16_t payload_len;
		uint8_t next_header;
		uint8_t hop_limit;
		Addr src;
		Addr dst;

	} __attribute__ ((__packed__));


	static constexpr uint8_t PROTO_UDP = 17;

	static bool validate_packet(pcap::Frame& pkt) noexcept {
		const Header* hdr;
		if(pkt.assign_stay(hdr)) {
			const auto available = pkt.available();
			const auto pkt_size = ntohs(hdr->payload_len) + sizeof(Header);
			if(hdr->version == 6/*IP_V4*/ && available >= pkt_size) {

				// adjust padding if necessary
				return pkt.tail_move_back(available - pkt_size);
			}
		}
		return false;
	}

	static Protocol next(pcap::Frame& pkt) noexcept {
		Protocol result = Protocol::END;
		Header* hdr;
		if(pkt.assign(hdr)) {
			switch(hdr->next_header) {
				case PROTO_UDP:
					result = Protocol::L4_UDP;
					break;

			}
		}
		return result;
	}

};

}; // namespace ip

