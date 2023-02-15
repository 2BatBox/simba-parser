#pragma once

#include <cstdlib>

#include "../pcap/Frame.h"

namespace proto_ip {

enum class Protocol {
	L2_ETHERNET,
	L2_VLAN,
	L3_IPv4,
	L3_IPv6,
	L4_UDP,

	END = 0xFF
};

}; // namespace ip

