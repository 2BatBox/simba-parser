#pragma once

#include <cstdint>

namespace pcap {

static constexpr uint32_t MAGIC_NUMBER = 0xA1B2C3D4u;

using FrameSize_t = uint32_t;

struct pcap_hdr {
	uint32_t magic_number;   // magic number
	uint16_t version_major;  // major version number
	uint16_t version_minor;  // minor version number
	int32_t thiszone;        // GMT to local correction
	uint32_t sigfigs;        // accuracy of timestamps
	uint32_t snaplen;        // max length of captured packets, in octets
	uint32_t network;        // data link type
} __attribute__ ((__packed__));

struct pcaprec_hdr {
	uint32_t ts_sec;         // timestamp seconds
	uint32_t ts_usec;        // timestamp microseconds
	uint32_t incl_len;       // number of octets of packet saved in file
	uint32_t orig_len;       // actual length of packet
} __attribute__ ((__packed__));

class Limits {
public:
	static constexpr uint16_t VER_MIN_MAJOR = 2u;
	static constexpr uint16_t VER_MIN_MINOR = 3u;
	static constexpr FrameSize_t FRAME_SIZE_LIMIT = 0xFFFFu;
};

}; // namespace pcap;
