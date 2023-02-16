#include <cstdio>
#include <cstdlib>

#include "pcap/Reader.h"
#include "IpFrameParser.h"
#include "SimbaParser.h"

bool extract_udp_payload(pcap::Frame& frame) noexcept {
	bool result = false;
	IpFrameParser parser(frame);
	auto proto = parser.protocol();
	while(proto != proto_ip::Protocol::END) {
		proto = parser.next();
		if(proto == proto_ip::Protocol::L4_UDP) {
			// Move the head to the UDP playload.
			parser.next();
			result = true;
			break;
		}

	}
	return result;
}

int main(int argc, char** argv) noexcept {
	if(argc < 2) {
		fprintf(stderr, "usage: %s [pcap-file]\n", argv[0]);
		return EXIT_FAILURE;
	}

	pcap::Reader reader(argv[1]);
	if(reader.open()) {
		pcap::Frame frame;
		while(reader.load(frame)) {
			if(extract_udp_payload(frame)) {
				SimbaParser parser(frame);
				if(not parser.dump(stdout)) {
					frame.dump(stderr);
					fprintf(stderr, "The frame is dropped!\n");
				}
				printf("\n");
			} else {
				frame.dump(stderr);
				fprintf(stderr, ": The frame is dropped, not a UDP packet\n");
			}
		}
	}

	return EXIT_SUCCESS;
}
