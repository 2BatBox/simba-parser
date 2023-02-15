#include <cstdio>
#include <cstdlib>

#include "pcap/Reader.h"
#include "IpFrameParser.h"
#include "SimbaParser.h"

bool extract_udp_payload(pcap::Frame& frame) noexcept {
	IpFrameParser parser(frame);
	auto proto = parser.protocol();
	while(proto != proto_ip::Protocol::END) {
		proto = parser.next();
		if(proto == proto_ip::Protocol::L4_UDP) {
			parser.next();
			return true;
		}
	}
	return false;
}

void process_file(pcap::Reader& reader) {
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
			fprintf(stderr, ": The packet is skipped, not a UDP packet\n");
		}
	}
}

int main(int argc, char** argv) noexcept {
	if(argc < 2) {
		fprintf(stderr, "usage: %s [pcap-file(s)]\n", argv[0]);
		return EXIT_FAILURE;
	}

	int err = EXIT_SUCCESS;
	for(int idx = 1; idx < argc; ++idx) {
		pcap::Reader reader(argv[idx]);
		if(reader.open()) {
			process_file(reader);
		} else {
			err = EXIT_FAILURE;
			break;
		}
	}

	return err;
}
