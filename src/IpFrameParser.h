#pragma once

#include <cstdlib>

#include "ip/ip.h"

#include "ip/procotols/Ethernet.h"
#include "ip/procotols/Vlan.h"
#include "ip/procotols/IPv4.h"
#include "ip/procotols/IPv6.h"
#include "ip/procotols/Udp.h"
#include "pcap/Frame.h"

/**
 * IpFrameParser is a protocol stack parser.
 * Might be used to work with packets which contain headers only.
 *   
 * Using sample:
 * IpFrameParser parser(...);
 * 
 * 1.
 * parser.protocol() == Protocol::L2_ETHERNET;
 * assign_stay(ptr) sets 'ptr' to the Ethernet header.
 *
 *  |--Ethernet--|----VLAN----|--IPv4----|----UDP----|
 *  |
 * head
 *
 * 2.
 * parser.next();
 * parser.protocol() == Protocol::VLAN;
 * assign_stay(ptr) sets 'ptr' to the VLAN header.
 *
 *  |--Ethernet--|----VLAN----|--IPv4----|----UDP----|
 *               |
 *              head
 *
 * 3.
 * parser.next();
 * parser.protocol() == Protocol::IPv4;
 * assign_stay(ptr) sets 'ptr' to the IPv4 header.
 * 
 *  |--Ethernet--|----VLAN----|--IPv4----|----UDP----|
 *                            |
 *                           head
 *
 * and etc.
 */

class IpFrameParser {
protected:
	pcap::Frame& _frame;
	proto_ip::Protocol _proto;

public:

	IpFrameParser(pcap::Frame& frame, proto_ip::Protocol proto_first = proto_ip::Protocol::L2_ETHERNET) noexcept :
		_frame(frame),
		_proto(validate_packet(proto_first)) {}

	/**
	 * Return a current protocol in the stack.
	 * @return current protocol
	 */
	inline proto_ip::Protocol protocol() const noexcept {
		return _proto;
	}

	/**
	 * Step to the next protocol in the stack.
	 * @return - the next protocol.
	 */
	proto_ip::Protocol next() noexcept {
		proto_ip::Protocol next_proto = proto_ip::Protocol::END;
		switch(_proto) {
			case proto_ip::Protocol::L2_ETHERNET:
				next_proto = proto_ip::Ethernet::next(_frame);
				break;

			case proto_ip::Protocol::L2_VLAN:
				next_proto = proto_ip::Vlan::next(_frame);
				break;

			case proto_ip::Protocol::L3_IPv4:
				next_proto = proto_ip::IPv4::next(_frame);
				break;

			case proto_ip::Protocol::L3_IPv6:
				next_proto = proto_ip::IPv6::next(_frame);
				break;

			case proto_ip::Protocol::L4_UDP:
				next_proto = proto_ip::Udp::next(_frame);
				break;

			default:
				break;
		}

		_proto = validate_packet(next_proto);
		return _proto;
	}


protected:

	inline proto_ip::Protocol validate_packet(proto_ip::Protocol new_proto) noexcept {
		bool result = false;
		switch(new_proto) {
			case proto_ip::Protocol::L2_ETHERNET:
				result = proto_ip::Ethernet::validate_packet(_frame);
				break;

			case proto_ip::Protocol::L2_VLAN:
				result = proto_ip::Vlan::validate_packet(_frame);
				break;

			case proto_ip::Protocol::L3_IPv4:
				result = proto_ip::IPv4::validate_packet(_frame);
				break;

			case proto_ip::Protocol::L3_IPv6:
				result = proto_ip::IPv6::validate_packet(_frame);
				break;

			case proto_ip::Protocol::L4_UDP:
				result = proto_ip::Udp::validate_packet(_frame);
				break;

			default:
				break;
		}
		if(not result) {
			new_proto = proto_ip::Protocol::END;
		}

		return new_proto;
	}

};


