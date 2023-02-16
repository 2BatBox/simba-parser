#pragma once

#include <cstdlib>

#include "simba/simba.h"
#include "pcap/Frame.h"

class SimbaParser {
protected:
	pcap::Frame& _frame;

public:

	SimbaParser(pcap::Frame& frame) noexcept :
		_frame(frame) {}

	bool dump(FILE* out) {
		bool result = false;
		const simba::MarketDataPacketHeader* market_data_header;

		_frame.dump(out);
		if(assign(market_data_header)) {

			market_data_header->dump(out);
			if(market_data_header->has_flag(simba::MarketDataPacketHeader::Flags::IncrementalPacket)) {
				result = dump_incremental(out);
			} else {
				result = dump_sbe_message(out);
			}
		}
		return result;
	}

protected:

	bool dump_incremental(FILE* out) noexcept {
		bool result = false;
		simba::IncrementalHeader* incremental_header;

		_frame.dump(out);
		if(assign(incremental_header)) {
			incremental_header->dump(out);
			result = dump_sbe_message(out);

			while(_frame.available() && result) {
				result = dump_sbe_message(out);
			}

		} else {
			fprintf(stderr, "simba::IncrementalHeader is missed.");
		}

		return result;
	}

	bool dump_sbe_message(FILE* out) noexcept {
		bool result = false;

		const simba::SBEMessageHeader* sbe_header;

		_frame.dump(out);
		if(assign(sbe_header)) {
			sbe_header->dump(out);

			if(sbe_header->schema_id == simba::SchemaId::Default) {
				switch(sbe_header->template_id) {

					case simba::TemplateId::Logon:
					case simba::TemplateId::Logout:
					case simba::TemplateId::Heartbeat:
					case simba::TemplateId::SequenceReset:
					case simba::TemplateId::EmptyBook:
					case simba::TemplateId::SecurityStatus:
					case simba::TemplateId::SecurityDefinitionUpdateReport:
					case simba::TemplateId::TradingSessionStatus:
					case simba::TemplateId::MarketDataRequest:
						result = skip_message(*sbe_header);
						break;

					case simba::TemplateId::SecurityDefinition:
					case simba::TemplateId::BestPrices:
					case simba::TemplateId::DiscreteAuction:
						result = skip_message(*sbe_header) && skip_entry();
						break;

					case simba::TemplateId::OrderUpdate:
						result = dump_message<simba::OrderUpdate>(out, *sbe_header);
						break;

					case simba::TemplateId::OrderExecution:
						result = dump_message<simba::OrderExecution>(out, *sbe_header);
						break;

					case simba::TemplateId::OrderBookSnapshot:
						result = dump_message_with_entry<simba::OrderBookSnapshotRoot, simba::OrderBookSnapshotEntry>(
							out, *sbe_header);
						break;

					default:
						fprintf(stderr, "Unknown template id %u \n", static_cast<uint16_t>(sbe_header->template_id));
						break;
				}
			}
		} else {
			fprintf(stderr, "simba::SBEMessageHeader is missed.");
		}

		return result;
	}

	template <typename Header>
	bool dump_message(FILE* out, const simba::SBEMessageHeader& sbe_header) noexcept {
		Header* header;

		if(sbe_header.block_length != sizeof(*header)) {
			fprintf(stderr, "SBEMessageHeader::BlockLength mismatch!");
			fprintf(stderr, " block_length=%u", sbe_header.block_length);
			fprintf(stderr, " expected=%zu\n", sizeof(*header));
			return false;
		}

		_frame.dump(out);
		if(not assign(header)) {
			fprintf(stderr, "The header is missed.");
			return false;
		}

		header->dump(out);
		return true;

	}

	template <typename Header, typename Entry>
	bool dump_message_with_entry(FILE* out, const simba::SBEMessageHeader& sbe_header) noexcept {
		Header* header;
		simba::GroupSize* group_size;
		Entry* entry;

		if(sbe_header.block_length != sizeof(*header)) {
			fprintf(stderr, "SBEMessageHeader::BlockLength mismatch!");
			fprintf(stderr, " block_length=%u", sbe_header.block_length);
			fprintf(stderr, " expected=%zu\n", sizeof(*header));
			return false;
		}

		_frame.dump(out);
		if(not assign(header)) {
			fprintf(stderr, "The header is missed.");
			return false;
		}
		header->dump(out);

		_frame.dump(out);
		if(not assign(group_size)) {
			fprintf(stderr, "simba::GroupSize is missed.");
			return false;
		}

		const size_t expected_size = group_size->block_length * group_size->num_in_group;
		if(expected_size > _frame.available()) {
			fprintf(stderr, "simba::GroupSize::BlockLength mismatch.");
			fprintf(stderr, " available=%zu", _frame.available());
			fprintf(stderr, " expected=%zu\n", expected_size);
			return false;
		}
		group_size->dump(out);

		for(simba::uInt8 grp_idx = 0; grp_idx < group_size->num_in_group; ++grp_idx) {
			_frame.dump(out);
			if(assign(entry)) {
				entry->dump(out);
			}
		}

		return true;
	}

	bool skip_message(const simba::SBEMessageHeader& sbe_header) {
		bool result = _frame.head_move(sbe_header.block_length);
		if(not result) {
			fprintf(stderr, "SBEMessageHeader::BlockLength mismatch!");
			fprintf(stderr, " block_length=%u", sbe_header.block_length);
			fprintf(stderr, " available=%zu\n", _frame.available());
			return false;
		}
		return result;
	}

	bool skip_entry() {
		simba::GroupSize* group_size;
		if(not assign(group_size)) {
			fprintf(stderr, "simba::GroupSize is missed.");
			return false;
		}

		const size_t expected_size = group_size->block_length * group_size->num_in_group;
		if(expected_size > _frame.available()) {
			fprintf(stderr, "simba::GroupSize::BlockLength mismatch.");
			fprintf(stderr, " available=%zu", _frame.available());
			fprintf(stderr, " expected=%zu\n", expected_size);
			return false;
		}

		_frame.head_move(expected_size);

		return true;
	}

	template<typename V>
	inline bool assign(V*& pointer) noexcept {
		bool result = _frame.assign(pointer);
#if __BYTE_ORDER == __BIG_ENDIAN
		if(result){
			pointer->swap_endian();
		}
#endif
		return result;
	}
};


