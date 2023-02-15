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
		if(_frame.assign(market_data_header)) {
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
		if(_frame.assign(incremental_header)) {
			incremental_header->dump(out);
			result = dump_sbe_message(out);
		} else {
			fprintf(stderr, "simba::IncrementalHeader is missed.");
		}

		return result;
	}

	bool dump_sbe_message(FILE* out) noexcept {
		bool result = false;

		const simba::SBEMessageHeader* sbe_header;

		_frame.dump(out);
		if(_frame.assign(sbe_header)) {
			sbe_header->dump(out);

			if(sbe_header->schema_id == simba::SchemaId::Default) {
				switch(sbe_header->template_id) {

					case simba::TemplateId::OrderUpdate:
						result = dump_order_book_snapshot(out, *sbe_header);
						break;

					case simba::TemplateId::OrderBookSnapshot:
						result = dump_order_book_snapshot(out, *sbe_header);
						break;

					default:
						result = true; // The rest is skipped.
						break;
				}
			}
		} else {
			fprintf(stderr, "simba::SBEMessageHeader is missed.");
		}

		return result;
	}

	bool dump_order_update(FILE* out, const simba::SBEMessageHeader& sbe_header) noexcept {
//		simba::OrderBookSnapshotRoot* root;
//		simba::GroupSize* group_size;
//		simba::OrderBookSnapshotEntry* entry;
//
//		if(sbe_header.block_length != sizeof(simba::OrderBookSnapshotRoot)) {
//			fprintf(stderr, "OrderBookSnapshotRoot::BlockLength mismatch!");
//			fprintf(stderr, " block_length=%u", sbe_header.block_length);
//			fprintf(stderr, " expected=%zu\n", sizeof(simba::OrderBookSnapshotRoot));
//			return false;
//		}
//
//		if(not _frame.assign(root)) {
//			fprintf(stderr, "simba::OrderBookSnapshotRoot is missed.");
//			return false;
//		}
//
//		if(not _frame.assign(group_size)) {
//			fprintf(stderr, "simba::GroupSize is missed.");
//			return false;
//		}
//
//		const size_t expected_size = group_size->block_length * group_size->num_in_group;
//		if(expected_size < _frame.available()) {
//			fprintf(stderr, "simba::GroupSize::BlockLength mismatch.");
//			fprintf(stderr, " available=%zu", _frame.available());
//			fprintf(stderr, " expected=%zu\n", expected_size);
//			return false;
//		}
//
//		root->dump(out);
//		group_size->dump(out);
//
//		for(simba::uInt8 grp_idx = 0; grp_idx < group_size->num_in_group; ++grp_idx) {
//			if(_frame.assign(entry)) {
//				entry->dump(out);
//			}
//		}

		return true;
	}

	bool dump_order_book_snapshot(FILE* out, const simba::SBEMessageHeader& sbe_header) noexcept {
		simba::OrderBookSnapshotRoot* root;
		simba::GroupSize* group_size;
		simba::OrderBookSnapshotEntry* entry;

		if(sbe_header.block_length != sizeof(simba::OrderBookSnapshotRoot)) {
			fprintf(stderr, "OrderBookSnapshotRoot::BlockLength mismatch!");
			fprintf(stderr, " block_length=%u", sbe_header.block_length);
			fprintf(stderr, " expected=%zu\n", sizeof(simba::OrderBookSnapshotRoot));
			return false;
		}

		if(not _frame.assign(root)) {
			fprintf(stderr, "simba::OrderBookSnapshotRoot is missed.");
			return false;
		}

		if(not _frame.assign(group_size)) {
			fprintf(stderr, "simba::GroupSize is missed.");
			return false;
		}

		const size_t expected_size = group_size->block_length * group_size->num_in_group;
		if(expected_size < _frame.available()) {
			fprintf(stderr, "simba::GroupSize::BlockLength mismatch.");
			fprintf(stderr, " available=%zu", _frame.available());
			fprintf(stderr, " expected=%zu\n", expected_size);
			return false;
		}

		root->dump(out);
		group_size->dump(out);

		for(simba::uInt8 grp_idx = 0; grp_idx < group_size->num_in_group; ++grp_idx) {
			if(_frame.assign(entry)) {
				entry->dump(out);
			}
		}

		return true;
	}
};


