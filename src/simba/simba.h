#pragma once

#include <cstdint>

#include "types.h"

namespace simba {


//===================================
// 2.3.3. Market Data Packet Header
//===================================
struct MarketDataPacketHeader {

	enum class Flags : uint8_t {
		LastFragment,
		StartOfSnapshot,
		EndOfSnapshot,
		IncrementalPacket,
		PossDupFlag,
	};

	uInt32 msg_seq_num;  // Y
	uInt16 msg_size;     // Y
	uInt16 msg_flags;    // Y
	uInt64 sending_time; // Y

	inline bool has_flag(const Flags& flag) const noexcept {
		const uInt16 flag_mask = (uInt16(1ull) << static_cast<uint16_t>(flag));
		return (msg_flags & flag_mask) == flag_mask;
	}

	void dump(FILE* out) const noexcept {
		fprintf(out, "MarketDataPacketHeader [");
		fprintf(out, " msg_seq_num=%u", msg_seq_num);
		fprintf(out, " msg_size=%u", msg_size);
		fprintf(out, " msg_flags=0x%x", msg_flags);

		if(msg_flags) {
			fprintf(out, "(");
			fprintf(out, "%s", has_flag(Flags::LastFragment) ? " LastFragment" : "");
			fprintf(out, "%s", has_flag(Flags::StartOfSnapshot) ? " StartOfSnapshot" : "");
			fprintf(out, "%s", has_flag(Flags::EndOfSnapshot) ? " EndOfSnapshot" : "");
			fprintf(out, "%s", has_flag(Flags::IncrementalPacket) ? " IncrementalPacket" : "");
			fprintf(out, "%s", has_flag(Flags::PossDupFlag) ? " PossDupFlag" : "");
			fprintf(out, " )");
		}

		fprintf(out, " sending_time=0x%zu", sending_time);
		fprintf(out, " ]\n");
	}

} __attribute__ ((__packed__));


//===================================
// 2.3.4. Incremental Packet Header
//===================================
struct IncrementalHeader {
	uint64_t transact_time;               // Y
	uint32_t exchange_trading_session_id; // N

	void dump(FILE* out) noexcept {
		fprintf(out, "IncrementalHeader [");
		fprintf(out, " transact_time=%zu", transact_time);
		fprintf(out, " exchange_trading_session_id=0x%u", exchange_trading_session_id);
		fprintf(out, "]\n");
	}

} __attribute__ ((__packed__));


//===================================
// 2.3.5. SBE Header
//===================================
struct SBEMessageHeader {
	uInt16 block_length;  // Y
	TemplateId template_id; // Y
	SchemaId schema_id;     // Y
	uInt16 version;       // Y

	void dump(FILE* out) const noexcept {
		fprintf(out, "SBEMessage [");
		fprintf(out, " block_length=%u", block_length);
		fprintf(out, " template_id='%s'(%u)", template_id_name(template_id), template_id);
		fprintf(out, " schema_id='%s'(%u)", schema_id_name(schema_id), schema_id);
		fprintf(out, " version=%u", version);
		fprintf(out, " ]\n");
	}

} __attribute__ ((__packed__));


//===================================
// 4.1.5. OrderBookSnapshot (msg id=7)
//===================================
struct OrderBookSnapshotRoot {
	uInt32 security_id;
	uInt32 last_msg_seq_sum_processed;
	uInt32 rpt_seq;
	uInt32 exchange_trading_session_id;

	void dump(FILE* out) noexcept {
		fprintf(out, "OrderBookSnapshotRoot [");
		fprintf(out, " security_id=%u", security_id);
		fprintf(out, " last_msg_seq_sum_processed=%u", last_msg_seq_sum_processed);
		fprintf(out, " rpt_seq=%u", rpt_seq);
		fprintf(out, " exchange_trading_session_id=%u", exchange_trading_session_id);
		fprintf(out, " ]\n");
	}

} __attribute__ ((__packed__));


struct GroupSize {
	uInt16 block_length;
	uInt8 num_in_group;

	void dump(FILE* out) noexcept {
		fprintf(out, "GroupSize [");
		fprintf(out, " block_ength=%u", block_length);
		fprintf(out, " num_in_group=%u", num_in_group);
		fprintf(out, " ]\n");
	}

} __attribute__ ((__packed__));


struct OrderBookSnapshotEntry {
	Int64Null md_entry_id;
	uInt64 transact_time;
	Decimal5Null md_entry_px;
	Int64Null md_entry_size;
	Int64Null trade_id;
	MDFlagsSet ms_flags;
	MDEntryType md_entry_type;

	void dump(FILE* out) noexcept {
		fprintf(out, "OrderBookSnapshotEntry [");
		fprintf(out, " md_entry_id=%s", md_entry_id.to_string().c_str());
		fprintf(out, " transact_time=%zu", transact_time);
		fprintf(out, " md_entry_px=%s", md_entry_px.to_string().c_str());
		fprintf(out, " md_entry_size=%s", md_entry_size.to_string().c_str());
		fprintf(out, " trade_id=%s", trade_id.to_string().c_str());
		fprintf(out, " ms_flags=0x%zx", ms_flags);

		if(ms_flags) {
			fprintf(out, "(");
			for(uint8_t bit = 0; bit < sizeof(MDFlagsSet) * 8u; ++bit) {
				const MDFlagsSet mask = 1ull << bit;
				if(ms_flags & mask) {
					fprintf(out, " %s", md_flag_bits_name(static_cast<MDFlagsBits>(bit)));
				}
			}
			fprintf(out, " )");
		}


		fprintf(out, " md_entry_type='%s'", md_entry_type_name(md_entry_type));
		fprintf(out, " ]\n");
	}

} __attribute__ ((__packed__));


}; // namespace simba
