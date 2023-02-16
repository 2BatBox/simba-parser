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

	void swap_endian() noexcept {
		msg_seq_num = __builtin_bswap32(msg_seq_num);
		msg_size = __builtin_bswap16(msg_size);
		msg_flags = __builtin_bswap16(msg_flags);
		sending_time = __builtin_bswap64(sending_time);
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

	void swap_endian() noexcept {
		transact_time = __builtin_bswap64(transact_time);
		exchange_trading_session_id = __builtin_bswap32(exchange_trading_session_id);
	}

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

	void swap_endian() noexcept {
		block_length = __builtin_bswap16(block_length);
		template_id = static_cast<TemplateId>(__builtin_bswap16(static_cast<uint16_t>(template_id)));
		schema_id = static_cast<SchemaId>(__builtin_bswap16(static_cast<uint16_t>(schema_id)));
		version = __builtin_bswap16(version);
	}

	void dump(FILE* out) const noexcept {
		fprintf(out, "SBEMessage [");
		fprintf(out, " block_length=%u", block_length);
		fprintf(out, " template_id='%s'(%u)", template_id_name(template_id), static_cast<uint16_t>(template_id));
		fprintf(out, " schema_id='%s'(%u)", schema_id_name(schema_id), static_cast<uint16_t>(schema_id));
		fprintf(out, " version=%u", version);
		fprintf(out, " ]\n");
	}

} __attribute__ ((__packed__));


//===================================
// 4.1.3. OrderUpdate (msg id=5)
//===================================
struct OrderUpdate {
	Int64 md_entry_id;
	Decimal5 md_entry_px;
	Int64 md_entry_size;
	MDFlagsSet md_flags;
	Int32 security_id;
	uInt32 rpt_seq;
	MDUpdateAction md_update_action;
	MDEntryType md_entry_type;

	void swap_endian() noexcept {
		md_entry_id = __builtin_bswap64(md_entry_id);
		md_entry_px._value = __builtin_bswap64(md_entry_px._value);
		md_entry_size = __builtin_bswap64(md_entry_size);
		md_flags = __builtin_bswap64(md_flags);
		security_id = __builtin_bswap32(security_id);
		rpt_seq = __builtin_bswap16(rpt_seq);
	}

	void dump(FILE* out) noexcept {
		fprintf(out, "OrderUpdate [");
		fprintf(out, " md_entry_id=%zd", md_entry_id);
		fprintf(out, " md_entry_px=%f", md_entry_px.get());
		fprintf(out, " md_entry_size=%zd", md_entry_size);
		fprintf(out, " md_flags=0x%zx", md_flags);

		if(md_flags) {
			fprintf(out, "(");
			dump_md_flag_bits(out, md_flags);
			fprintf(out, " )");
		}

		fprintf(out, " md_entry_size=%d", security_id);
		fprintf(out, " rpt_seq=%u", rpt_seq);
		fprintf(out, " md_entry_type='%s'", md_update_action_name(md_update_action));
		fprintf(out, " md_entry_type='%s'", md_entry_type_name(md_entry_type));
		fprintf(out, " ]\n");
	}

} __attribute__ ((__packed__));


//===================================
// 4.1.4. OrderExecution (msg id=6)
//===================================
struct OrderExecution {
	Int64 md_entry_id;
	Decimal5Null md_entry_px;
	Int64Null md_entry_size;
	Decimal5 last_px;
	Int64 last_qty;
	Int64 trade_id;
	MDFlagsSet md_flags;
	Int32 security_id;
	uInt32 rpt_seq;
	MDUpdateAction md_update_action;
	MDEntryType md_entry_type;

	void swap_endian() noexcept {
		md_entry_id = __builtin_bswap64(md_entry_id);
		md_entry_px._value = __builtin_bswap64(md_entry_px._value);
		md_entry_size._value = __builtin_bswap64(md_entry_size._value);
		last_px._value = __builtin_bswap64(last_px._value);
		last_qty = __builtin_bswap64(last_qty);
		trade_id = __builtin_bswap64(trade_id);
		md_flags = __builtin_bswap64(md_flags);
		security_id = __builtin_bswap32(security_id);
		rpt_seq = __builtin_bswap32(rpt_seq);
	}

	void dump(FILE* out) noexcept {
		fprintf(out, "OrderExecution [");
		fprintf(out, " md_entry_id=%zd", md_entry_id);
		fprintf(out, " md_entry_px=%s", md_entry_px.to_string().c_str());
		fprintf(out, " md_entry_size=%s", md_entry_size.to_string().c_str());
		fprintf(out, " last_px=%f", last_px.get());
		fprintf(out, " last_qty=%zd", last_qty);
		fprintf(out, " trade_id=%zd", trade_id);
		fprintf(out, " md_flags=0x%zx", md_flags);

		if(md_flags) {
			fprintf(out, "(");
			dump_md_flag_bits(out, md_flags);
			fprintf(out, " )");
		}

		fprintf(out, " md_entry_size=%d", security_id);
		fprintf(out, " rpt_seq=%u", rpt_seq);
		fprintf(out, " md_entry_type='%s'", md_update_action_name(md_update_action));
		fprintf(out, " md_entry_type='%s'", md_entry_type_name(md_entry_type));
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

	void swap_endian() noexcept {
		security_id = __builtin_bswap32(security_id);
		last_msg_seq_sum_processed = __builtin_bswap32(last_msg_seq_sum_processed);
		rpt_seq = __builtin_bswap32(rpt_seq);
		exchange_trading_session_id = __builtin_bswap32(exchange_trading_session_id);
	}

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

	void swap_endian() noexcept {
		block_length = __builtin_bswap16(block_length);
	}

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
	MDFlagsSet md_flags;
	MDEntryType md_entry_type;

	void swap_endian() noexcept {
		md_entry_id._value = __builtin_bswap64(md_entry_id._value);
		transact_time = __builtin_bswap64(transact_time);
		md_entry_px._value = __builtin_bswap64(md_entry_px._value);
		md_entry_size._value = __builtin_bswap64(md_entry_size._value);
		trade_id._value = __builtin_bswap64(trade_id._value);
		md_flags = __builtin_bswap64(md_flags);
	}

	void dump(FILE* out) noexcept {
		fprintf(out, "OrderBookSnapshotEntry [");
		fprintf(out, " md_entry_id=%s", md_entry_id.to_string().c_str());
		fprintf(out, " transact_time=%zu", transact_time);
		fprintf(out, " md_entry_px=%s", md_entry_px.to_string().c_str());
		fprintf(out, " md_entry_size=%s", md_entry_size.to_string().c_str());
		fprintf(out, " trade_id=%s", trade_id.to_string().c_str());
		fprintf(out, " md_flags=0x%zx", md_flags);

		if(md_flags) {
			fprintf(out, "(");
			dump_md_flag_bits(out, md_flags);
			fprintf(out, " )");
		}

		fprintf(out, " md_entry_type='%s'", md_entry_type_name(md_entry_type));
		fprintf(out, " ]\n");
	}

} __attribute__ ((__packed__));


}; // namespace simba
