#pragma once

#include <cstdint>
#include <string>
#include <cmath>

namespace simba {

template <typename T, const T NullValue>
struct IntNull {
	T _value;

	inline bool is_null() const noexcept {
		return _value == NullValue;
	}

	inline std::string to_string() const noexcept {
		return is_null() ? "'null'" : std::to_string(_value);
	}

} __attribute__ ((__packed__));

template <typename T, const T NullValue, const T div>
struct DecimalNull {
	T _value;

	inline double get() const noexcept {
		return double(_value) / div;
	}

	inline bool is_null() const noexcept {
		return _value == NullValue;
	}

	inline std::string to_string() const noexcept {
		return is_null() ? "'null'" : std::to_string(get());
	}

} __attribute__ ((__packed__));

using uInt8 = uint8_t;
using uInt16 = uint16_t;
using uInt32 = uint32_t;
using uInt64 = uint64_t;

using Int8 = int8_t;
using Int16 = int16_t;
using Int32 = int32_t;
using Int64 = int64_t;

using uInt8Null = uint8_t;
using uInt16Null = uint16_t;
using uInt32Null = uint32_t;
using uInt64Null = uint64_t;

using Int8Null = IntNull<int8_t, int8_t(0x80)>;
using Int16Null = IntNull<int16_t, int16_t(0x8000)>;
using Int32Null = IntNull<int32_t, int32_t(0x80000000)>;
using Int64Null = IntNull<int64_t, int64_t(0x8000000000000000)>;

using Decimal2Null = DecimalNull<int64_t, 0x7fffffffffffffff, 100ll>;
using Decimal5Null = DecimalNull<int64_t, 0x7fffffffffffffff, 100000ll>;

using MDFlagsSet = uint64_t;
using MDEntryType = char;

enum MDFlagsBits : uint8_t {
	Day = 0u,
	IOC = 1u,
	NonQuote = 2u,
	EndOfTransaction = 12u,
	SecondLeg = 14u,
	FOK = 19u,
	Replace = 20u,
	Cancel = 21u,
	MassCancel = 22u,
	Negotiated = 26u,
	MultiLeg = 27u,
	CrossTrade = 29u,
	COD = 32u,
	ActiveSide = 41u,
	PassiveSide = 42u,
	Synthetic = 45u,
	RFS = 46u,
	SyntheticPassive = 57u,
	BOC = 60u,
	DuringDiscreteAuction = 62u
};

const char* md_flag_bits_name(const MDFlagsBits& bits) noexcept {
	switch(bits) {
		case MDFlagsBits::Day : return "Day";
		case MDFlagsBits::IOC : return "IOC";
		case MDFlagsBits::NonQuote : return "NonQuote";
		case MDFlagsBits::EndOfTransaction : return "EndOfTransaction";
		case MDFlagsBits::SecondLeg : return "SecondLeg";
		case MDFlagsBits::FOK : return "FOK";
		case MDFlagsBits::Replace : return "Replace";
		case MDFlagsBits::Cancel : return "Cancel";
		case MDFlagsBits::MassCancel : return "MassCancel";
		case MDFlagsBits::Negotiated : return "Negotiated";
		case MDFlagsBits::MultiLeg : return "MultiLeg";
		case MDFlagsBits::CrossTrade : return "CrossTrade";
		case MDFlagsBits::COD : return "COD";
		case MDFlagsBits::ActiveSide : return "ActiveSide";
		case MDFlagsBits::PassiveSide : return "PassiveSide";
		case MDFlagsBits::Synthetic : return "Synthetic";
		case MDFlagsBits::RFS : return "RFS";
		case MDFlagsBits::SyntheticPassive : return "SyntheticPassive";
		case MDFlagsBits::BOC : return "BOC";
		case MDFlagsBits::DuringDiscreteAuction : return "DuringDiscreteAuction";
		default:
			return "UNKNOWN";
	}
}

enum TemplateId : uint16_t {
	Heartbeat = 1u,
	SequenceReset = 2u,
	BestPrices = 3u,
	EmptyBook = 4u,
	OrderUpdate = 5u,
	OrderExecution = 6u,
	OrderBookSnapshot = 7u,
	SecurityStatus = 8u,
	SecurityDefinitionUpdateReport = 10u,
	TradingSessionStatus = 11u,
	SecurityDefinition = 12u,
	DiscreteAuction = 13u,
	Logon = 1000u,
	Logout = 1001u,
	MarketDataRequest = 1002u
};

const char* template_id_name(const TemplateId& tid) noexcept {
	switch(tid) {
		case TemplateId::Heartbeat: return "Heartbeat";
		case TemplateId::SequenceReset:  return "SequenceReset";
		case TemplateId::BestPrices :  return "BestPrices";
		case TemplateId::EmptyBook :  return "EmptyBook";
		case TemplateId::OrderUpdate :  return "OrderUpdate";
		case TemplateId::OrderExecution :  return "OrderExecution";
		case TemplateId::OrderBookSnapshot :  return "OrderBookSnapshot";
		case TemplateId::SecurityStatus :  return "SecurityStatus";
		case TemplateId::SecurityDefinitionUpdateReport :  return "SecurityDefinitionUpdateReport";
		case TemplateId::TradingSessionStatus :  return "TradingSessionStatus";
		case TemplateId::SecurityDefinition :  return "SecurityDefinition";
		case TemplateId::DiscreteAuction :  return "DiscreteAuction";
		case TemplateId::Logon :  return "Logon";
		case TemplateId::Logout :  return "Logout";
		case TemplateId::MarketDataRequest :  return "MarketDataRequest";
		default:
			return "UNKNOWN";
	}
}

enum SchemaId : uint16_t {
	Default = 19780
};

const char* schema_id_name(const SchemaId& sch) noexcept {
	switch(sch) {
		case SchemaId::Default: return "Default";
		default:
			return "UNKNOWN";
	}
}

const char* md_entry_type_name(const MDEntryType& etype) noexcept {
	switch(etype) {
		case '0': return "Bid";
		case '1': return "Ask";
		case 'J': return "Empty-Book";
		default:
			return "UNKNOWN";
	}
}

}; // namespace simba
