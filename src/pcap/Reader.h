#pragma once

#include <cstdint>
#include <cstdio>
#include <cstring>
#include <cstdlib>
#include <string>

#include "Pcap.h"
#include "CFile.h"
#include "Frame.h"

namespace pcap {

class Reader {

protected:

	const std::string _file_name;
	CFile _file;
	bool _fields_swap;
	pcap_hdr _pcap_header;
	size_t _next_frame_index;

public:

	Reader(const Reader&) = delete;
	Reader& operator=(const Reader&) = delete;

	Reader(Reader&& rv) noexcept = delete;
	Reader& operator=(Reader&& rv) = delete;

	/**
	 * @param file_name - PCAP file path. MUST NOT be empty.
	 */
	Reader(std::string file_name) noexcept :
		_file_name(std::move(file_name)),
		_file(),
		_fields_swap(false),
		_next_frame_index(0) {}


	/**
	 * WARNING: not virtual destructor is provided.
	 */
	~Reader() noexcept = default;


	/**
	 * Opens PCAP file name which has been provided in constructor 'Reader(std::string)'.
	 * Reads the PCAP file header and validate it.
	 * @return false - in case on any errors.
	 */
	bool open() noexcept {

		auto file = CFile(fopen(_file_name.c_str(), "rb"));
		if(file.get() == nullptr) {
			fprintf(stderr, "'%s' is not available for reading.\n", _file_name.c_str());
			return false;
		}

		if(not file.read_pod(_pcap_header)) {
			fprintf(stderr, "'%s' is not a PCAP file.\n", _file_name.c_str());
			return false;
		}

		if(__builtin_bswap32(_pcap_header.magic_number) == MAGIC_NUMBER) {
			_fields_swap = true;
			header_bytes_swap(_pcap_header);
		}

		// The header validation.
		if(_pcap_header.magic_number != MAGIC_NUMBER) {
			fprintf(stderr, "'%s' : bad magic number, file format is not supported\n", _file_name.c_str());
			return false;
		}

		const bool is_old_ver = _pcap_header.version_major < Limits::VER_MIN_MAJOR ||
		                        (_pcap_header.version_major == Limits::VER_MIN_MAJOR &&
		                         _pcap_header.version_minor < Limits::VER_MIN_MINOR);

		if(is_old_ver) {
			fprintf(stderr, "'%s' : versions before %u.%u is not supported\n",
			        _file_name.c_str(),
			        Limits::VER_MIN_MAJOR,
			        Limits::VER_MIN_MINOR
			);
			return false;
		}

		// The header validation.
		if(_pcap_header.snaplen > Limits::FRAME_SIZE_LIMIT) {
			fprintf(stderr, "'%s' : the frame size is exceeded.\n", _file_name.c_str());
			return false;
		}

		_file = std::move(file);

		return true;
	}

	/**
	 * Reads the next frame from the PCAP file if any.
	 * @param frame - the instance to read to.
	 * @return false - in case of nothing to read or the frame size is exceeded.
	 */
	inline bool load(Frame& frame) noexcept {
		bool result = false;
		pcaprec_hdr record;
		if(_file.read_pod(record)) {

			if(_fields_swap) {
				record_bytes_swap(record);
			}

			if(frame.reset(record.incl_len, _next_frame_index)) {
				result = _file.read_bytes(frame.begin(), frame.available());
			} else {
				fprintf(stderr, "the frame size is exceeded.");
			}

			_next_frame_index++;
		}
		return result;
	}

	/**
	 * @return - The number of the frame that will be read with 'load()' next.
	 */
	inline size_t next_frame_index() const noexcept {
		return _next_frame_index;
	}

	/**
	 * For debug purposes.
	 * @param out - a file stream to print to.
	 */
	void dump_header(FILE* out) const noexcept {
		fprintf(out, "==== struct pcap_hdr ====\n");
		fprintf(out, "\tmagic_number  : 0x%x\n", _pcap_header.magic_number);
		fprintf(out, "\tversion_major : 0x%x\n", _pcap_header.version_major);
		fprintf(out, "\tversion_minor : 0x%x\n", _pcap_header.version_minor);
		fprintf(out, "\tthiszone      : 0x%x\n", _pcap_header.thiszone);
		fprintf(out, "\tsigfigs       : 0x%x\n", _pcap_header.sigfigs);
		fprintf(out, "\tsnaplen       : 0x%x\n", _pcap_header.snaplen);
		fprintf(out, "\tnetwork       : 0x%x\n", _pcap_header.network);
	}

private:

	static inline void header_bytes_swap(pcap_hdr& hdr) noexcept {
		hdr.magic_number = __builtin_bswap32(hdr.magic_number);
		hdr.version_major = __builtin_bswap16(hdr.version_major);
		hdr.version_minor = __builtin_bswap16(hdr.version_minor);
		hdr.thiszone = __builtin_bswap32(hdr.thiszone);
		hdr.sigfigs = __builtin_bswap32(hdr.sigfigs);
		hdr.snaplen = __builtin_bswap32(hdr.snaplen);
		hdr.network = __builtin_bswap32(hdr.network);
	}

	static inline void record_bytes_swap(pcaprec_hdr& rec) noexcept {
		rec.ts_sec = __builtin_bswap32(rec.ts_sec);
		rec.ts_usec = __builtin_bswap32(rec.ts_usec);
		rec.incl_len = __builtin_bswap32(rec.incl_len);
		rec.ts_sec = __builtin_bswap32(rec.ts_sec);
	}

};

}; // namespace pcap;
