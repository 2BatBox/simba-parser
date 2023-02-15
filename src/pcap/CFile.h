#pragma once

#include <cstdio>

namespace pcap {

class CFile {

	FILE* _file;

public:

	CFile(const CFile&) = delete;
	CFile& operator=(const CFile&) = delete;

	CFile() noexcept : _file(nullptr) {}
	explicit CFile(FILE* file) noexcept : _file(file) {}

	CFile(CFile&& rvalue) noexcept : _file(rvalue._file) {
		rvalue.clear();
	}

	CFile& operator=(CFile&& rvalue) noexcept {
		if(this != &rvalue) {
			close();
			_file = rvalue._file;
			rvalue.clear();
		}
		return *this;
	}

	~CFile() noexcept {
		close();
	}

	inline void close() noexcept {
		if(_file) {
			fclose(_file);
			clear();
		}
	}

	inline FILE* get() noexcept {
		return _file;
	}

	inline const FILE* get() const noexcept {
		return _file;
	}

	template <typename T>
	inline bool read_pod(T& pod) noexcept {
		const auto read = fread(&pod, sizeof(pod), 1u, _file);
		return read == 1u;
	}

	template <typename T>
	inline bool read_bytes(T* buffer, size_t size) noexcept {
		const auto read = fread(buffer, 1u, size, _file);
		return read == size;
	}

	inline bool skip_bytes(size_t size) noexcept {
		return (fseek(_file, size, SEEK_CUR) == 0);
	}

private:

	inline void clear() noexcept {
		_file = nullptr;
	}

};

}; // namespace pcap;
