#pragma once

#include <memory>
#include <cstdio>
#include "Pcap.h"

namespace pcap {


/**
 * The Frame design.
 * An instance of Frame class represents a memory area divided into three subareas.
 * The class provides a bounds checking solution for safe reading and heads moving operations.
 *
 *                 head               tail
 *                   |                 |
 *   | <- offset ->  | <- available -> | <- padding -> |
 *   |R|R|R|R|R|R|R|R|A|A|A|A|A|A|A|A|A|P|P|P|P|P|P|P|P|
 *   | <-------------------- size -------------------> |
 * begin                                              end
 *
 * R - already read.
 * A - available to read.
 * P - padding bytes, they're not available to read.
 *
 * The frame is divided into three subareas called 'offset', 'available' and 'padding'.
 *
 * There is no way to move 'begin' and 'end' points (after resetting the frame) but 'head' and 'tail' can be moved.
 * Moving 'head' and 'tail' points affects the subareas they start or end with.
 *
 **/
class Frame {

	using PtrBase_t = uint8_t;

protected:
	std::unique_ptr<PtrBase_t[]> _begin;
	size_t _offset;    // bytes have been read
	size_t _available; // bytes available to read
	size_t _padding;   // padding bytes
	uint64_t _index;   // The frame index in the PCAP dump file.

public:

	Frame(const Frame&) = delete;
	Frame& operator=(const Frame&) = delete;

	Frame(Frame&& rv) noexcept = delete;
	Frame& operator=(Frame&& rv) = delete;

	Frame() noexcept :
		_begin(new PtrBase_t[Limits::FRAME_SIZE_LIMIT])
		, _offset(0)
		, _available(0)
		, _padding(0) {}

	/**
	 * @return The 'begin' pointer.
	 */
	inline PtrBase_t* begin() const noexcept {
		return _begin.get();
	}

	/**
	 * @return The 'head' pointer.
	 */
	inline PtrBase_t* head() const noexcept {
		return begin() + _offset;
	}

	/**
	 * @return The 'tail' pointer.
	 */
	inline PtrBase_t* tail() const noexcept {
		return head() + available();
	}

	/**
	 * @return The 'end' pointer.
	 */
	inline PtrBase_t* end() const noexcept {
		return tail() + _padding;
	}

	/**
	 * @return The distance between 'begin' and 'end'
	 */
	inline size_t size() const noexcept {
		return _offset + _available + _padding;
	}

	/**
	 * @return The distance between 'begin' and 'head'
	 */
	inline size_t offset() const noexcept {
		return _offset;
	}

	/**
	 * @return The distance between 'head' and 'tail'
	 */
	inline size_t available() const noexcept {
		return _available;
	}

	/**
	 * @return The distance between 'tail' and 'end'
	 */
	inline size_t padding() const noexcept {
		return _padding;
	}

	/**
	 * @return true - if at least @bytes are available.
	 */
	inline bool available(const size_t bytes) const noexcept {
		return bytes <= _available;
	}

	/**
	 * @return The size of the internal buffer.
	 */
	inline static constexpr size_t capacity() noexcept {
		return Limits::FRAME_SIZE_LIMIT;
	}

	/**
	 * Reset the state of the packet.
	 * @return true - if the packet has enough stace in the memory area to perform the operation.
	 */
	inline bool reset(size_t available, uint64_t index) noexcept {
		_offset = 0;
		_available = available;
		_padding = 0;
		_index = index;
		return available < capacity();
	}

	/**
	 * Move the head @bytes forward.
	 * @param bytes - bytes to move.
	 * @return true - if the packet has enough stace in the memory area to perform the operation.
	 */
	inline bool head_move(const size_t bytes) noexcept {
		bool result = bytes <= _available;
		if(result) {
			_offset += bytes;
			_available -= bytes;
		}
		return result;
	}

	/**
	 * Move the head @bytes backward.
	 * @param bytes - bytes to move.
	 * @return true - if the packet has enough stace in the memory area to perform the operation.
	 */
	inline bool head_move_back(const size_t bytes) noexcept {
		const bool result = bytes <= offset();
		if(result) {
			_offset -= bytes;
			_available += bytes;
		}
		return result;
	}

	/**
	 * Move the tail @bytes forward.
	 * @param bytes - bytes to move.
	 * @return true - if the packet has enough stace in the memory area to perform the operation.
	 */
	inline bool tail_move(const size_t bytes) noexcept {
		const bool result = bytes <= _padding;
		if(result) {
			_available += bytes;
			_padding -= bytes;
		}
		return result;
	}

	/**
	 * Move the tail @bytes backward.
	 * @param bytes - bytes to move.
	 * @return true - if the packet has enough stace in the memory area to perform the operation.
	 */
	inline bool tail_move_back(const size_t bytes) noexcept {
		const bool result = bytes <= offset();
		if(result) {
			_available -= bytes;
			_padding += bytes;
		}
		return result;
	}

	/**
	 * Read @value from the packet.
	 * The head moves to the new position.
	 * @param value - variable to read to.
	 * @return true - if the packet has enough stace in the memory area to perform the operation.
	 */
	template<typename V>
	inline bool read(V& value) noexcept {
		const bool result = sizeof(V) <= _available;
		if(result) {
			read_impl(value);
		}
		return result;
	}

	/**
	 * Read @value and @args from the packet.
	 * The head moves to the new position.
	 * @param value - a variable to read to.
	 * @param args - variables to read to.
	 * @return true - if the packet has enough stace in the memory area to perform the operation.
	 */
	template<typename V, typename... Args>
	inline bool read(V& value, Args& ... args) noexcept {
		const bool result = sizeof_args(value, args...) <= _available;
		if(result) {
			read_impl(value, args...);
		}
		return result;
	}

	/**
	 * Assign a pointer to the head.
	 * The head moves to the new position.
	 * @param pointer - a pointer to assign.
	 * @return true - if the packet has enough stace in the memory area to perform the operation.
	 */
	template<typename V>
	inline bool assign(V*& pointer) noexcept {
		const bool result = sizeof(V) <= _available;
		if(result) {
			pointer = reinterpret_cast<V*>(head());
			_offset += sizeof(V);
			_available -= sizeof(V);
		}
		return result;
	}

	/**
	 * Assign a pointer to the head.
	 * The head doesn't move.
	 * @param pointer - a pointer to assign.
	 * @return true - if the packet has enough stace in the memory area to perform the operation.
	 */
	template<typename V>
	inline bool assign_stay(V*& pointer) noexcept {
		const bool result = sizeof(V) <= _available;
		if(result) {
			pointer = reinterpret_cast<V*>(head());
		}
		return result;
	}

	inline void dump(FILE* out) const {
		fprintf(out, "Frame [idx=%zu off=%zu avl=%zu pad=%zu] | ", _index, _offset, _available, _padding);
	}

protected:

	static inline constexpr size_t sizeof_args() noexcept {
		return 0;
	}

	template<typename V, typename... Args>
	static inline constexpr size_t sizeof_args(V& value, Args& ... args) noexcept {
		return sizeof(value) + sizeof_args(args...);
	}

	template<typename V>
	inline void read_impl(V& value) noexcept {
		value = *reinterpret_cast<const V*>(head());
		_offset += sizeof(V);
		_available -= sizeof(V);
	}

	template<typename V, typename... Args>
	inline void read_impl(V& value, Args& ... args) noexcept {
		read_impl(value);
		read_impl(args...);
	}

};

}; // namespace pcap;
