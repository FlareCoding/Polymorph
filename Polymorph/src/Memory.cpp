#include "Memory.h"
#include <iostream>

constexpr char _s_hexmap_[] = { '0', '1', '2', '3', '4', '5', '6', '7', '8', '9', 'A', 'B', 'C', 'D', 'E', 'F' };

const std::string memory_utils::bytes_to_string(bytearray_t data, int len)
{
	std::string s = "";
	for (int i = 0; i < len; ++i) {
		s += _s_hexmap_[(data[i] & 0xF0) >> 4];
		s += _s_hexmap_[data[i] & 0x0F];
		s += ' ';
	}
	return s;
}

const uint32_t memory_utils::get_function_size(void* fn_addr, void* stub_addr)
{
	return (uint32_t)stub_addr - (uint32_t)fn_addr;
}

void memory_utils::set_page_executable_privileges(void* fn, int fn_len)
{
	DWORD old_protect;
	VirtualProtect(fn, fn_len, PAGE_EXECUTE_READWRITE, &old_protect);
}

function_hook::function_hook(void* fn, void* stub, bytearray_t payload)
	: fn_handle(fn), original_src(0), payload_src(payload), 
	fn_size(memory_utils::get_function_size(fn, stub)), injected(false), is_page_executable(false)
{
	// making a separate copy of original source 
	// so it doesn't get overwritten when injecting
	original_src = new unsigned char[fn_size];
	std::memcpy(original_src, (bytearray_t)fn, fn_size);
}

void function_hook::inject()
{
	if (!is_page_executable)
	{
		memory_utils::set_page_executable_privileges(fn_handle, fn_size);
		is_page_executable = true;
	}

	if (!injected)
	{
		std::memcpy(fn_handle, payload_src, fn_size);
		injected = true;
	}
}

void function_hook::eject()
{
	if (injected)
	{
		std::memcpy(fn_handle, original_src, fn_size);
		injected = false;
	}
}

const std::string function_hook::dump_content() const
{
	return memory_utils::bytes_to_string((bytearray_t)fn_handle, fn_size);
}
