#pragma once
#include <Windows.h>
#include <string>
#include <vector>

using memaddr_t = unsigned long;
using bytearray_t = unsigned char*;

#define MEMADDR(fnptr) ((memaddr_t)&fnptr)

class memory_utils
{
public:
	static const std::string bytes_to_string(bytearray_t data, int len);
	static const uint32_t get_function_size(void* fn_addr, void* stub_addr);
	static void set_page_executable_privileges(void* fn, int fn_len);
};

class function_hook
{
public:
	function_hook(void* fn, void* stub, bytearray_t payload);

	const bool		is_payload_injected()	const { return injected; }
	const uint32_t	get_function_size()		const { return fn_size; }

	void inject();
	void eject();

	template<typename... Args>
	std::int32_t call(Args... args)
	{
		return reinterpret_cast<std::int32_t(*)(Args...)>(fn_handle)(args...);
	}

	const std::string dump_content() const;

private:
	void*		fn_handle;
	bytearray_t original_src;
	bytearray_t payload_src;
	uint32_t	fn_size;

private:
	bool		is_page_executable;
	bool		injected;
};

class function_crypt
{
public:
	function_crypt(void* fn, void* stub);

	void encrypt(DWORD key);
	void decrypt(DWORD key);

	const uint32_t	get_function_size()		const { return fn_size; }

	template<typename... Args>
	std::int32_t call(Args... args)
	{
		return reinterpret_cast<std::int32_t(*)(Args...)>(fn_handle)(args...);
	}

private:
	void* fn_handle;
	uint32_t	fn_size;
};
