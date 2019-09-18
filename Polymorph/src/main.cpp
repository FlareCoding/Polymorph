#include <iostream>
using std::cout;
using std::cin;

#include "Memory.h"

constexpr DWORD ENCRYPTION_KEY = 0x5B;

int addition_func_to_override(int x, int y)
{
	return x + y;
}

void stub_fn() {}

int main()
{
	cout << "\n[+] Witness Polymorph [+]\n\n";

	std::vector<unsigned char> payload =
	{
		0x55,				// push ebp
		0x89, 0xE5,			// mov ebp, esp
		0x8B, 0x45, 0x08,	// mov eax, DWORD PTR [ebp + 0x8] 
		0x2B, 0x45, 0x0C,	// sub eax, DWORD PTR [ebp + 0xC]
		0x5D,				// pop ebp
		0xC3,				// ret
		0xCC, 
		0xCC, 
		0xCC, 
		0xCC, 
		0xCC
	};

	function_hook hook(addition_func_to_override, stub_fn, payload.data());
	cout << "Hook Content Before Injecting:\n" << hook.dump_content() << "\n\n";

	// Calling the original function
	int result = hook.call<int, int>(12, 5);
	cout << "Arguments: 12, 5 \nResult: " << result << "\n\n";

	// Injecting payload
	hook.inject();
	cout << "Hook Content After Injecting:\n" << hook.dump_content() << "\n\n";

	// Calling the modified function code
	result = hook.call<int, int>(12, 5);
	cout << "Arguments: 12, 5 \nResult: " << result << "\n\n";

	// Ejecting payload
	hook.eject();
	cout << "Hook Content After Ejecting:\n" << hook.dump_content() << "\n\n";

	// Calling the restored function code
	result = hook.call<int, int>(12, 5);
	cout << "Arguments: 12, 5 \nResult: " << result << "\n\n";

	//===================================================================================//
	//===================================================================================//

	function_crypt crypt(addition_func_to_override, stub_fn);
	cout << "\n======= Demonstrating Function Encryption =======\n\n";
	cout << "Calling Original Unencrypted Function\n12 + 5 = " << crypt.call<int, int>(12, 5) << "\n";
	cout << "Original Unencrypted Function Content:\n" << memory_utils::bytes_to_string((bytearray_t)addition_func_to_override, crypt.get_function_size()) << "\n\n";

	crypt.encrypt(ENCRYPTION_KEY);
	cout << "Calling Function After Encryption . . .\n12 + 5 = [spoiler alert... function won't work and program will crash]\n";
	cout << "Encrypted Function Content:\n" << memory_utils::bytes_to_string((bytearray_t)addition_func_to_override, crypt.get_function_size()) << "\n\n";

	cout << "Decrypting the function back...\n\n";

	crypt.decrypt(ENCRYPTION_KEY);
	cout << "Calling Function After Decrypting\n12 + 5 = " << crypt.call<int, int>(12, 5) << "\n";
	cout << "Decrypted Function Content:\n" << memory_utils::bytes_to_string((bytearray_t)addition_func_to_override, crypt.get_function_size()) << "\n\n";

	cout << "\n";
	return 0;
}
