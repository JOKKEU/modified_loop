#include "loop.h"

int check_encrypt_part(char* buffer_zero_sector, unsigned offset, size_t size)
{
	int is_encrypt = 1; // не шифрован
	int i = 0;
	while(!is_encrypt || i <= size)
	{
		if (buffer_zero_sector[i] != 0x00) {is_encrypt = 0; break;} // раздел шифрован
		++i;
	}

	is_check_disk = true;
	LOG(KERN_INFO, "status: %d\n", is_encrypt);
	return is_encrypt;
}
