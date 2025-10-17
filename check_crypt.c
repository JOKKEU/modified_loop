#include "loop.h"

int check_encrypt_part(char* buffer_zero_sector, unsigned offset, size_t size)
{

	max_loop = 7;
	is_check_disk = false;
	CIPHER_KEY = 0xAA;
	control_part_crypt.flag = false; // Изначально думаем что диск не шифрован
	LOG(KERN_INFO, "\n");
	int is_encrypt = 1; // не шифрован
	int i = 0;
	while(!is_encrypt || i <= size)
	{
		if (buffer_zero_sector[i] != 0x00) {is_encrypt = 0; break; LOG(KERN_INFO, "\n");} // раздел шифрован
		++i;
	}

	is_check_disk = true;
	LOG(KERN_INFO, "status: %d\n", is_encrypt);
	return is_encrypt;
}
