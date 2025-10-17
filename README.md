Это модификация линуксовой технологии петлевого диска (модуля ядра loop.c). Модуль позволяет загружаться с шифрованного раздела (для примера диск был зашифрован на маске 0xAA).
Все обращения к блочному устройству происходят через виртуальный диск.
```




                              обращение к вируальному диску (чтение)
                                        ||         /\
                                        ||         ||   
                                        ||         ||   <-------------- передаем приложению
                                        \/         ||
                                   +----------------------+
                                   |       loop disk      |  <------------ дешифруем их
                                   +----------------------+                                                            
                                        ||         /\              
                                        ||         ||     <-------- зашифрованные сектора
                                        \/         ||
                                   +----------------------+                   
                                   |   block device       |                    
                                   |   nvme0n1p3          | <----- шифрованный раздел
                                   |   system part        |                    
                                   +----------------------+ 



|------------------------------------------------------------------------------------------------------|

                              обращение к вируальному диску (запись)
         запрос                         ||         /\
        на запись       ------------->  ||         ||   
     + структура био                    ||         ||  
                                        \/         ||
                                   +----------------------+
парсим структуру био      ----->   |       loop disk      | 
шифруем каждый bio_vec             +----------------------+                                                            
м передаем                              ||         /\              
на оригинальное блочное                 ||         ||     
устройство                              \/         ||
                                   +----------------------+                   
                                   |   block device       |                    
                                   |   nvme0n1p3          | <----- шифрованный раздел
                                   |   system part        |                    
                                   +----------------------+             




```
Код написан в основном под версию 5.15.
Можно использовать и без шифрованного раздела, при первом чтениее 0-го сектора, если заголовок файловой системы ext4 будет не зашифрован, то будем использовать ключ 0x00 (то есть без шифрования).
```
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
	return is_encrypt;
}

из функции transfer_xor


if (cmd == READ)
	{
		in = raw_buf;
		out = loop_buf;

		if (real_block == 0 || !is_check_disk)
		{
			control_part_crypt.flag = check_encrypt_part(in, raw_off, size);
			if (control_part_crypt.flag != 0) {CIPHER_KEY = 0x00; LOG(KERN_INFO, "Disk not crypt!\n");}
			else {LOG(KERN_INFO, "Disk crypt!\n");}
		}
	}
```

Основная уязвимость безопасности данных -> писать в другое блочное устройсво. тк данные дешифруются и запишутся на другое устройство в не шифрованном виде.
По этому было принято решение заблокировать все блочные устройства в ядре.
Из-за того, что глобальные списки блочнных устройств и классов блочных устройств из ядра почему то не экспортируются в версии 5.15, было принято решение блокировать устройства брут форсом (перебором major, minor).
Есть белый список устройств, которые нельзя блокировать, это наши лупы и разделы на которые они накладываются и сам диск. С самого диска мы грузимся, если мы его заблокируем, то не сможем загрузится!!!
```
// БЛОКИРУЕМ СТАВИМ В RO ВСЕ БЛОЧНЫЕ УСТРОЙСТВА КОТОРЫЕ НЕ ВХОДЯТ В БЕЛЫЙ СПИСОК
void set_other_devices_readonly_whitelist(struct work_struct* work)
{
	//printk(KERN_INFO "Start kernel worker <lockdown blkdev>'\n");
	struct block_device *bdev;

	// БЕЛЫЙ СПИСОК: все устройства, которым РАЗРЕШЕНО оставаться R/W.
	const dev_t allow_list[] =
	{
		MKDEV(259, 3), // system_part (/dev/nvme0n1p3)
		MKDEV(259, 4), // swap_part (/dev/nvme0n1p4)

		MKDEV(7, 8),   // system_part_loop (/dev/loop_jokkeu1)
		MKDEV(7, 9),   // swap_part_loop (/dev/loop_jokkeu2)

		// ВАЖНО: Добавим сюда и сам корневой диск, чтобы утилиты
		// вроде fdisk -l могли читать с него таблицу разделов.
		MKDEV(259, 0)  // /dev/nvme0n1
	};


	int i;
	int major;
	int minor;

	for (major = 260; major > 0; --major)
	{

		if (major == 2) {continue;} // skip floppy device
		for (minor = 0; minor < 15; ++minor)
		{
			bdev = blkdev_get_by_dev(MKDEV(major, minor), FMODE_READ | FMODE_WRITE, NULL);
			if (IS_ERR(bdev))
			{
				continue;
			}
			bool is_allowed = false;
			struct gendisk* disk = bdev->bd_disk;

			if (!disk)
			{
				continue;
			}

			// 1. Проверяем, есть ли текущее устройство в нашем белом списке.
			for (i = 0; i < ARRAY_SIZE(allow_list); i++)
			{
				if (bdev->bd_dev == allow_list[i])
				{
					is_allowed = true;
					break;
				}
			}

			// 2. Если устройство в списке разрешённых, пропускаем его.
			if (is_allowed)
			{
				//printk(KERN_INFO "Whitelisted device %s (%d:%d), skipping.\n",
				//disk->disk_name, MAJOR(bdev->bd_dev), MINOR(bdev->bd_dev));
				put_disk(disk);
				continue;
			}

			// 3. Если мы здесь, значит устройства нет в списке. БЛОКИРУЕМ ЕГО.
			if (!get_disk_ro(disk))
			{
				//printk(KERN_WARNING "Locking non-whitelisted device %s (%d:%d) to read-only.\n",
				//disk->disk_name, MAJOR(bdev->bd_dev), MINOR(bdev->bd_dev));

				set_disk_ro(disk, 1);
			}

			put_disk(disk);
		}
	}

}

```

Также блокируем появление scsi дисков и usb. Перехватываем функции probe и ничего не делаем.
```
// Перехват SCSI DRIVE / USB_DRIVE

extern struct bus_type scsi_bus_type;
/////////////////////////////////////////////////////
static int (*original_sd_probe)(struct device* dev);
static int (*original_sd_remove)(struct device* dev);

static int sd_probe(struct device* dev);
static int sd_remove(struct device* dev);

/////////////////////////////////////////////////////
static int (*original_sr_probe)(struct device* dev);
static int (*original_sr_remove)(struct device* dev);

static int sr_probe(struct device* dev);
static int sr_remove(struct device* dev);
/////////////////////////////////////////////////////

void notifier_init(struct work_struct* work)
{
	printk(KERN_INFO "\n");
	bool flag = false;
	while(!flag)
	{
		struct device_driver* sd_driver = NULL;
		sd_driver = driver_find("sd", &scsi_bus_type);
		if (sd_driver)
		{
			printk(KERN_INFO "sd driver find\n");
			original_sd_probe = sd_driver->probe;
			original_sd_remove = sd_driver->remove;

			sd_driver->probe = sd_probe;
			sd_driver->remove = sd_remove;
			flag = true;
		}


		struct device_driver* sr_driver = NULL;
		sr_driver = driver_find("sr", &scsi_bus_type);
		if (sr_driver)
		{
			printk(KERN_INFO "sr driver find\n");
			original_sr_probe = sr_driver->probe;
			original_sr_remove = sr_driver->remove;

			sr_driver->probe = sr_probe;
			sr_driver->remove = sr_remove;
			flag = true;
		}
		msleep(100);
	}

}


int sd_probe(struct device* dev)
{

	return 0;
}
int sd_remove(struct device* dev)
{

	return 0;
}
int sr_probe(struct device* dev)
{

	return 0;
}
int sr_remove(struct device* dev)
{

	return 0;
}
```

В этой версии будет работать только на таком расположении разделов nvme диска
```
nvme0n1     259:0    0 ...  0 disk 
├─nvme0n1p1 259:1    0 ...  0 part /boot/efi
├─nvme0n1p2 259:2    0 ...  0 part /boot                        
|─nvme0n1p3 259:3    0 ...  0 part /
|─nvme0n1p3 259:4    0 ...  0 part [swap]
```
Установка.
```
git clone https://github.com/JOKKEU/modified_loop
```
переходим в папку с проектом и выполняем make
```
make
```
перемещаем main_loop.ko
```
sudo cp main_loop.ko /lib/modules/$(uname -r)
```
далее модифицируем initramfs
файл /etc/initramfs-tools/modules
добавляем в конец main_loop.
<img width="895" height="307" alt="image" src="https://github.com/user-attachments/assets/83906065-81b7-491d-900a-d98c4e732103" />
далее модифицираем /etc/fstab
<img width="1219" height="379" alt="image" src="https://github.com/user-attachments/assets/24e7df7b-e090-4a01-a0a5-c75638191a15" />
затем обновляем зависимости модулей 
```
sudo depmod -a
```
и обновляем файловую систему initramfs
```
sudo update-initramfs -uk $(uname -r)
```
Всё готово!!!
Я за шифровал раздел swap и root из ефи среды.
проверяем первый раздел.
<img width="854" height="637" alt="image" src="https://github.com/user-attachments/assets/ba013626-9707-4286-8f61-ccfeaf75aa18" />

видим что таблица файловой системы зашифрованна, значит будем использовать ключ 0xAA.
Запускаемся.
проверяем
<img width="606" height="279" alt="image" src="https://github.com/user-attachments/assets/167f6e03-c635-4cf7-89ec-69845664133b" />

и смотрим dmesg.
<img width="1058" height="782" alt="image" src="https://github.com/user-attachments/assets/56fabfec-b800-4af8-a311-15f910ab3701" />











