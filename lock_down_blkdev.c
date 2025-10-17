#include "loop.h"

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
	//printk(KERN_INFO "Activating whitelist lockdown mode...\n");

	//spin_lock(&bdev_lock);

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

	//spin_unlock(&bdev_lock);

	//printk(KERN_INFO "Lockdown complete.\n");

}


