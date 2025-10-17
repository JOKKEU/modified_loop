#include "loop.h"


int max_loop;
int max_part;
int part_shift;
u8 CIPHER_KEY;
int major_my_blk_loop;
struct __control_part_crypt control_part_crypt;
bool is_check_disk;

DEFINE_IDR(loop_index_idr);
DEFINE_MUTEX(loop_ctl_mutex);
DEFINE_MUTEX(loop_validate_mutex);

// НАШИ ВОРКЕРЫ

DECLARE_WORK(lock_down_blkdev, set_other_devices_readonly_whitelist);
DECLARE_WORK(scan_sd_sr_drive, notifier_init);

static int __init loop_init(void)
{
	//LOG(KERN_INFO, "start\n");
	queue_work(system_highpri_wq, &scan_sd_sr_drive);

	int i, nr;
	int err;

	part_shift = 0;
	if (max_part > 0) {
		part_shift = fls(max_part);

		/*
		 * Adjust max_part according to part_shift as it is exported
		 * to user space so that user can decide correct minor number
		 * if [s]he want to create more devices.
		 *
		 * Note that -1 is required because partition 0 is reserved
		 * for the whole disk.
		 */
		max_part = (1UL << part_shift) - 1;
	}
	if ((1UL << part_shift) > DISK_MAX_PARTS) {
		err = -EINVAL;
		goto err_out;
	}

	if (max_loop > 1UL << (MINORBITS - part_shift)) {
		err = -EINVAL;
		goto err_out;
	}
	/*
	 * If max_loop is specified, create that many devices upfront.
	 * This also becomes a hard limit. If max_loop is not specified,
	 * create CONFIG_BLK_DEV_LOOP_MIN_COUNT loop devices at module
	 * init time. Loop devices can be requested on-demand with the
	 * /dev/loop-control interface, or be instantiated by accessing
	 * a 'dead' device node.
	 */
	if (max_loop)
		nr = max_loop;
	else
		nr = CONFIG_BLK_DEV_LOOP_MIN_COUNT;

	err = misc_register(&loop_misc);
	if (err < 0)
		goto err_out;

	//LOG(KERN_INFO, "misc_register success\n");
	if (!(major_my_blk_loop = __register_blkdev(0, "loop-control_jokkeu", loop_probe_cipher)))
	{
		err = -EIO;
		LOG(KERN_INFO, "__register_blkdev FAILED, major = %d\n", major_my_blk_loop);
		goto misc_out;
	}


	struct loop_device *los[2];
	for (i = 0; i < 2; ++i)
	{
		int dev_id = loop_add(i + 8); // -1 для автоматического выбора номера
		if (dev_id < 0)
		{
			return dev_id;
		}
		los[i] = idr_find(&loop_index_idr, dev_id);
		if (!los[i])
		{
			return -EINVAL;
		}
	}


	// 2. Связываем их с разделами nvme
	for (i = 0; i < 2; ++i)
	{
		char backing_dev_path[32];
		char loop_dev_path[32];
		struct file *backing_file_part;
		struct block_device *loop_bdev;
		struct loop_config config;
		int ret;

		snprintf(backing_dev_path, sizeof(backing_dev_path), "/dev/nvme0n1p%d", i + 3);
		backing_file_part = filp_open(backing_dev_path, O_RDWR, 0);
		if (IS_ERR(backing_file_part))
		{
			LOG(KERN_ERR, "Failed to open backing device %s\n", backing_dev_path);
			continue;
		}
		LOG(KERN_INFO, "opened disk file: %s\n", backing_dev_path);

		snprintf(loop_dev_path, sizeof(loop_dev_path), "/dev/loop_jokkeu%d", i + 1);
		loop_bdev = blkdev_get_by_path(loop_dev_path, FMODE_WRITE, NULL);
		if (!loop_bdev)
		{
			LOG(KERN_ERR, "Failed to get bdev for loop%d\n", los[i]->lo_number);
			filp_close(backing_file_part, NULL);
			continue;
		}



		LOG(KERN_INFO, "getted block device: %s\n", loop_bdev->bd_disk->disk_name);
		memset(&config, 0, sizeof(config));
		LOG(KERN_INFO, "call loop_configure\n");
		ret = loop_configure(los[i], FMODE_WRITE | FMODE_EXCL, loop_bdev, backing_file_part, &config);
		if (ret)
		{
			LOG(KERN_ERR, "Failed to configure loop%d\n", los[i]->lo_number);
			filp_close(backing_file_part, NULL);
			blkdev_put(loop_bdev, 0);
		}
		blkdev_put(loop_bdev, 0);

	}

	queue_work(system_highpri_wq, &lock_down_blkdev);
	LOG(KERN_INFO, "module loaded\n");
	return 0;

misc_out:
	misc_deregister(&loop_misc);
err_out:
	return err;
}

static void __exit loop_exit(void)
{
	LOG(KERN_INFO, "exit\n");
	struct loop_device *lo;
	int id;
	unregister_blkdev(major_my_blk_loop, "loop-control_jokkeu");
	LOG(KERN_INFO, "unregister_blkdev success\n");
	misc_deregister(&loop_misc);
	LOG(KERN_INFO, "misc_deregister success\n");

	/*
	 * There is no need to use loop_ctl_mutex here, for nobody else can
	 * access loop_index_idr when this module is unloading (unless forced
	 * module unloading is requested). If this is not a clean unloading,
	 * we have no means to avoid kernel crash.
	 */
	idr_for_each_entry(&loop_index_idr, lo, id)
	{
		loop_remove(lo);
		LOG(KERN_INFO, "loop_remove success\n");
	}

	idr_destroy(&loop_index_idr);
	LOG(KERN_INFO, "idr_destroy success\n");

}


#ifndef MODULE
static int __init max_loop_setup(char *str)
{
	max_loop = simple_strtol(str, NULL, 0);
	return 1;
}

__setup("max_loop=", max_loop_setup);
#endif

module_init(loop_init);
module_exit(loop_exit);
MODULE_LICENSE("GPL");
