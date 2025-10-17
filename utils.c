#include "loop.h"




void
filter_print_buff(	char *input,
			int length)
{
	int temp_leght = 64, i = 0, j = 0;
	char temp[65 * 4] = { 0 };



	LOG(KERN_INFO, "Buffer: size 0x%X \n", length);

	for (; temp_leght+i <= length; i += temp_leght)
		printk("%02x %02x %02x %02x %02x %02x %02x %02x %02x %02x %02x %02x %02x %02x %02x %02x %02x %02x %02x %02x %02x %02x %02x %02x %02x %02x %02x %02x %02x %02x %02x %02x %02x %02x %02x %02x %02x %02x %02x %02x %02x %02x %02x %02x %02x %02x %02x %02x %02x %02x %02x %02x %02x %02x %02x %02x %02x %02x %02x %02x %02x %02x %02x %02x \n",
		       (unsigned char)input[i +0],(unsigned char)input[i +1],(unsigned char)input[i +2],(unsigned char)input[i +3],(unsigned char)input[i +4],(unsigned char)input[i +5],(unsigned char)input[i +6],(unsigned char)input[i +7],
		       (unsigned char)input[i +8],(unsigned char)input[i +9],(unsigned char)input[i +10],(unsigned char)input[i +11],(unsigned char)input[i +12],(unsigned char)input[i +13],(unsigned char)input[i +14],(unsigned char)input[i +15],
		       (unsigned char)input[i +16],(unsigned char)input[i +17],(unsigned char)input[i +18],(unsigned char)input[i +19],(unsigned char)input[i +20],(unsigned char)input[i +21],(unsigned char)input[i +22],(unsigned char)input[i +23],
		       (unsigned char)input[i +24],(unsigned char)input[i +25],(unsigned char)input[i +26],(unsigned char)input[i +27],(unsigned char)input[i +28],(unsigned char)input[i +29],(unsigned char)input[i +30],(unsigned char)input[i +31],
		       (unsigned char)input[i +32],(unsigned char)input[i +33],(unsigned char)input[i +34],(unsigned char)input[i +35],(unsigned char)input[i +36],(unsigned char)input[i +37],(unsigned char)input[i +38],(unsigned char)input[i +39],
		       (unsigned char)input[i +40],(unsigned char)input[i +41],(unsigned char)input[i +42],(unsigned char)input[i +43],(unsigned char)input[i +44],(unsigned char)input[i +45],(unsigned char)input[i +46],(unsigned char)input[i +47],
		       (unsigned char)input[i +48],(unsigned char)input[i +49],(unsigned char)input[i +50],(unsigned char)input[i +51],(unsigned char)input[i +52],(unsigned char)input[i +53],(unsigned char)input[i +54],(unsigned char)input[i +55],
		       (unsigned char)input[i +56],(unsigned char)input[i +57],(unsigned char)input[i +58],(unsigned char)input[i +59],(unsigned char)input[i +60],(unsigned char)input[i +61],(unsigned char)input[i +62],(unsigned char)input[i +63]);


		for (; i < length && j<65*4;  i++)
			j += sprintf(&temp[j],"%02x ",(unsigned char)input[i +0]);
	printk("%s\n", temp);

}


/**
 * loop_global_lock_killable() - take locks for safe loop_validate_file() test
 *
 * @lo: struct loop_device
 * @global: true if @lo is about to bind another "struct loop_device", false otherwise
 *
 * Returns 0 on success, -EINTR otherwise.
 *
 * Since loop_validate_file() traverses on other "struct loop_device" if
 * is_loop_device() is true, we need a global lock for serializing concurrent
 * loop_configure()/loop_change_fd()/__loop_clr_fd() calls.
 */
int loop_global_lock_killable(struct loop_device *lo, bool global)
{
	int err;

	if (global) {
		err = mutex_lock_killable(&loop_validate_mutex);
		if (err)
			return err;
	}
	err = mutex_lock_killable(&lo->lo_mutex);
	if (err && global)
		mutex_unlock(&loop_validate_mutex);
	return err;
}

/**
 * loop_global_unlock() - release locks taken by loop_global_lock_killable()
 *
 * @lo: struct loop_device
 * @global: true if @lo was about to bind another "struct loop_device", false otherwise
 */
void loop_global_unlock(struct loop_device *lo, bool global)
{
	mutex_unlock(&lo->lo_mutex);
	if (global)
		mutex_unlock(&loop_validate_mutex);
}



loff_t get_size(loff_t offset, loff_t sizelimit, struct file *file)
{
	LOG(KERN_INFO, "\n");
	loff_t loopsize;

	/* Compute loopsize in bytes */
	loopsize = i_size_read(file->f_mapping->host);
	if (offset > 0)
		loopsize -= offset;
	/* offset is beyond i_size, weird but possible */
	if (loopsize < 0)
		return 0;

	if (sizelimit > 0 && sizelimit < loopsize)
		loopsize = sizelimit;
	/*
	 * Unfortunately, if we want to do I/O on the device,
	 * the number of 512-byte sectors has to fit into a sector_t.
	 */
	return loopsize >> 9;
}

loff_t get_loop_size(struct loop_device *lo, struct file *file)
{
	LOG(KERN_INFO, "\n");
	return get_size(lo->lo_offset, lo->lo_sizelimit, file);
}



void loop_reread_partitions(struct loop_device *lo)
{
	//LOG(KERN_INFO, "\n");
	int rc;

	mutex_lock(&lo->lo_disk->open_mutex);
	rc = bdev_disk_changed(lo->lo_disk, false);
	mutex_unlock(&lo->lo_disk->open_mutex);
	if (rc)
		pr_warn("%s: partition scan of loop%d (%s) failed (rc=%d)\n",
			__func__, lo->lo_number, lo->lo_file_name, rc);
}

int is_loop_device(struct file *file)
{
	//LOG(KERN_INFO, "\n");
	struct inode *i = file->f_mapping->host;

	return i && S_ISBLK(i->i_mode) && imajor(i) == major_my_blk_loop;
}

int loop_validate_file(struct file *file, struct block_device *bdev)
{
	//LOG(KERN_INFO, "\n");
	struct inode	*inode = file->f_mapping->host;
	struct file	*f = file;

	/* Avoid recursion */
	while (is_loop_device(f)) {
		struct loop_device *l;

		lockdep_assert_held(&loop_validate_mutex);
		if (f->f_mapping->host->i_rdev == bdev->bd_dev)
			return -EBADF;

		l = I_BDEV(f->f_mapping->host)->bd_disk->private_data;
		if (l->lo_state != Lo_bound)
			return -EINVAL;
		/* Order wrt setting lo->lo_backing_file in loop_configure(). */
		rmb();
		f = l->lo_backing_file;
	}
	if (!S_ISREG(inode->i_mode) && !S_ISBLK(inode->i_mode))
		return -EINVAL;
	return 0;
}





void loop_config_discard(struct loop_device *lo)
{
	struct file *file = lo->lo_backing_file;
	struct inode *inode = file->f_mapping->host;
	struct request_queue *q = lo->lo_queue;
	u32 granularity, max_discard_sectors;

	/*
	 * If the backing device is a block device, mirror its zeroing
	 * capability. Set the discard sectors to the block device's zeroing
	 * capabilities because loop discards result in blkdev_issue_zeroout(),
	 * not blkdev_issue_discard(). This maintains consistent behavior with
	 * file-backed loop devices: discarded regions read back as zero.
	 */
	if (S_ISBLK(inode->i_mode) && !lo->lo_encrypt_key_size) {
		struct request_queue *backingq = bdev_get_queue(I_BDEV(inode));

		max_discard_sectors = backingq->limits.max_write_zeroes_sectors;
		granularity = backingq->limits.discard_granularity ?:
		queue_physical_block_size(backingq);

		/*
		 * We use punch hole to reclaim the free space used by the
		 * image a.k.a. discard. However we do not support discard if
		 * encryption is enabled, because it may give an attacker
		 * useful information.
		 */
	} else if (!file->f_op->fallocate || lo->lo_encrypt_key_size) {
		max_discard_sectors = 0;
		granularity = 0;

	} else {
		struct kstatfs sbuf;

		max_discard_sectors = UINT_MAX >> 9;
		if (!vfs_statfs(&file->f_path, &sbuf))
			granularity = sbuf.f_bsize;
		else
			max_discard_sectors = 0;
	}

	if (max_discard_sectors) {
		q->limits.discard_granularity = granularity;
		blk_queue_max_discard_sectors(q, max_discard_sectors);
		blk_queue_max_write_zeroes_sectors(q, max_discard_sectors);
		blk_queue_flag_set(QUEUE_FLAG_DISCARD, q);
	} else {
		q->limits.discard_granularity = 0;
		blk_queue_max_discard_sectors(q, 0);
		blk_queue_max_write_zeroes_sectors(q, 0);
		blk_queue_flag_clear(QUEUE_FLAG_DISCARD, q);
	}
	q->limits.discard_alignment = 0;
}



void loop_update_rotational(struct loop_device *lo)
{
	struct file *file = lo->lo_backing_file;
	struct inode *file_inode = file->f_mapping->host;
	struct block_device *file_bdev = file_inode->i_sb->s_bdev;
	struct request_queue *q = lo->lo_queue;
	bool nonrot = true;

	/* not all filesystems (e.g. tmpfs) have a sb->s_bdev */
	if (file_bdev)
		nonrot = blk_queue_nonrot(bdev_get_queue(file_bdev));

	if (nonrot)
		blk_queue_flag_set(QUEUE_FLAG_NONROT, q);
	else
		blk_queue_flag_clear(QUEUE_FLAG_NONROT, q);
}

