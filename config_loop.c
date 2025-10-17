#include "loop.h"


int loop_configure(struct loop_device *lo, fmode_t mode,  struct block_device *bdev, struct file* file, const struct loop_config *config)
{
	LOG(KERN_INFO, "loop_configure\n");
	LOG(KERN_INFO, "bdev->bd_disk->disk_name: %s\n", bdev->bd_disk->disk_name);
	struct inode *inode;
	struct address_space *mapping;
	int error;
	loff_t size;
	bool partscan;
	unsigned short bsize;
	bool is_loop;

	if (!file)
		return -EBADF;
	is_loop = is_loop_device(file);

	/* This is safe, since we have a reference from open(). */
	__module_get(THIS_MODULE);

	/*
	 * If we don't hold exclusive handle for the device, upgrade to it
	 * here to avoid changing device under exclusive owner.
	 */
	if (!(mode & FMODE_EXCL)) {
		error = bd_prepare_to_claim(bdev, loop_configure);
		if (error)
		{
			goto out_putf;
		}

	}

	error = loop_global_lock_killable(lo, is_loop);
	if (error)
	{
		goto out_bdev;
	}

	error = -EBUSY;
	if (lo->lo_state != Lo_unbound)
		goto out_unlock;

	error = loop_validate_file(file, bdev);
	if (error)
		goto out_unlock;

	mapping = file->f_mapping;
	inode = mapping->host;

	if ((config->info.lo_flags & ~LOOP_CONFIGURE_SETTABLE_FLAGS) != 0) {
		error = -EINVAL;
		goto out_unlock;
	}

	if (config->block_size) {
		error = blk_validate_block_size(config->block_size);
		if (error)
			goto out_unlock;
	}

	error = loop_set_status_from_info(lo, &config->info);
	if (error)
		goto out_unlock;


	if (!(file->f_mode & FMODE_WRITE) || !(mode & FMODE_WRITE) ||
		!file->f_op->write_iter)
		lo->lo_flags |= LO_FLAGS_READ_ONLY;

	lo->workqueue = alloc_workqueue("loop_jokkeu%d",
					WQ_UNBOUND | WQ_FREEZABLE,
				 0,
				 lo->lo_number);
	if (!lo->workqueue) {
		error = -ENOMEM;
		goto out_unlock;
	}

	disk_force_media_change(lo->lo_disk, DISK_EVENT_MEDIA_CHANGE);
	set_disk_ro(lo->lo_disk, (lo->lo_flags & LO_FLAGS_READ_ONLY) != 0);

	INIT_WORK(&lo->rootcg_work, loop_rootcg_workfn);
	INIT_LIST_HEAD(&lo->rootcg_cmd_list);
	INIT_LIST_HEAD(&lo->idle_worker_list);
	lo->worker_tree = RB_ROOT;
	timer_setup(&lo->timer, loop_free_idle_workers,
		    TIMER_DEFERRABLE);
	lo->use_dio = lo->lo_flags & LO_FLAGS_DIRECT_IO;
	lo->lo_device = bdev;
	lo->lo_backing_file = file;
	lo->old_gfp_mask = mapping_gfp_mask(mapping);
	mapping_set_gfp_mask(mapping, lo->old_gfp_mask & ~(__GFP_IO|__GFP_FS));

	if (!(lo->lo_flags & LO_FLAGS_READ_ONLY) && file->f_op->fsync)
		blk_queue_write_cache(lo->lo_queue, true, false);

	if (config->block_size)
		bsize = config->block_size;
	else if ((lo->lo_backing_file->f_flags & O_DIRECT) && inode->i_sb->s_bdev)
		/* In case of direct I/O, match underlying block size */
		bsize = bdev_logical_block_size(inode->i_sb->s_bdev);
	else
		bsize = 512;

	blk_queue_logical_block_size(lo->lo_queue, bsize);
	blk_queue_physical_block_size(lo->lo_queue, bsize);
	blk_queue_io_min(lo->lo_queue, bsize);

	loop_config_discard(lo);
	loop_update_rotational(lo);
	loop_update_dio(lo);
	loop_sysfs_init(lo);

	size = get_loop_size(lo, file);
	loop_set_size(lo, size);

	/* Order wrt reading lo_state in loop_validate_file(). */
	wmb();

	lo->lo_state = Lo_bound;
	if (part_shift)
		lo->lo_flags |= LO_FLAGS_PARTSCAN;
	partscan = lo->lo_flags & LO_FLAGS_PARTSCAN;
	if (partscan)
		lo->lo_disk->flags &= ~GENHD_FL_NO_PART_SCAN;

	loop_global_unlock(lo, is_loop);
	if (partscan)
		loop_reread_partitions(lo);
	if (!(mode & FMODE_EXCL))
		bd_abort_claiming(bdev, loop_configure);
	return 0;

	out_unlock:
	loop_global_unlock(lo, is_loop);
	out_bdev:
	if (!(mode & FMODE_EXCL))
		bd_abort_claiming(bdev, loop_configure);
	out_putf:
	fput(file);
	/* This is safe: open() is still holding a reference. */
	module_put(THIS_MODULE);
	return error;
}

int __loop_clr_fd(struct loop_device *lo, bool release)
{
	LOG(KERN_INFO, "\n");
	struct file *filp = NULL;
	gfp_t gfp = lo->old_gfp_mask;
	struct block_device *bdev = lo->lo_device;
	int err = 0;
	bool partscan = false;
	int lo_number;
	struct loop_worker *pos, *worker;

	/*
	 * Flush loop_configure() and loop_change_fd(). It is acceptable for
	 * loop_validate_file() to succeed, for actual clear operation has not
	 * started yet.
	 */
	mutex_lock(&loop_validate_mutex);
	mutex_unlock(&loop_validate_mutex);
	/*
	 * loop_validate_file() now fails because l->lo_state != Lo_bound
	 * became visible.
	 */

	mutex_lock(&lo->lo_mutex);
	if (WARN_ON_ONCE(lo->lo_state != Lo_rundown)) {
		err = -ENXIO;
		goto out_unlock;
	}

	filp = lo->lo_backing_file;
	if (filp == NULL) {
		err = -EINVAL;
		goto out_unlock;
	}

	if (test_bit(QUEUE_FLAG_WC, &lo->lo_queue->queue_flags))
		blk_queue_write_cache(lo->lo_queue, false, false);

	/* freeze request queue during the transition */
	blk_mq_freeze_queue(lo->lo_queue);

	destroy_workqueue(lo->workqueue);
	spin_lock_irq(&lo->lo_work_lock);
	list_for_each_entry_safe(worker, pos, &lo->idle_worker_list,
				 idle_list) {
		list_del(&worker->idle_list);
		rb_erase(&worker->rb_node, &lo->worker_tree);
		css_put(worker->blkcg_css);
		kfree(worker);
				 }
				 spin_unlock_irq(&lo->lo_work_lock);
				 del_timer_sync(&lo->timer);

				 spin_lock_irq(&lo->lo_lock);
				 lo->lo_backing_file = NULL;
				 spin_unlock_irq(&lo->lo_lock);

				 loop_release_xfer(lo);
				 lo->transfer = NULL;
				 lo->ioctl = NULL;
				 lo->lo_device = NULL;
				 lo->lo_encryption = NULL;
				 lo->lo_offset = 0;
				 lo->lo_sizelimit = 0;
				 lo->lo_encrypt_key_size = 0;
				 memset(lo->lo_encrypt_key, 0, LO_KEY_SIZE);
				 memset(lo->lo_crypt_name, 0, LO_NAME_SIZE);
				 memset(lo->lo_file_name, 0, LO_NAME_SIZE);
				 blk_queue_logical_block_size(lo->lo_queue, 512);
				 blk_queue_physical_block_size(lo->lo_queue, 512);
				 blk_queue_io_min(lo->lo_queue, 512);
				 if (bdev) {
					 invalidate_bdev(bdev);
					 bdev->bd_inode->i_mapping->wb_err = 0;
				 }
				 set_capacity(lo->lo_disk, 0);
				 loop_sysfs_exit(lo);
				 if (bdev) {
					 /* let user-space know about this change */
					 kobject_uevent(&disk_to_dev(bdev->bd_disk)->kobj, KOBJ_CHANGE);
				 }
				 mapping_set_gfp_mask(filp->f_mapping, gfp);
				 /* This is safe: open() is still holding a reference. */
				 module_put(THIS_MODULE);
				 blk_mq_unfreeze_queue(lo->lo_queue);

				 partscan = lo->lo_flags & LO_FLAGS_PARTSCAN && bdev;
				 lo_number = lo->lo_number;
				 disk_force_media_change(lo->lo_disk, DISK_EVENT_MEDIA_CHANGE);
				 out_unlock:
				 mutex_unlock(&lo->lo_mutex);
				 if (partscan) {
					 /*
					  * open_mutex has been held already in release path, so don't
					  * acquire it if this function is called in such case.
					  *
					  * If the reread partition isn't from release path, lo_refcnt
					  * must be at least one and it can only become zero when the
					  * current holder is released.
					  */
					 if (!release)
						 mutex_lock(&lo->lo_disk->open_mutex);
					 err = bdev_disk_changed(lo->lo_disk, false);
					 if (!release)
						 mutex_unlock(&lo->lo_disk->open_mutex);
					 if (err)
						 pr_warn("%s: partition scan of loop%d failed (rc=%d)\n",
							 __func__, lo_number, err);
						 /* Device is gone, no point in returning error */
						 err = 0;
				 }

				 /*
				  * lo->lo_state is set to Lo_unbound here after above partscan has
				  * finished.
				  *
				  * There cannot be anybody else entering __loop_clr_fd() as
				  * lo->lo_backing_file is already cleared and Lo_rundown state
				  * protects us from all the other places trying to change the 'lo'
				  * device.
				  */
				 mutex_lock(&lo->lo_mutex);
				 lo->lo_flags = 0;
				 if (!part_shift)
					 lo->lo_disk->flags |= GENHD_FL_NO_PART_SCAN;
	lo->lo_state = Lo_unbound;
	mutex_unlock(&lo->lo_mutex);

	/*
	 * Need not hold lo_mutex to fput backing file. Calling fput holding
	 * lo_mutex triggers a circular lock dependency possibility warning as
	 * fput can take open_mutex which is usually taken before lo_mutex.
	 */
	if (filp)
		fput(filp);
	return err;
}

int loop_clr_fd(struct loop_device *lo)
{
	LOG(KERN_INFO, "\n");
	int err;

	err = mutex_lock_killable(&lo->lo_mutex);
	if (err)
		return err;
	if (lo->lo_state != Lo_bound) {
		mutex_unlock(&lo->lo_mutex);
		return -ENXIO;
	}
	/*
	 * If we've explicitly asked to tear down the loop device,
	 * and it has an elevated reference count, set it for auto-teardown when
	 * the last reference goes away. This stops $!~#$@ udev from
	 * preventing teardown because it decided that it needs to run blkid on
	 * the loopback device whenever they appear. xfstests is notorious for
	 * failing tests because blkid via udev races with a losetup
	 * <dev>/do something like mkfs/losetup -d <dev> causing the losetup -d
	 * command to fail with EBUSY.
	 */
	if (atomic_read(&lo->lo_refcnt) > 1) {
		lo->lo_flags |= LO_FLAGS_AUTOCLEAR;
		mutex_unlock(&lo->lo_mutex);
		return 0;
	}
	lo->lo_state = Lo_rundown;
	mutex_unlock(&lo->lo_mutex);

	return __loop_clr_fd(lo, false);
}
