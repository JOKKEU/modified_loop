#include "loop.h"

int lo_simple_ioctl(struct loop_device *lo, unsigned int cmd,
			   unsigned long arg)
{
	//LOG(KERN_INFO, "cmd: %u, arg: %llu\n", cmd, arg);
	int err;

	err = mutex_lock_killable(&lo->lo_mutex);
	if (err)
		return err;
	switch (cmd) {
		case LOOP_SET_CAPACITY:
			err = loop_set_capacity(lo);
			break;
		case LOOP_SET_DIRECT_IO:
			err = loop_set_dio(lo, arg);
			break;
		case LOOP_SET_BLOCK_SIZE:
			err = loop_set_block_size(lo, arg);
			break;
		default:
			err = lo->ioctl ? lo->ioctl(lo, cmd, arg) : -EINVAL;
	}
	mutex_unlock(&lo->lo_mutex);
	return err;
}

int lo_ioctl(struct block_device *bdev, fmode_t mode,
		    unsigned int cmd, unsigned long arg)
{
	//LOG(KERN_INFO, "mode: %d, cmd: %u, arg: %llu\n", mode, cmd, arg);
	struct loop_device *lo = bdev->bd_disk->private_data;



	void __user *argp = (void __user *) arg;
	int err;

	switch (cmd) {
		case LOOP_SET_FD: {
			/*
			 * Legacy case - pass in a zeroed out struct loop_config with
			 * only the file descriptor set , which corresponds with the
			 * default parameters we'd have used otherwise.
			 */
			struct loop_config config;

			memset(&config, 0, sizeof(config));
			config.fd = arg;
			//LOG(KERN_INFO, "LOOP_SET_FD\n");
			return loop_configure(lo, mode, bdev, NULL, &config);
		}
		case LOOP_CONFIGURE: {
			struct loop_config config;

			if (copy_from_user(&config, argp, sizeof(config)))
				return -EFAULT;

			//LOG(KERN_INFO, "LOOP_CONFIGURE\n");
			//filter_print_buff((void*)&config, sizeof(config));
			return loop_configure(lo, mode, bdev, NULL, &config);
		}
		case LOOP_CHANGE_FD:
			return loop_change_fd(lo, bdev, arg);
		case LOOP_CLR_FD:
			return loop_clr_fd(lo);
		case LOOP_SET_STATUS:
			err = -EPERM;
			if ((mode & FMODE_WRITE) || capable(CAP_SYS_ADMIN)) {
				err = loop_set_status_old(lo, argp);
			}
			break;
		case LOOP_GET_STATUS:
			return loop_get_status_old(lo, argp);
		case LOOP_SET_STATUS64:
			err = -EPERM;
			if ((mode & FMODE_WRITE) || capable(CAP_SYS_ADMIN)) {
				err = loop_set_status64(lo, argp);
			}
			break;
		case LOOP_GET_STATUS64:
			return loop_get_status64(lo, argp);
		case LOOP_SET_CAPACITY:
		case LOOP_SET_DIRECT_IO:
		case LOOP_SET_BLOCK_SIZE:
			if (!(mode & FMODE_WRITE) && !capable(CAP_SYS_ADMIN))
				return -EPERM;
		fallthrough;
		default:
			err = lo_simple_ioctl(lo, cmd, arg);
			break;
	}

	return err;
}

#ifdef CONFIG_COMPAT


/*
 * Transfer 32-bit compatibility structure in userspace to 64-bit loop info
 * - noinlined to reduce stack space usage in main part of driver
 */
noinline int loop_info64_from_compat(const struct compat_loop_info __user *arg, struct loop_info64 *info64)
{
	LOG(KERN_INFO, "\n");
	struct compat_loop_info info;

	if (copy_from_user(&info, arg, sizeof(info)))
		return -EFAULT;

	memset(info64, 0, sizeof(*info64));
	info64->lo_number = info.lo_number;
	info64->lo_device = info.lo_device;
	info64->lo_inode = info.lo_inode;
	info64->lo_rdevice = info.lo_rdevice;
	info64->lo_offset = info.lo_offset;
	info64->lo_sizelimit = 0;
	info64->lo_encrypt_type = info.lo_encrypt_type;
	info64->lo_encrypt_key_size = info.lo_encrypt_key_size;
	info64->lo_flags = info.lo_flags;
	info64->lo_init[0] = info.lo_init[0];
	info64->lo_init[1] = info.lo_init[1];
	if (info.lo_encrypt_type == LO_CRYPT_CRYPTOAPI)
		memcpy(info64->lo_crypt_name, info.lo_name, LO_NAME_SIZE);
	else
		memcpy(info64->lo_file_name, info.lo_name, LO_NAME_SIZE);
	memcpy(info64->lo_encrypt_key, info.lo_encrypt_key, LO_KEY_SIZE);
	return 0;
}

/*
 * Transfer 64-bit loop info to 32-bit compatibility structure in userspace
 * - noinlined to reduce stack space usage in main part of driver
 */
noinline int
loop_info64_to_compat(const struct loop_info64 *info64,
		      struct compat_loop_info __user *arg)
{
	//LOG(KERN_INFO, "\n");
	struct compat_loop_info info;

	memset(&info, 0, sizeof(info));
	info.lo_number = info64->lo_number;
	info.lo_device = info64->lo_device;
	info.lo_inode = info64->lo_inode;
	info.lo_rdevice = info64->lo_rdevice;
	info.lo_offset = info64->lo_offset;
	info.lo_encrypt_type = info64->lo_encrypt_type;
	info.lo_encrypt_key_size = info64->lo_encrypt_key_size;
	info.lo_flags = info64->lo_flags;
	info.lo_init[0] = info64->lo_init[0];
	info.lo_init[1] = info64->lo_init[1];
	if (info.lo_encrypt_type == LO_CRYPT_CRYPTOAPI)
		memcpy(info.lo_name, info64->lo_crypt_name, LO_NAME_SIZE);
	else
		memcpy(info.lo_name, info64->lo_file_name, LO_NAME_SIZE);
	memcpy(info.lo_encrypt_key, info64->lo_encrypt_key, LO_KEY_SIZE);

	/* error in case values were truncated */
	if (info.lo_device != info64->lo_device ||
		info.lo_rdevice != info64->lo_rdevice ||
		info.lo_inode != info64->lo_inode ||
		info.lo_offset != info64->lo_offset ||
		info.lo_init[0] != info64->lo_init[0] ||
		info.lo_init[1] != info64->lo_init[1])
		return -EOVERFLOW;

	if (copy_to_user(arg, &info, sizeof(info)))
		return -EFAULT;
	return 0;
}

int loop_set_status_compat(struct loop_device *lo,
		       const struct compat_loop_info __user *arg)
{
	//LOG(KERN_INFO, "\n");
	struct loop_info64 info64;
	int ret;

	ret = loop_info64_from_compat(arg, &info64);
	if (ret < 0)
		return ret;
	return loop_set_status(lo, &info64);
}

int loop_get_status_compat(struct loop_device *lo,
		       struct compat_loop_info __user *arg)
{
	//LOG(KERN_INFO, "\n");
	struct loop_info64 info64;
	int err;

	if (!arg)
		return -EINVAL;
	err = loop_get_status(lo, &info64);
	if (!err)
		err = loop_info64_to_compat(&info64, arg);
	return err;
}
int lo_compat_ioctl(struct block_device *bdev, fmode_t mode,
			   unsigned int cmd, unsigned long arg)
{
	//LOG(KERN_INFO, "\n");
	struct loop_device *lo = bdev->bd_disk->private_data;
	int err;

	switch(cmd) {
		case LOOP_SET_STATUS:
			err = loop_set_status_compat(lo,
						     (const struct compat_loop_info __user *)arg);
			break;
		case LOOP_GET_STATUS:
			err = loop_get_status_compat(lo,
						     (struct compat_loop_info __user *)arg);
			break;
		case LOOP_SET_CAPACITY:
		case LOOP_CLR_FD:
		case LOOP_GET_STATUS64:
		case LOOP_SET_STATUS64:
		case LOOP_CONFIGURE:
			arg = (unsigned long) compat_ptr(arg);
			fallthrough;
		case LOOP_SET_FD:
		case LOOP_CHANGE_FD:
		case LOOP_SET_BLOCK_SIZE:
		case LOOP_SET_DIRECT_IO:
			err = lo_ioctl(bdev, mode, cmd, arg);
			break;
		default:
			err = -ENOIOCTLCMD;
			break;
	}
	return err;
}
#endif

int lo_open(struct block_device *bdev, fmode_t mode)
{
	//LOG(KERN_INFO, "\n");
	struct loop_device *lo = bdev->bd_disk->private_data;
	int err;

	err = mutex_lock_killable(&lo->lo_mutex);
	if (err)
		return err;
	if (lo->lo_state == Lo_deleting)
		err = -ENXIO;
	else
		atomic_inc(&lo->lo_refcnt);
	mutex_unlock(&lo->lo_mutex);
	return err;
}

void lo_release(struct gendisk *disk, fmode_t mode)
{
	//LOG(KERN_INFO, "\n");
	struct loop_device *lo = disk->private_data;

	mutex_lock(&lo->lo_mutex);
	if (atomic_dec_return(&lo->lo_refcnt))
		goto out_unlock;

	if (lo->lo_flags & LO_FLAGS_AUTOCLEAR) {
		if (lo->lo_state != Lo_bound)
			goto out_unlock;
		lo->lo_state = Lo_rundown;
		mutex_unlock(&lo->lo_mutex);
		/*
		 * In autoclear mode, stop the loop thread
		 * and remove configuration after last close.
		 */
		__loop_clr_fd(lo, true);
		return;
	} else if (lo->lo_state == Lo_bound) {
		/*
		 * Otherwise keep thread (if running) and config,
		 * but flush possible ongoing bios in thread.
		 */
		blk_mq_freeze_queue(lo->lo_queue);
		blk_mq_unfreeze_queue(lo->lo_queue);
	}

	out_unlock:
	mutex_unlock(&lo->lo_mutex);
}

const struct block_device_operations lo_fops = {
	.owner =	THIS_MODULE,
	.open =		lo_open,
	.release =	lo_release,
	.ioctl =	lo_ioctl,
#ifdef CONFIG_COMPAT
	.compat_ioctl =	lo_compat_ioctl,
#endif
};


const struct blk_mq_ops loop_mq_ops =
{
	.queue_rq       = loop_queue_rq,
	.complete	= lo_complete_rq,
};




int loop_add(int i)
{
	LOG(KERN_INFO, "start loop_add\n");
	struct loop_device *lo;
	struct gendisk *disk;
	int err;

	err = -ENOMEM;
	lo = kzalloc(sizeof(*lo), GFP_KERNEL);
	if (!lo)
		goto out;
	lo->lo_state = Lo_unbound;

	err = mutex_lock_killable(&loop_ctl_mutex);
	if (err)
		goto out_free_dev;

	/* allocate id, if @id >= 0, we're requesting that specific id */
	if (i >= 0) {
		err = idr_alloc(&loop_index_idr, lo, i, i + 1, GFP_KERNEL);
		if (err == -ENOSPC)
			err = -EEXIST;
	} else {
		err = idr_alloc(&loop_index_idr, lo, 0, 0, GFP_KERNEL);
	}
	mutex_unlock(&loop_ctl_mutex);
	if (err < 0)
		goto out_free_dev;
	i = err;

	err = -ENOMEM;
	lo->tag_set.ops = &loop_mq_ops;
	lo->tag_set.nr_hw_queues = 1;
	lo->tag_set.queue_depth = 128;
	lo->tag_set.numa_node = NUMA_NO_NODE;
	lo->tag_set.cmd_size = sizeof(struct loop_cmd);
	lo->tag_set.flags = BLK_MQ_F_SHOULD_MERGE | BLK_MQ_F_STACKING |
	BLK_MQ_F_NO_SCHED_BY_DEFAULT;
	lo->tag_set.driver_data = lo;

	err = blk_mq_alloc_tag_set(&lo->tag_set);
	if (err)
		goto out_free_idr;

	disk = lo->lo_disk = blk_mq_alloc_disk(&lo->tag_set, lo);
	if (IS_ERR(disk)) {
		err = PTR_ERR(disk);
		goto out_cleanup_tags;
	}
	lo->lo_queue = lo->lo_disk->queue;

	blk_queue_max_hw_sectors(lo->lo_queue, BLK_DEF_MAX_SECTORS);

	/*
	 * By default, we do buffer IO, so it doesn't make sense to enable
	 * merge because the I/O submitted to backing file is handled page by
	 * page. For directio mode, merge does help to dispatch bigger request
	 * to underlayer disk. We will enable merge once directio is enabled.
	 */
	blk_queue_flag_set(QUEUE_FLAG_NOMERGES, lo->lo_queue);

	/*
	 * Disable partition scanning by default. The in-kernel partition
	 * scanning can be requested individually per-device during its
	 * setup. Userspace can always add and remove partitions from all
	 * devices. The needed partition minors are allocated from the
	 * extended minor space, the main loop device numbers will continue
	 * to match the loop minors, regardless of the number of partitions
	 * used.
	 *
	 * If max_part is given, partition scanning is globally enabled for
	 * all loop devices. The minors for the main loop devices will be
	 * multiples of max_part.
	 *
	 * Note: Global-for-all-devices, set-only-at-init, read-only module
	 * parameteters like 'max_loop' and 'max_part' make things needlessly
	 * complicated, are too static, inflexible and may surprise
	 * userspace tools. Parameters like this in general should be avoided.
	 */
	if (!part_shift)
		disk->flags |= GENHD_FL_NO_PART_SCAN;
	disk->flags |= GENHD_FL_EXT_DEVT;
	atomic_set(&lo->lo_refcnt, 0);
	mutex_init(&lo->lo_mutex);
	lo->lo_number		= i;
	spin_lock_init(&lo->lo_lock);
	spin_lock_init(&lo->lo_work_lock);
	disk->major		= LOOP_MAJOR;
	disk->first_minor	= i << part_shift;
	disk->minors		= 1 << part_shift;
	disk->fops		= &lo_fops;
	disk->private_data	= lo;
	disk->queue		= lo->lo_queue;
	disk->events		= DISK_EVENT_MEDIA_CHANGE;
	disk->event_flags	= DISK_EVENT_FLAG_UEVENT;
	sprintf(disk->disk_name, "loop_jokkeu%d", i - 7);
	/* Make this loop device reachable from pathname. */
	add_disk(disk);
	/* Show this loop device. */
	mutex_lock(&loop_ctl_mutex);
	lo->idr_visible = true;
	mutex_unlock(&loop_ctl_mutex);


	return i;

out_cleanup_tags:
	blk_mq_free_tag_set(&lo->tag_set);
out_free_idr:
	mutex_lock(&loop_ctl_mutex);
	idr_remove(&loop_index_idr, i);
	mutex_unlock(&loop_ctl_mutex);
out_free_dev:
	kfree(lo);
out:
	return err;
}

void loop_remove(struct loop_device *lo)
{
	/* Make this loop device unreachable from pathname. */
	del_gendisk(lo->lo_disk);
	blk_cleanup_disk(lo->lo_disk);
	blk_mq_free_tag_set(&lo->tag_set);
	mutex_lock(&loop_ctl_mutex);
	idr_remove(&loop_index_idr, lo->lo_number);
	mutex_unlock(&loop_ctl_mutex);
	/* There is no route which can find this loop device. */
	mutex_destroy(&lo->lo_mutex);
	kfree(lo);
}

void loop_probe_cipher(dev_t dev)
{
	return 0;
}

int loop_control_remove(int idx)
{
	struct loop_device *lo;
	int ret;

	if (idx < 0) {
		pr_warn_once("deleting an unspecified loop device is not supported.\n");
		return -EINVAL;
	}

	/* Hide this loop device for serialization. */
	ret = mutex_lock_killable(&loop_ctl_mutex);
	if (ret)
		return ret;
	lo = idr_find(&loop_index_idr, idx);
	if (!lo || !lo->idr_visible)
		ret = -ENODEV;
	else
		lo->idr_visible = false;
	mutex_unlock(&loop_ctl_mutex);
	if (ret)
		return ret;

	/* Check whether this loop device can be removed. */
	ret = mutex_lock_killable(&lo->lo_mutex);
	if (ret)
		goto mark_visible;
	if (lo->lo_state != Lo_unbound ||
		atomic_read(&lo->lo_refcnt) > 0) {
		mutex_unlock(&lo->lo_mutex);
	ret = -EBUSY;
	goto mark_visible;
		}
		/* Mark this loop device no longer open()-able. */
		lo->lo_state = Lo_deleting;
		mutex_unlock(&lo->lo_mutex);

		loop_remove(lo);
		return 0;

		mark_visible:
		/* Show this loop device again. */
		mutex_lock(&loop_ctl_mutex);
		lo->idr_visible = true;
		mutex_unlock(&loop_ctl_mutex);
		return ret;
}

int loop_control_get_free(int idx)
{
	struct loop_device *lo;
	int id, ret;

	ret = mutex_lock_killable(&loop_ctl_mutex);
	if (ret)
		return ret;
	idr_for_each_entry(&loop_index_idr, lo, id) {
		/* Hitting a race results in creating a new loop device which is harmless. */
		if (lo->idr_visible && data_race(lo->lo_state) == Lo_unbound)
			goto found;
	}
	mutex_unlock(&loop_ctl_mutex);
	return loop_add(-1);
	found:
	mutex_unlock(&loop_ctl_mutex);
	return id;
}

long loop_control_ioctl(struct file *file, unsigned int cmd,
			       unsigned long parm)
{
	switch (cmd) {
		case LOOP_CTL_ADD:
			return loop_add(parm);
		case LOOP_CTL_REMOVE:
			return loop_control_remove(parm);
		case LOOP_CTL_GET_FREE:
			return loop_control_get_free(parm);
		default:
			return -ENOSYS;
	}
}

const struct file_operations loop_ctl_fops = {
	.open		= nonseekable_open,
	.unlocked_ioctl	= loop_control_ioctl,
	.compat_ioctl	= loop_control_ioctl,
	.owner		= THIS_MODULE,
	.llseek		= noop_llseek,
};

struct miscdevice loop_misc = {
	.minor		= MISC_DYNAMIC_MINOR, // запрос динамичкского минора
	.name		= "loop-control_jokkkeu",
	.fops		= &loop_ctl_fops,
};





void lo_complete_rq(struct request *rq)
{
	//LOG(KERN_INFO, "\n");
	struct loop_cmd *cmd = blk_mq_rq_to_pdu(rq);
	blk_status_t ret = BLK_STS_OK;

	if (!cmd->use_aio || cmd->ret < 0 || cmd->ret == blk_rq_bytes(rq) ||
		req_op(rq) != REQ_OP_READ) {
		if (cmd->ret < 0)
			ret = errno_to_blk_status(cmd->ret);
		goto end_io;
		}

		/*
		 * Short READ - if we got some data, advance our request and
		 * retry it. If we got no data, end the rest with EIO.
		 */
		if (cmd->ret) {
			blk_update_request(rq, BLK_STS_OK, cmd->ret);
			cmd->ret = 0;
			blk_mq_requeue_request(rq, true);
		} else {
			if (cmd->use_aio) {
				struct bio *bio = rq->bio;

				while (bio) {
					zero_fill_bio(bio);
					bio = bio->bi_next;
				}
			}
			ret = BLK_STS_IOERR;
			end_io:
			blk_mq_end_request(rq, ret);
		}
}


blk_status_t loop_queue_rq(struct blk_mq_hw_ctx *hctx, const struct blk_mq_queue_data *bd)
{
	//LOG(KERN_INFO, "\n");
	struct request *rq = bd->rq;
	struct loop_cmd *cmd = blk_mq_rq_to_pdu(rq);
	struct loop_device *lo = rq->q->queuedata;

	blk_mq_start_request(rq);

	if (lo->lo_state != Lo_bound)
		return BLK_STS_IOERR;

	switch (req_op(rq)) {
		case REQ_OP_FLUSH:
		case REQ_OP_DISCARD:
		case REQ_OP_WRITE_ZEROES:
			cmd->use_aio = false;
			break;
		default:
			cmd->use_aio = lo->use_dio;
			break;
	}

	/* always use the first bio's css */
	cmd->blkcg_css = NULL;
	cmd->memcg_css = NULL;
	#ifdef CONFIG_BLK_CGROUP
	if (rq->bio && rq->bio->bi_blkg)
	{
		cmd->blkcg_css = &bio_blkcg(rq->bio)->css;
		#ifdef CONFIG_MEMCG
		cmd->memcg_css =
		cgroup_get_e_css(cmd->blkcg_css->cgroup,
				 &memory_cgrp_subsys);
		#endif
	}
	#endif
	loop_queue_work(lo, cmd);

	return BLK_STS_OK;
}

void loop_handle_cmd(struct loop_cmd *cmd)
{
	//LOG(KERN_INFO, "\n");
	struct request *rq = blk_mq_rq_from_pdu(cmd);
	const bool write = op_is_write(req_op(rq));
	struct loop_device *lo = rq->q->queuedata;
	int ret = 0;
	struct mem_cgroup *old_memcg = NULL;

	if (write && (lo->lo_flags & LO_FLAGS_READ_ONLY)) {
		ret = -EIO;
		goto failed;
	}

	if (cmd->blkcg_css)
		kthread_associate_blkcg(cmd->blkcg_css);
	if (cmd->memcg_css)
		old_memcg = set_active_memcg(mem_cgroup_from_css(cmd->memcg_css));

	ret = do_req_filebacked(lo, rq);

	if (cmd->blkcg_css)
		kthread_associate_blkcg(NULL);

	if (cmd->memcg_css) {
		set_active_memcg(old_memcg);
		css_put(cmd->memcg_css);
	}
	failed:
	/* complete non-aio request */
	if (!cmd->use_aio || ret)
	{
		if (ret == -EOPNOTSUPP)
			cmd->ret = ret;
		else
			cmd->ret = ret ? -EIO : 0;
		if (likely(!blk_should_fake_timeout(rq->q)))
			blk_mq_complete_request(rq);
	}
}


int loop_set_status(struct loop_device *lo, const struct loop_info64 *info)
{
	LOG(KERN_INFO, "\n");
	int err;
	kuid_t uid = current_uid();
	int prev_lo_flags;
	bool partscan = false;
	bool size_changed = false;

	err = mutex_lock_killable(&lo->lo_mutex);
	if (err)
		return err;
	if (lo->lo_encrypt_key_size &&
		!uid_eq(lo->lo_key_owner, uid) &&
		!capable(CAP_SYS_ADMIN)) {
		err = -EPERM;
	goto out_unlock;
		}
		if (lo->lo_state != Lo_bound) {
			err = -ENXIO;
			goto out_unlock;
		}

		if (lo->lo_offset != info->lo_offset ||
			lo->lo_sizelimit != info->lo_sizelimit) {
			size_changed = true;
		sync_blockdev(lo->lo_device);
		invalidate_bdev(lo->lo_device);
			}

			/* I/O need to be drained during transfer transition */
			blk_mq_freeze_queue(lo->lo_queue);

			if (size_changed && lo->lo_device->bd_inode->i_mapping->nrpages) {
				/* If any pages were dirtied after invalidate_bdev(), try again */
				err = -EAGAIN;
				pr_warn("%s: loop%d (%s) has still dirty pages (nrpages=%lu)\n",
					__func__, lo->lo_number, lo->lo_file_name,
	    lo->lo_device->bd_inode->i_mapping->nrpages);
				goto out_unfreeze;
			}

			prev_lo_flags = lo->lo_flags;

			err = loop_set_status_from_info(lo, info);
			if (err)
				goto out_unfreeze;

	/* Mask out flags that can't be set using LOOP_SET_STATUS. */
	lo->lo_flags &= LOOP_SET_STATUS_SETTABLE_FLAGS;
	/* For those flags, use the previous values instead */
	lo->lo_flags |= prev_lo_flags & ~LOOP_SET_STATUS_SETTABLE_FLAGS;
	/* For flags that can't be cleared, use previous values too */
	lo->lo_flags |= prev_lo_flags & ~LOOP_SET_STATUS_CLEARABLE_FLAGS;

	if (size_changed) {
		loff_t new_size = get_size(lo->lo_offset, lo->lo_sizelimit,
					   lo->lo_backing_file);
		loop_set_size(lo, new_size);
	}

	loop_config_discard(lo);

	/* update dio if lo_offset or transfer is changed */
	__loop_update_dio(lo, lo->use_dio);

	out_unfreeze:
	blk_mq_unfreeze_queue(lo->lo_queue);

	if (!err && (lo->lo_flags & LO_FLAGS_PARTSCAN) &&
		!(prev_lo_flags & LO_FLAGS_PARTSCAN)) {
		lo->lo_disk->flags &= ~GENHD_FL_NO_PART_SCAN;
	partscan = true;
		}
		out_unlock:
		mutex_unlock(&lo->lo_mutex);
		if (partscan)
			loop_reread_partitions(lo);

	return err;
}

int loop_get_status(struct loop_device *lo, struct loop_info64 *info)
{
	LOG(KERN_INFO, "\n");
	struct path path;
	struct kstat stat;
	int ret;

	ret = mutex_lock_killable(&lo->lo_mutex);
	if (ret)
		return ret;
	if (lo->lo_state != Lo_bound) {
		mutex_unlock(&lo->lo_mutex);
		return -ENXIO;
	}

	memset(info, 0, sizeof(*info));
	info->lo_number = lo->lo_number;
	info->lo_offset = lo->lo_offset;
	info->lo_sizelimit = lo->lo_sizelimit;
	info->lo_flags = lo->lo_flags;
	memcpy(info->lo_file_name, lo->lo_file_name, LO_NAME_SIZE);
	memcpy(info->lo_crypt_name, lo->lo_crypt_name, LO_NAME_SIZE);
	info->lo_encrypt_type =
	lo->lo_encryption ? lo->lo_encryption->number : 0;
	if (lo->lo_encrypt_key_size && capable(CAP_SYS_ADMIN)) {
		info->lo_encrypt_key_size = lo->lo_encrypt_key_size;
		memcpy(info->lo_encrypt_key, lo->lo_encrypt_key,
		       lo->lo_encrypt_key_size);
	}

	/* Drop lo_mutex while we call into the filesystem. */
	path = lo->lo_backing_file->f_path;
	path_get(&path);
	mutex_unlock(&lo->lo_mutex);
	ret = vfs_getattr(&path, &stat, STATX_INO, AT_STATX_SYNC_AS_STAT);
	if (!ret) {
		info->lo_device = huge_encode_dev(stat.dev);
		info->lo_inode = stat.ino;
		info->lo_rdevice = huge_encode_dev(stat.rdev);
	}
	path_put(&path);
	return ret;
}

void loop_info64_from_old(const struct loop_info *info, struct loop_info64 *info64)
{
	LOG(KERN_INFO, "\n");
	memset(info64, 0, sizeof(*info64));
	info64->lo_number = info->lo_number;
	info64->lo_device = info->lo_device;
	info64->lo_inode = info->lo_inode;
	info64->lo_rdevice = info->lo_rdevice;
	info64->lo_offset = info->lo_offset;
	info64->lo_sizelimit = 0;
	info64->lo_encrypt_type = info->lo_encrypt_type;
	info64->lo_encrypt_key_size = info->lo_encrypt_key_size;
	info64->lo_flags = info->lo_flags;
	info64->lo_init[0] = info->lo_init[0];
	info64->lo_init[1] = info->lo_init[1];
	if (info->lo_encrypt_type == LO_CRYPT_CRYPTOAPI)
		memcpy(info64->lo_crypt_name, info->lo_name, LO_NAME_SIZE);
	else
		memcpy(info64->lo_file_name, info->lo_name, LO_NAME_SIZE);
	memcpy(info64->lo_encrypt_key, info->lo_encrypt_key, LO_KEY_SIZE);
}

int loop_info64_to_old(const struct loop_info64 *info64, struct loop_info *info)
{
	LOG(KERN_INFO, "\n");
	memset(info, 0, sizeof(*info));
	info->lo_number = info64->lo_number;
	info->lo_device = info64->lo_device;
	info->lo_inode = info64->lo_inode;
	info->lo_rdevice = info64->lo_rdevice;
	info->lo_offset = info64->lo_offset;
	info->lo_encrypt_type = info64->lo_encrypt_type;
	info->lo_encrypt_key_size = info64->lo_encrypt_key_size;
	info->lo_flags = info64->lo_flags;
	info->lo_init[0] = info64->lo_init[0];
	info->lo_init[1] = info64->lo_init[1];
	if (info->lo_encrypt_type == LO_CRYPT_CRYPTOAPI)
		memcpy(info->lo_name, info64->lo_crypt_name, LO_NAME_SIZE);
	else
		memcpy(info->lo_name, info64->lo_file_name, LO_NAME_SIZE);
	memcpy(info->lo_encrypt_key, info64->lo_encrypt_key, LO_KEY_SIZE);

	/* error in case values were truncated */
	if (info->lo_device != info64->lo_device ||
		info->lo_rdevice != info64->lo_rdevice ||
		info->lo_inode != info64->lo_inode ||
		info->lo_offset != info64->lo_offset)
		return -EOVERFLOW;

	return 0;
}

int loop_set_status_old(struct loop_device *lo, const struct loop_info __user *arg)
{
	struct loop_info info;
	struct loop_info64 info64;

	if (copy_from_user(&info, arg, sizeof (struct loop_info)))
		return -EFAULT;
	loop_info64_from_old(&info, &info64);
	return loop_set_status(lo, &info64);
}

int loop_set_status64(struct loop_device *lo, const struct loop_info64 __user *arg)
{
	LOG(KERN_INFO, "\n");
	struct loop_info64 info64;

	if (copy_from_user(&info64, arg, sizeof (struct loop_info64)))
		return -EFAULT;
	return loop_set_status(lo, &info64);
}

int loop_get_status_old(struct loop_device *lo, struct loop_info __user *arg) {
	struct loop_info info;
	struct loop_info64 info64;
	int err;

	if (!arg)
		return -EINVAL;
	err = loop_get_status(lo, &info64);
	if (!err)
		err = loop_info64_to_old(&info64, &info);
	if (!err && copy_to_user(arg, &info, sizeof(info)))
		err = -EFAULT;

	return err;
}

int loop_get_status64(struct loop_device *lo, struct loop_info64 __user *arg) {
	LOG(KERN_INFO, "\n");
	struct loop_info64 info64;
	int err;

	if (!arg)
		return -EINVAL;
	err = loop_get_status(lo, &info64);
	if (!err && copy_to_user(arg, &info64, sizeof(info64)))
		err = -EFAULT;

	return err;
}

int loop_set_capacity(struct loop_device *lo)
{
	LOG(KERN_INFO, "\n");
	loff_t size;

	if (unlikely(lo->lo_state != Lo_bound))
		return -ENXIO;

	size = get_loop_size(lo, lo->lo_backing_file);
	loop_set_size(lo, size);

	return 0;
}

int loop_set_dio(struct loop_device *lo, unsigned long arg)
{
	LOG(KERN_INFO, "\n");
	int error = -ENXIO;
	if (lo->lo_state != Lo_bound)
		goto out;

	__loop_update_dio(lo, !!arg);
	if (lo->use_dio == !!arg)
		return 0;
	error = -EINVAL;
	out:
	return error;
}

int loop_set_block_size(struct loop_device *lo, unsigned long arg)
{
	LOG(KERN_INFO, "\n");
	int err = 0;

	if (lo->lo_state != Lo_bound)
		return -ENXIO;

	err = blk_validate_block_size(arg);
	if (err)
		return err;

	if (lo->lo_queue->limits.logical_block_size == arg)
		return 0;

	sync_blockdev(lo->lo_device);
	invalidate_bdev(lo->lo_device);

	blk_mq_freeze_queue(lo->lo_queue);

	/* invalidate_bdev should have truncated all the pages */
	if (lo->lo_device->bd_inode->i_mapping->nrpages) {
		err = -EAGAIN;
		pr_warn("%s: loop%d (%s) has still dirty pages (nrpages=%lu)\n",
			__func__, lo->lo_number, lo->lo_file_name,
	  lo->lo_device->bd_inode->i_mapping->nrpages);
		goto out_unfreeze;
	}

	blk_queue_logical_block_size(lo->lo_queue, arg);
	blk_queue_physical_block_size(lo->lo_queue, arg);
	blk_queue_io_min(lo->lo_queue, arg);
	loop_update_dio(lo);
	out_unfreeze:
	blk_mq_unfreeze_queue(lo->lo_queue);

	return err;
}


/*
 * loop_change_fd switched the backing store of a loopback device to
 * a new file. This is useful for operating system installers to free up
 * the original file and in High Availability environments to switch to
 * an alternative location for the content in case of server meltdown.
 * This can only work if the loop device is used read-only, and if the
 * new backing store is the same size and type as the old backing store.
 */
int loop_change_fd(struct loop_device *lo, struct block_device *bdev,
			  unsigned int arg)
{
	//LOG(KERN_INFO, "\n");
	struct file *file = fget(arg);
	struct file *old_file;
	int error;
	bool partscan;
	bool is_loop;

	if (!file)
		return -EBADF;
	is_loop = is_loop_device(file);
	error = loop_global_lock_killable(lo, is_loop);
	if (error)
		goto out_putf;
	error = -ENXIO;
	if (lo->lo_state != Lo_bound)
		goto out_err;

	/* the loop device has to be read-only */
	error = -EINVAL;
	if (!(lo->lo_flags & LO_FLAGS_READ_ONLY))
		goto out_err;

	error = loop_validate_file(file, bdev);
	if (error)
		goto out_err;

	old_file = lo->lo_backing_file;

	error = -EINVAL;

	/* size of the new backing store needs to be the same */
	if (get_loop_size(lo, file) != get_loop_size(lo, old_file))
		goto out_err;

	/* and ... switch */
	disk_force_media_change(lo->lo_disk, DISK_EVENT_MEDIA_CHANGE);
	blk_mq_freeze_queue(lo->lo_queue);
	mapping_set_gfp_mask(old_file->f_mapping, lo->old_gfp_mask);
	lo->lo_backing_file = file;
	lo->old_gfp_mask = mapping_gfp_mask(file->f_mapping);
	mapping_set_gfp_mask(file->f_mapping,
			     lo->old_gfp_mask & ~(__GFP_IO|__GFP_FS));
	loop_update_dio(lo);
	blk_mq_unfreeze_queue(lo->lo_queue);
	partscan = lo->lo_flags & LO_FLAGS_PARTSCAN;
	loop_global_unlock(lo, is_loop);

	/*
	 * Flush loop_validate_file() before fput(), for l->lo_backing_file
	 * might be pointing at old_file which might be the last reference.
	 */
	if (!is_loop) {
		mutex_lock(&loop_validate_mutex);
		mutex_unlock(&loop_validate_mutex);
	}
	/*
	 * We must drop file reference outside of lo_mutex as dropping
	 * the file ref can take open_mutex which creates circular locking
	 * dependency.
	 */
	fput(old_file);
	if (partscan)
		loop_reread_partitions(lo);
	return 0;

	out_err:
	loop_global_unlock(lo, is_loop);
	out_putf:
	fput(file);
	return error;
}



/**
 * loop_set_status_from_info - configure device from loop_info
 * @lo: struct loop_device to configure
 * @info: struct loop_info64 to configure the device with
 *
 * Configures the loop device parameters according to the passed
 * in loop_info64 configuration.
 */
int loop_set_status_from_info(struct loop_device *lo,
			  const struct loop_info64 *info)
{
	LOG(KERN_INFO, "\n");
	int err;
	struct loop_func_table *xfer;
	kuid_t uid = current_uid();

	if ((unsigned int) info->lo_encrypt_key_size > LO_KEY_SIZE)
		return -EINVAL;

	err = loop_release_xfer(lo);
	if (err)
		return err;
	/*
	if (info->lo_encrypt_type)
	{
		unsigned int type = info->lo_encrypt_type;

		if (type >= MAX_LO_CRYPT)
			return -EINVAL;
		xfer = xfer_funcs[type];
		if (xfer == NULL)
			return -EINVAL;
	} else
		xfer = NULL;

	*/

	LOG(KERN_INFO, "set encrypt\n");
	err = loop_init_xfer(lo, xfer, info);
	if (err)
		return err;
	/*
	lo->lo_offset = info->lo_offset;
	lo->lo_sizelimit = info->lo_sizelimit;
	memcpy(lo->lo_file_name, info->lo_file_name, LO_NAME_SIZE);
	memcpy(lo->lo_crypt_name, info->lo_crypt_name, LO_NAME_SIZE);
	lo->lo_file_name[LO_NAME_SIZE-1] = 0;
	lo->lo_crypt_name[LO_NAME_SIZE-1] = 0;

	if (!xfer)
		xfer = &none_funcs;
	lo->transfer = xfer->transfer;
	lo->ioctl = xfer->ioctl;

	lo->lo_flags = info->lo_flags;

	lo->lo_encrypt_key_size = info->lo_encrypt_key_size;
	lo->lo_init[0] = info->lo_init[0];
	lo->lo_init[1] = info->lo_init[1];
	if (info->lo_encrypt_key_size) {
		memcpy(lo->lo_encrypt_key, info->lo_encrypt_key,
		       info->lo_encrypt_key_size);
		lo->lo_key_owner = uid;
	}
	*/

	return 0;
}

