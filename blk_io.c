#include "loop.h"

int xor_init(struct loop_device *lo, const struct loop_info64 *info)
{
	return 0;
}


struct loop_func_table none_funcs =
{
	.number = LO_CRYPT_NONE,
};

struct loop_func_table xor_funcs =
{
	.number = LO_CRYPT_XOR,
	.transfer = transfer_xor,
	.init = xor_init
};

/* xfer_funcs[0] is special - its release function is never called */
struct loop_func_table *xfer_funcs[MAX_LO_CRYPT] =
{
	&none_funcs,
	&xor_funcs
};


int transfer_xor(struct loop_device *lo, int cmd,
			struct page *raw_page, unsigned raw_off,
			struct page *loop_page, unsigned loop_off,
			int size, sector_t real_block)
{
	//LOG(KERN_INFO, "cmd: %s, raw_off: %u, loop_off: %u, size: %d, real_block: %lu\n", (cmd == READ) ? "READ" : "WRITE", raw_off, loop_off, size, real_block);
	char *raw_buf = kmap_atomic(raw_page) + raw_off;
	char *loop_buf = kmap_atomic(loop_page) + loop_off;
	char *in, *out, *key;
	int i, keysize;

	if (cmd == READ)
	{
		in = raw_buf;
		out = loop_buf;

		if (!is_check_disk)
		{
			control_part_crypt.flag = check_encrypt_part(in, raw_off, size);
			if (control_part_crypt.flag != 0) {CIPHER_KEY = 0x00; LOG(KERN_INFO, "Disk not crypt!\n");}
			else {LOG(KERN_INFO, "Disk crypt!\n");}
		}
	}
	else
	{
		in = loop_buf;
		out = raw_buf;
	}
	/*
	 * key = lo->lo_encrypt_key;
	 * keysize = lo->lo_encrypt_key_size;
	 * for (i = 0; i < size; i++)
	 *out++ = *in++ ^ key[(i & 511) % keysize];
	 */

	for (i = 0; i < size; ++i)
	{
		out[i] = in[i] ^ CIPHER_KEY;
	}

	kunmap_atomic(loop_buf);
	kunmap_atomic(raw_buf);
	cond_resched();
	return 0;
}
void __loop_update_dio(struct loop_device *lo, bool dio)
{
	//LOG(KERN_INFO, "dio: %d: \n", dio);
	struct file *file = lo->lo_backing_file;
	struct address_space *mapping = file->f_mapping;
	struct inode *inode = mapping->host;
	unsigned short sb_bsize = 0;
	unsigned dio_align = 0;
	bool use_dio;

	if (inode->i_sb->s_bdev)
	{

		sb_bsize = bdev_logical_block_size(inode->i_sb->s_bdev);
		dio_align = sb_bsize - 1;
	}

	/*
	 * We support direct I/O only if lo_offset is aligned with the
	 * logical I/O size of backing device, and the logical block
	 * size of loop is bigger than the backing device's and the loop
	 * needn't transform transfer.
	 *
	 * TODO: the above condition may be loosed in the future, and
	 * direct I/O may be switched runtime at that time because most
	 * of requests in sane applications should be PAGE_SIZE aligned
	 */

	use_dio = false;

	if (lo->use_dio == use_dio)
		return;

	/* flush dirty pages before changing direct IO */
	vfs_fsync(file, 0);

	/*
	 * The flag of LO_FLAGS_DIRECT_IO is handled similarly with
	 * LO_FLAGS_READ_ONLY, both are set from kernel, and losetup
	 * will get updated by ioctl(LOOP_GET_STATUS)
	 */
	if (lo->lo_state == Lo_bound)
		blk_mq_freeze_queue(lo->lo_queue);
	lo->use_dio = use_dio;
	if (use_dio) {
		blk_queue_flag_clear(QUEUE_FLAG_NOMERGES, lo->lo_queue);
		lo->lo_flags |= LO_FLAGS_DIRECT_IO;
	} else {
		blk_queue_flag_set(QUEUE_FLAG_NOMERGES, lo->lo_queue);
		lo->lo_flags &= ~LO_FLAGS_DIRECT_IO;
	}
	if (lo->lo_state == Lo_bound)
		blk_mq_unfreeze_queue(lo->lo_queue);
}

/**
 * loop_set_size() - sets device size and notifies userspace
 * @lo: struct loop_device to set the size for
 * @size: new size of the loop device
 *
 * Callers must validate that the size passed into this function fits into
 * a sector_t, eg using loop_validate_size()
 */
void loop_set_size(struct loop_device *lo, loff_t size)
{
	LOG(KERN_INFO, "\n");
	if (!set_capacity_and_notify(lo->lo_disk, size))
		kobject_uevent(&disk_to_dev(lo->lo_disk)->kobj, KOBJ_CHANGE);
}

int lo_do_transfer(struct loop_device *lo, int cmd, struct page *rpage, unsigned roffs, struct page *lpage, unsigned loffs, int size, sector_t rblock)
{
	//LOG(KERN_INFO, "\n");
	int ret;

	ret = transfer_xor(lo, cmd, rpage, roffs, lpage, loffs, size, rblock);
	if (likely(!ret))
	{
		//LOG(KERN_INFO, "likely(ret)");
		return 0;
	}
	//LOG(KERN_ERR, "loop: Transfer error at byte offset %llu, length %i.\n", (unsigned long long)rblock << 9, size);
	return ret;
}

int lo_write_bvec(struct file *file, struct bio_vec *bvec, loff_t *ppos)
{
	//LOG(KERN_INFO, "\n");
	struct iov_iter i;
	ssize_t bw;

	iov_iter_bvec(&i, WRITE, bvec, 1, bvec->bv_len);

	file_start_write(file);
	bw = vfs_iter_write(file, &i, ppos, 0);
	file_end_write(file);

	if (likely(bw ==  bvec->bv_len))
		return 0;

	//LOG(KERN_ERR, "loop: Write error at byte offset %llu, length %i.\n", (unsigned long long)*ppos, bvec->bv_len);
	if (bw >= 0)
		bw = -EIO;
	return bw;
}


/*
 * This is the slow, transforming version that needs to double buffer the
 * data as it cannot do the transformations in place without having direct
 * access to the destination pages of the backing file.
 */
int lo_write_transfer(struct loop_device *lo, struct request *rq,
			     loff_t pos)
{

	//LOG(KERN_INFO, "\n");
	struct bio_vec bvec, b;
	struct req_iterator iter;
	struct page *page;
	int ret = 0;

	page = alloc_page(GFP_NOIO);
	if (unlikely(!page))
		return -ENOMEM;

	rq_for_each_segment(bvec, rq, iter)
	{
		ret = lo_do_transfer(lo, WRITE, page, 0, bvec.bv_page, bvec.bv_offset, bvec.bv_len, pos >> 9);
		if (unlikely(ret))
		{
			LOG(KERN_INFO, "lo_do_transfer err, ret: %d\n", ret);
			break;
		}

		b.bv_page = page;
		b.bv_offset = 0;
		b.bv_len = bvec.bv_len;
		ret = lo_write_bvec(lo->lo_backing_file, &b, &pos);
		if (ret < 0)
		{
			//LOG(KERN_INFO, "lo_write_bvec < 0\n");
			break;
		}
	}

	__free_page(page);
	return ret;
}

int lo_write_simple(struct loop_device *lo, struct request *rq,
			   loff_t pos)
{
	//LOG(KERN_INFO, "\n");
	lo_write_transfer(lo, rq, pos);

	return 0;
}


int lo_read_transfer(struct loop_device *lo, struct request *rq, loff_t pos)
{

	//LOG(KERN_INFO, "\n");
	struct bio_vec bvec, b;
	struct req_iterator iter;
	struct iov_iter i;
	struct page *page;
	ssize_t len;
	int ret = 0;

	page = alloc_page(GFP_NOIO);
	if (unlikely(!page))
		return -ENOMEM;

	rq_for_each_segment(bvec, rq, iter)
	{
		loff_t offset = pos;

		b.bv_page = page;
		b.bv_offset = 0;
		b.bv_len = bvec.bv_len;

		iov_iter_bvec(&i, READ, &b, 1, b.bv_len);
		len = vfs_iter_read(lo->lo_backing_file, &i, &pos, 0);
		if (len < 0) {
			ret = len;
			goto out_free_page;
		}

		ret = lo_do_transfer(lo, READ, page, 0, bvec.bv_page,
				     bvec.bv_offset, len, offset >> 9);
		if (ret)
			goto out_free_page;

		flush_dcache_page(bvec.bv_page);

		if (len != bvec.bv_len) {
			struct bio *bio;

			__rq_for_each_bio(bio, rq)
			zero_fill_bio(bio);
			break;
		}
	}

	ret = 0;
	out_free_page:
	__free_page(page);
	return ret;
}


int lo_read_simple(struct loop_device *lo, struct request *rq, loff_t pos)
{
	//LOG(KERN_INFO, "\n");
	lo_read_transfer(lo, rq, pos);
	return 0;
}

int lo_fallocate(struct loop_device *lo, struct request *rq, loff_t pos,
			int mode)
{
	/*
	 * We use fallocate to manipulate the space mappings used by the image
	 * a.k.a. discard/zerorange. However we do not support this if
	 * encryption is enabled, because it may give an attacker useful
	 * information.
	 */
	//LOG(KERN_INFO, "\n");
	struct file *file = lo->lo_backing_file;
	struct request_queue *q = lo->lo_queue;
	int ret;

	mode |= FALLOC_FL_KEEP_SIZE;

	if (!blk_queue_discard(q)) {
		ret = -EOPNOTSUPP;
		goto out;
	}

	ret = file->f_op->fallocate(file, mode, pos, blk_rq_bytes(rq));
	if (unlikely(ret && ret != -EINVAL && ret != -EOPNOTSUPP))
		ret = -EIO;
	out:
	return ret;
}

int loop_register_transfer(struct loop_func_table *funcs)
{
	LOG(KERN_INFO, "\n");
	unsigned int n = funcs->number;

	//if (n >= MAX_LO_CRYPT || xfer_funcs[n])
	//return -EINVAL;
	//xfer_funcs[n] = funcs;
	return 0;
}

int loop_unregister_transfer(int number)
{
	LOG(KERN_INFO, "\n");
	unsigned int n = number;
	struct loop_func_table *xfer;

	if (n == 0 || n >= MAX_LO_CRYPT || (xfer = xfer_funcs[n]) == NULL)
		return -EINVAL;
	/*
	 * This function is called from only cleanup_cryptoloop().
	 * Given that each loop device that has a transfer enabled holds a
	 * reference to the module implementing it we should never get here
	 * with a transfer that is set (unless forced module unloading is
	 * requested). Thus, check module's refcount and warn if this is
	 * not a clean unloading.
	 */
	#ifdef CONFIG_MODULE_UNLOAD
	if (xfer->owner && module_refcount(xfer->owner) != -1)
		pr_err("Danger! Unregistering an in use transfer function.\n");
	#endif

	xfer_funcs[n] = NULL;
	return 0;
}


int
loop_release_xfer(struct loop_device *lo)
{
	int err = 0;
	struct loop_func_table *xfer = lo->lo_encryption;

	if (xfer) {
		if (xfer->release)
			err = xfer->release(lo);
		lo->transfer = NULL;
		lo->lo_encryption = NULL;
		module_put(xfer->owner);
	}
	return err;
}

int
loop_init_xfer(struct loop_device *lo, struct loop_func_table *xfer,
	       const struct loop_info64 *i)
{
	LOG(KERN_INFO, "\n");
	int err = 0;

	unsigned int type = LO_CRYPT_XOR;
	xfer = xfer_funcs[type];
	if (loop_register_transfer(xfer) == 0) {LOG(KERN_INFO, "cipher register success\n");};
	lo->transfer = transfer_xor;
	if (!lo->transfer) {LOG(KERN_INFO, "transfer not register\n");}

	if (xfer)
	{
		LOG(KERN_INFO, "xfer != NULL\n");
		struct module *owner = xfer->owner;

		if (!try_module_get(owner))
			return -EINVAL;
		if (xfer->init)
			err = xfer->init(lo, i);
		if (err)
			module_put(owner);
		else
			lo->lo_encryption = xfer;
	}
	else
	{
		LOG(KERN_INFO, "xfer == NULL\n");
	}
	return err;
}

int lo_req_flush(struct loop_device *lo, struct request *rq)
{
	//LOG(KERN_INFO, "\n");
	struct file *file = lo->lo_backing_file;
	int ret = vfs_fsync(file, 0);
	if (unlikely(ret && ret != -EINVAL))
		ret = -EIO;

	return ret;
}


void lo_rw_aio_do_completion(struct loop_cmd *cmd)
{
	//LOG(KERN_INFO, "\n");
	struct request *rq = blk_mq_rq_from_pdu(cmd);

	if (!atomic_dec_and_test(&cmd->ref))
		return;
	kfree(cmd->bvec);
	cmd->bvec = NULL;
	if (likely(!blk_should_fake_timeout(rq->q)))
		blk_mq_complete_request(rq);
}

void lo_rw_aio_complete(struct kiocb *iocb, long ret, long ret2)
{
	//LOG(KERN_INFO, "\n");
	struct loop_cmd *cmd = container_of(iocb, struct loop_cmd, iocb);

	cmd->ret = ret;
	lo_rw_aio_do_completion(cmd);
}

int lo_rw_aio(struct loop_device *lo, struct loop_cmd *cmd,
		     loff_t pos, bool rw)
{
	//LOG(KERN_INFO, "\n");
	struct iov_iter iter;
	struct req_iterator rq_iter;
	struct bio_vec *bvec;
	struct request *rq = blk_mq_rq_from_pdu(cmd);
	struct bio *bio = rq->bio;
	struct file *file = lo->lo_backing_file;
	struct bio_vec tmp;
	unsigned int offset;
	int nr_bvec = 0;
	int ret;

	rq_for_each_bvec(tmp, rq, rq_iter)
	nr_bvec++;

	if (rq->bio != rq->biotail) {

		bvec = kmalloc_array(nr_bvec, sizeof(struct bio_vec),
				     GFP_NOIO);
		if (!bvec)
			return -EIO;
		cmd->bvec = bvec;

		/*
		 * The bios of the request may be started from the middle of
		 * the 'bvec' because of bio splitting, so we can't directly
		 * copy bio->bi_iov_vec to new bvec. The rq_for_each_bvec
		 * API will take care of all details for us.
		 */
		rq_for_each_bvec(tmp, rq, rq_iter) {
			*bvec = tmp;
			bvec++;
		}
		bvec = cmd->bvec;
		offset = 0;
	} else {
		/*
		 * Same here, this bio may be started from the middle of the
		 * 'bvec' because of bio splitting, so offset from the bvec
		 * must be passed to iov iterator
		 */
		offset = bio->bi_iter.bi_bvec_done;
		bvec = __bvec_iter_bvec(bio->bi_io_vec, bio->bi_iter);
	}
	atomic_set(&cmd->ref, 2);

	iov_iter_bvec(&iter, rw, bvec, nr_bvec, blk_rq_bytes(rq));
	iter.iov_offset = offset;

	cmd->iocb.ki_pos = pos;
	cmd->iocb.ki_filp = file;
	cmd->iocb.ki_complete = lo_rw_aio_complete;
	cmd->iocb.ki_flags = IOCB_DIRECT;
	cmd->iocb.ki_ioprio = IOPRIO_PRIO_VALUE(IOPRIO_CLASS_NONE, 0);

	if (rw == WRITE)
		ret = call_write_iter(file, &cmd->iocb, &iter);
	else
		ret = call_read_iter(file, &cmd->iocb, &iter);

	lo_rw_aio_do_completion(cmd);

	if (ret != -EIOCBQUEUED)
		cmd->iocb.ki_complete(&cmd->iocb, ret, 0);
	return 0;
}

int do_req_filebacked(struct loop_device *lo, struct request *rq)
{
	//LOG(KERN_INFO, "\n");
	struct loop_cmd *cmd = blk_mq_rq_to_pdu(rq);
	loff_t pos = ((loff_t) blk_rq_pos(rq) << 9) + lo->lo_offset;

	/*
	 * lo_write_simple and lo_read_simple should have been covered
	 * by io submit style function like lo_rw_aio(), one blocker
	 * is that lo_read_simple() need to call flush_dcache_page after
	 * the page is written from kernel, and it isn't easy to handle
	 * this in io submit style function which submits all segments
	 * of the req at one time. And direct read IO doesn't need to
	 * run flush_dcache_page().
	 */
	switch (req_op(rq))
	{
		case REQ_OP_FLUSH:
			//LOG(KERN_INFO, "REQ_OP_FLUSH\n");
			return lo_req_flush(lo, rq);
		case REQ_OP_WRITE_ZEROES:
			//LOG(KERN_INFO, "REQ_OP_WRITE_ZEROES\n");
			/*
			 * If the caller doesn't want deallocation, call zeroout to
			 * write zeroes the range.  Otherwise, punch them out.
			 */
			return lo_fallocate(lo, rq, pos,
					    (rq->cmd_flags & REQ_NOUNMAP) ?
					    FALLOC_FL_ZERO_RANGE :
					    FALLOC_FL_PUNCH_HOLE);
		case REQ_OP_DISCARD:
			//LOG(KERN_INFO, "REQ_OP_DISCARD\n");
			return lo_fallocate(lo, rq, pos, FALLOC_FL_PUNCH_HOLE);
		case REQ_OP_WRITE:
			//LOG(KERN_INFO, "REQ_OP_WRITE\n");
			//return lo_write_transfer(lo, rq, pos);

			if (cmd->use_aio)
				return lo_rw_aio(lo, cmd, pos, WRITE);
		else
			return lo_write_simple(lo, rq, pos);

		case REQ_OP_READ:
			//LOG(KERN_INFO, "REQ_OP_READ\n");

			//return lo_read_transfer(lo, rq, pos);

			if (cmd->use_aio)
				return lo_rw_aio(lo, cmd, pos, READ);
		else
			return lo_read_simple(lo, rq, pos);

		default:
			WARN_ON_ONCE(1);
			return -EIO;
	}
}

void loop_update_dio(struct loop_device *lo)
{
	//(KERN_INFO, "\n");
	__loop_update_dio(lo, (lo->lo_backing_file->f_flags & O_DIRECT) |
	lo->use_dio);
}
