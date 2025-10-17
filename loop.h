
#ifndef _LINUX_LOOP_H
#define _LINUX_LOOP_H

#include <linux/bio.h>
#include <linux/blkdev.h>
#include <linux/blk-mq.h>
#include <linux/spinlock.h>
#include <linux/mutex.h>
#include <uapi/linux/loop.h>
#include <linux/fs.h>
#include <linux/module.h>
#include <linux/moduleparam.h>
#include <linux/sched.h>
#include <linux/pagemap.h>
#include <linux/file.h>
#include <linux/stat.h>
#include <linux/errno.h>
#include <linux/major.h>
#include <linux/wait.h>
#include <linux/blkpg.h>
#include <linux/init.h>
#include <linux/swap.h>
#include <linux/slab.h>
#include <linux/compat.h>
#include <linux/suspend.h>
#include <linux/freezer.h>
#include <linux/mutex.h>
#include <linux/writeback.h>
#include <linux/completion.h>
#include <linux/highmem.h>
#include <linux/splice.h>
#include <linux/sysfs.h>
#include <linux/miscdevice.h>
#include <linux/falloc.h>
#include <linux/uio.h>
#include <linux/ioprio.h>
#include <linux/blk-cgroup.h>
#include <linux/sched/mm.h>
#include <linux/statfs.h>
#include <linux/delay.h>
#include <linux/workqueue.h>
#include <linux/uaccess.h>


#include <scsi/scsi.h>
#include <scsi/scsi_host.h>
#include <scsi/scsi_device.h>
#include <scsi/scsi_driver.h>

#define DRIVER_NAME "mail_loop"

//выводит структурированные логи
//смотрится как магия но работает (?^o^)???
#define LOG(level,fmt, a...)									\
	do {								   			\
				printk(level"["DRIVER_NAME "]: |%s| "fmt, __func__, ## a);	\
	} while (0)


/* Possible states of device */
enum {
	Lo_unbound,
	Lo_bound,
	Lo_rundown,
	Lo_deleting,
};

struct loop_func_table;

struct loop_device {
	int		lo_number;
	atomic_t	lo_refcnt;
	loff_t		lo_offset;
	loff_t		lo_sizelimit;
	int		lo_flags;
	int		(*transfer)(struct loop_device *, int cmd,
				    struct page *raw_page, unsigned raw_off,
				    struct page *loop_page, unsigned loop_off,
				    int size, sector_t real_block);
	char		lo_file_name[LO_NAME_SIZE];
	char		lo_crypt_name[LO_NAME_SIZE];
	char		lo_encrypt_key[LO_KEY_SIZE];
	int		lo_encrypt_key_size;
	struct loop_func_table *lo_encryption;
	__u32           lo_init[2];
	kuid_t		lo_key_owner;	/* Who set the key */
	int		(*ioctl)(struct loop_device *, int cmd, 
				 unsigned long arg); 

	struct file *	lo_backing_file;
	struct block_device *lo_device;
	void		*key_data; 

	gfp_t		old_gfp_mask;

	spinlock_t		lo_lock;
	int			lo_state;
	spinlock_t              lo_work_lock;
	struct workqueue_struct *workqueue;
	struct work_struct      rootcg_work;
	struct list_head        rootcg_cmd_list;
	struct list_head        idle_worker_list;
	struct rb_root          worker_tree;
	struct timer_list       timer;
	bool			use_dio;
	bool			sysfs_inited;

	struct request_queue	*lo_queue;
	struct blk_mq_tag_set	tag_set;
	struct gendisk		*lo_disk;
	struct mutex		lo_mutex;
	bool			idr_visible;
};

struct loop_cmd {
	struct list_head list_entry;
	bool use_aio; /* use AIO interface to handle I/O */
	atomic_t ref; /* only for aio */
	long ret;
	struct kiocb iocb;
	struct bio_vec *bvec;
	struct cgroup_subsys_state *blkcg_css;
	struct cgroup_subsys_state *memcg_css;
};

/* Support for loadable transfer modules */
struct loop_func_table {
	int number;	/* filter type */ 
	int (*transfer)(struct loop_device *lo, int cmd,
			struct page *raw_page, unsigned raw_off,
			struct page *loop_page, unsigned loop_off,
			int size, sector_t real_block);
	int (*init)(struct loop_device *, const struct loop_info64 *); 
	/* release is called from loop_unregister_transfer or clr_fd */
	int (*release)(struct loop_device *); 
	int (*ioctl)(struct loop_device *, int cmd, unsigned long arg);
	struct module *owner;
}; 

int loop_register_transfer(struct loop_func_table *funcs);
int loop_unregister_transfer(int number); 


#define LO_CRYPT_NONE           0
#define LO_CRYPT_XOR            1
#define LO_CRYPT_DES            2
#define LO_CRYPT_FISH2          3    /* Twofish encryption */
#define LO_CRYPT_BLOW           4
#define LO_CRYPT_CAST128        5
#define LO_CRYPT_IDEA           6
#define LO_CRYPT_DUMMY          9
#define LO_CRYPT_SKIPJACK       10
#define LO_CRYPT_CRYPTOAPI      18
#define MAX_LO_CRYPT            20


struct __control_part_crypt
{
	u32 flag;
};

extern struct __control_part_crypt control_part_crypt;
extern int major_my_blk_loop;



extern int max_loop;

extern struct idr loop_index_idr;
extern struct mutex loop_ctl_mutex;
extern struct mutex loop_validate_mutex;

extern u8 CIPHER_KEY;

extern int max_part;
extern int part_shift;
//extern struct loop_func_table none_funcs;
//extern struct loop_func_table xor_funcs;
//extern struct loop_func_table *xfer_funcs[MAX_LO_CRYPT];


// check part
extern bool is_check_disk;
extern int check_encrypt_part(char* buffer_zero_sector, unsigned offset, size_t size);


#define LOOP_IDLE_WORKER_TIMEOUT (60 * HZ)


// functions

// blk funcs
extern int xor_init(struct loop_device *lo, const struct loop_info64 *info);
extern int transfer_xor(struct loop_device *lo, int cmd,struct page *raw_page, unsigned raw_off,struct page *loop_page, unsigned loop_off,int size, sector_t real_block);
extern void __loop_update_dio(struct loop_device *lo, bool dio);
extern void loop_set_size(struct loop_device *lo, loff_t size);
extern int lo_do_transfer(struct loop_device *lo, int cmd, struct page *rpage, unsigned roffs, struct page *lpage, unsigned loffs, int size, sector_t rblock);
extern int lo_write_bvec(struct file *file, struct bio_vec *bvec, loff_t *ppos);
extern int lo_write_transfer(struct loop_device *lo, struct request *rq, loff_t pos);
extern int lo_write_simple(struct loop_device *lo, struct request *rq, loff_t pos);
extern int lo_read_transfer(struct loop_device *lo, struct request *rq, loff_t pos);
extern int lo_read_simple(struct loop_device *lo, struct request *rq, loff_t pos);
extern int lo_fallocate(struct loop_device *lo, struct request *rq, loff_t pos, int mode);
extern int loop_register_transfer(struct loop_func_table *funcs);
extern int loop_unregister_transfer(int number);
extern int loop_release_xfer(struct loop_device *lo);
extern int loop_init_xfer(struct loop_device *lo, struct loop_func_table *xfer, const struct loop_info64 *i);
extern int lo_req_flush(struct loop_device *lo, struct request *rq);
extern void lo_rw_aio_do_completion(struct loop_cmd *cmd);
extern void lo_rw_aio_complete(struct kiocb *iocb, long ret, long ret2);
extern int lo_rw_aio(struct loop_device *lo, struct loop_cmd *cmd, loff_t pos, bool rw);
extern int do_req_filebacked(struct loop_device *lo, struct request *rq);
extern void loop_update_dio(struct loop_device *lo);


// loop_cfg
extern int loop_configure(struct loop_device *lo, fmode_t mode,  struct block_device *bdev, struct file* file, const struct loop_config *config);
extern int __loop_clr_fd(struct loop_device *lo, bool release);
extern int loop_clr_fd(struct loop_device *lo);

// fops_loop

extern int lo_simple_ioctl(struct loop_device *lo, unsigned int cmd, unsigned long arg);
extern int lo_ioctl(struct block_device *bdev, fmode_t mode, unsigned int cmd, unsigned long arg);
#ifdef CONFIG_COMPAT

	struct compat_loop_info
		{
			compat_int_t	lo_number;      /* ioctl r/o */
			compat_dev_t	lo_device;      /* ioctl r/o */
			compat_ulong_t	lo_inode;       /* ioctl r/o */
			compat_dev_t	lo_rdevice;     /* ioctl r/o */
			compat_int_t	lo_offset;
			compat_int_t	lo_encrypt_type;
			compat_int_t	lo_encrypt_key_size;    /* ioctl w/o */
			compat_int_t	lo_flags;       /* ioctl r/o */
			char		lo_name[LO_NAME_SIZE];
			unsigned char	lo_encrypt_key[LO_KEY_SIZE]; /* ioctl w/o */
			compat_ulong_t	lo_init[2];
			char		reserved[4];
		};
	extern noinline int loop_info64_from_compat(const struct compat_loop_info __user *arg, struct loop_info64 *info64);
	extern noinline int loop_info64_to_compat(const struct loop_info64 *info64, struct compat_loop_info __user *arg);
	extern int loop_set_status_compat(struct loop_device *lo, const struct compat_loop_info __user *arg);
	extern int loop_get_status_compat(struct loop_device *lo, struct compat_loop_info __user *arg);
	extern int lo_compat_ioctl(struct block_device *bdev, fmode_t mode, unsigned int cmd, unsigned long arg);
#endif

extern int lo_open(struct block_device *bdev, fmode_t mode);
extern void lo_release(struct gendisk *disk, fmode_t mode);



extern int loop_add(int i);
extern void loop_remove(struct loop_device *lo);
extern void loop_probe_cipher(dev_t dev);
extern int loop_control_remove(int idx);
extern int loop_control_get_free(int idx);
extern long loop_control_ioctl(struct file *file, unsigned int cmd, unsigned long parm);
//extern struct file_operations loop_ctl_fops;
extern struct miscdevice loop_misc;
extern void lo_complete_rq(struct request *rq);
extern blk_status_t loop_queue_rq(struct blk_mq_hw_ctx *hctx, const struct blk_mq_queue_data *bd);
extern void loop_handle_cmd(struct loop_cmd *cmd);
//extern struct blk_mq_ops loop_mq_ops;
extern int loop_set_status(struct loop_device *lo, const struct loop_info64 *info);
extern int loop_get_status(struct loop_device *lo, struct loop_info64 *info);
extern void loop_info64_from_old(const struct loop_info *info, struct loop_info64 *info64);
extern int loop_info64_to_old(const struct loop_info64 *info64, struct loop_info *info);
extern int loop_set_status_old(struct loop_device *lo, const struct loop_info __user *arg);
extern int loop_set_status64(struct loop_device *lo, const struct loop_info64 __user *arg);
extern int loop_get_status_old(struct loop_device *lo, struct loop_info __user *arg);
extern int loop_get_status64(struct loop_device *lo, struct loop_info64 __user *arg);
extern int loop_set_capacity(struct loop_device *lo);
extern int loop_set_dio(struct loop_device *lo, unsigned long arg);
extern int loop_set_block_size(struct loop_device *lo, unsigned long arg);
extern int loop_change_fd(struct loop_device *lo, struct block_device *bdev, unsigned int arg);
extern int loop_set_status_from_info(struct loop_device *lo, const struct loop_info64 *info);

// lock_down_blkdev
extern void notifier_init(struct work_struct* work);
extern void set_other_devices_readonly_whitelist(struct work_struct* work);

// sysfs_loop
extern ssize_t loop_attr_backing_file_show(struct loop_device *lo, char *buf);
extern ssize_t loop_attr_offset_show(struct loop_device *lo, char *buf);
extern ssize_t loop_attr_sizelimit_show(struct loop_device *lo, char *buf);
extern ssize_t loop_attr_autoclear_show(struct loop_device *lo, char *buf);
extern ssize_t loop_attr_partscan_show(struct loop_device *lo, char *buf);
extern ssize_t loop_attr_dio_show(struct loop_device *lo, char *buf);

extern const struct attribute_group loop_attribute_group;

extern void loop_sysfs_init(struct loop_device *lo);
extern void loop_sysfs_exit(struct loop_device *lo);

// utils
struct loop_worker
{
	struct rb_node rb_node;
	struct work_struct work;
	struct list_head cmd_list;
	struct list_head idle_list;
	struct loop_device *lo;
	struct cgroup_subsys_state *blkcg_css;
	unsigned long last_ran_at;
};

extern void filter_print_buff(char *input, int length);
extern int loop_global_lock_killable(struct loop_device *lo, bool global);
extern void loop_global_unlock(struct loop_device *lo, bool global);
extern loff_t get_size(loff_t offset, loff_t sizelimit, struct file *file);
extern loff_t get_loop_size(struct loop_device *lo, struct file *file);
extern void loop_reread_partitions(struct loop_device *lo);
extern int is_loop_device(struct file *file);
extern int loop_validate_file(struct file *file, struct block_device *bdev);
extern void loop_config_discard(struct loop_device *lo);
extern void loop_update_rotational(struct loop_device *lo);

// workers
extern void loop_workfn(struct work_struct *work);
extern void loop_rootcg_workfn(struct work_struct *work);
extern void loop_free_idle_workers(struct timer_list *timer);
extern void loop_set_timer(struct loop_device *lo);
extern void loop_process_work(struct loop_worker *worker, struct list_head *cmd_list, struct loop_device *lo);
extern void loop_queue_work(struct loop_device *lo, struct loop_cmd *cmd);


#endif // _LINUX_LOOP_H
