#include "loop.h"

/* loop sysfs attributes */

ssize_t loop_attr_show(struct device *dev, char *page,
			      ssize_t (*callback)(struct loop_device *, char *))
{
	LOG(KERN_INFO, "\n");
	struct gendisk *disk = dev_to_disk(dev);
	struct loop_device *lo = disk->private_data;

	return callback(lo, page);
}

#define LOOP_ATTR_RO(_name)						\
ssize_t loop_attr_##_name##_show(struct loop_device *, char *);	\
ssize_t loop_attr_do_show_##_name(struct device *d,		\
struct device_attribute *attr, char *b)	\
{									\
	return loop_attr_show(d, b, loop_attr_##_name##_show);		\
}									\
struct device_attribute loop_attr_##_name =			\
__ATTR(_name, 0444, loop_attr_do_show_##_name, NULL);

ssize_t loop_attr_backing_file_show(struct loop_device *lo, char *buf)
{
	ssize_t ret;
	char *p = NULL;

	spin_lock_irq(&lo->lo_lock);
	if (lo->lo_backing_file)
		p = file_path(lo->lo_backing_file, buf, PAGE_SIZE - 1);
	spin_unlock_irq(&lo->lo_lock);

	if (IS_ERR_OR_NULL(p))
		ret = PTR_ERR(p);
	else {
		ret = strlen(p);
		memmove(buf, p, ret);
		buf[ret++] = '\n';
		buf[ret] = 0;
	}

	return ret;
}

ssize_t loop_attr_offset_show(struct loop_device *lo, char *buf)
{
	return sysfs_emit(buf, "%llu\n", (unsigned long long)lo->lo_offset);
}

ssize_t loop_attr_sizelimit_show(struct loop_device *lo, char *buf)
{
	return sysfs_emit(buf, "%llu\n", (unsigned long long)lo->lo_sizelimit);
}

ssize_t loop_attr_autoclear_show(struct loop_device *lo, char *buf)
{
	int autoclear = (lo->lo_flags & LO_FLAGS_AUTOCLEAR);

	return sysfs_emit(buf, "%s\n", autoclear ? "1" : "0");
}

ssize_t loop_attr_partscan_show(struct loop_device *lo, char *buf)
{
	int partscan = (lo->lo_flags & LO_FLAGS_PARTSCAN);

	return sysfs_emit(buf, "%s\n", partscan ? "1" : "0");
}

ssize_t loop_attr_dio_show(struct loop_device *lo, char *buf)
{
	int dio = (lo->lo_flags & LO_FLAGS_DIRECT_IO);

	return sysfs_emit(buf, "%s\n", dio ? "1" : "0");
}

LOOP_ATTR_RO(backing_file);
LOOP_ATTR_RO(offset);
LOOP_ATTR_RO(sizelimit);
LOOP_ATTR_RO(autoclear);
LOOP_ATTR_RO(partscan);
LOOP_ATTR_RO(dio);

struct attribute* loop_attrs[7] = {
	&loop_attr_backing_file.attr,
	&loop_attr_offset.attr,
	&loop_attr_sizelimit.attr,
	&loop_attr_autoclear.attr,
	&loop_attr_partscan.attr,
	&loop_attr_dio.attr,
	NULL,
};

const struct attribute_group loop_attribute_group  = {
	.name = "loop_jokkeu",
	.attrs= loop_attrs,
};

void loop_sysfs_init(struct loop_device *lo)
{
	lo->sysfs_inited = !sysfs_create_group(&disk_to_dev(lo->lo_disk)->kobj,
					       &loop_attribute_group);
}

void loop_sysfs_exit(struct loop_device *lo)
{
	if (lo->sysfs_inited)
		sysfs_remove_group(&disk_to_dev(lo->lo_disk)->kobj,
				   &loop_attribute_group);
}
