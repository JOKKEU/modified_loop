CONFIG_MODULE_SIG=n

ifeq ($(KERNELRELEASE), )
KERNELDIR := /lib/modules/$(shell uname -r)/build
PWD :=$(shell pwd)
default:
	$(MAKE) -C $(KERNELDIR)  M=$(PWD)  

else
	main_loop-y += workers.o utils.o loop_sysfs.o fops_loop.o lock_down_blkdev.o blk_io.o check_crypt.o config_loop.o main.o
	obj-m := main_loop.o
endif
