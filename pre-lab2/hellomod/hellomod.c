/*
 * Lab problem set for UNIX programming course
 * by Chun-Ying Huang <chuang@cs.nctu.edu.tw>
 * License: GPLv2
 */
#include <linux/cdev.h>
#include <linux/cred.h>  // for current_uid();
#include <linux/device.h>
#include <linux/errno.h>
#include <linux/init.h>    // included for __init and __exit macros
#include <linux/kernel.h>  // included for KERN_INFO
#include <linux/module.h>  // included for all kernel modules
#include <linux/proc_fs.h>
#include <linux/sched.h>  // task_struct requried for current_uid()
#include <linux/seq_file.h>
#include <linux/slab.h>  // for kmalloc/kfree
#include <linux/string.h>
#include <linux/uaccess.h>  // copy_to_user
#include <linux/crypto.h>

static dev_t devnum;
static struct cdev c_dev;
static struct class *clazz;

static int hellomod_dev_open(struct inode *i, struct file *f)
{
    pr_info("hellomod: device opened.\n");
    return 0;
}

static int hellomod_dev_close(struct inode *i, struct file *f)
{
    pr_info("hellomod: device closed.\n");
    return 0;
}

static ssize_t hellomod_dev_read(struct file *f, char __user *buf, size_t len,
                                 loff_t *off)
{
    pr_info("hellomod: read %zu bytes @ %llu.\n", len, *off);
    if (copy_to_user(buf, "2123", 5))
    {
        return -EFAULT;
    }
    return len;
}

static ssize_t hellomod_dev_write(struct file *f, const char __user *buf,
                                  size_t len, loff_t *off)
{
    char *kern_buf = kzalloc(len, GFP_KERNEL);
    if (copy_from_user(kern_buf, buf, len))
    {
        return -EFAULT;
    }
    pr_info("hellomod: write %zu bytes @ %llu.\n", len, *off);
    pr_info("hellomod: buffer %s.\n", kern_buf);
    kvfree(kern_buf);
    kern_buf = NULL;
    return len;
}

static long hellomod_dev_ioctl(struct file *fp, unsigned int cmd,
                               unsigned long arg)
{
    printk(KERN_INFO "hellomod: ioctl cmd=%u arg=%lu.\n", cmd, arg);
    return 0;
}

static const struct file_operations hellomod_dev_fops = {
    .owner = THIS_MODULE,
    .open = hellomod_dev_open,
    .read = hellomod_dev_read,
    .write = hellomod_dev_write,
    .unlocked_ioctl = hellomod_dev_ioctl,
    .release = hellomod_dev_close};

static int hellomod_proc_read(struct seq_file *m, void *v)
{
    char buf[] = "`hello, world!` in /proc.\n";
    seq_printf(m, buf);
    return 0;
}

static int hellomod_proc_open(struct inode *inode, struct file *file)
{
    return single_open(file, hellomod_proc_read, NULL);
}

static const struct proc_ops hellomod_proc_fops = {
    .proc_open = hellomod_proc_open,
    .proc_read = seq_read,
    .proc_lseek = seq_lseek,
    .proc_release = single_release,
};

static char *hellomod_devnode(const struct device *dev, umode_t *mode)
{
    if (mode == NULL) return NULL;
    // 0xxx <- number in octal format
    *mode = 0666;
    return NULL;
}

static int __init hellomod_init(void)
{
    // create char dev
    if (alloc_chrdev_region(&devnum, 0, 1, "updev") < 0) return -1;
    if ((clazz = class_create("upclass")) == NULL) goto release_region;
    clazz->devnode = hellomod_devnode;
    if (device_create(clazz, NULL, devnum, NULL, "hello_dev") == NULL)
        goto release_class;
    cdev_init(&c_dev, &hellomod_dev_fops);
    if (cdev_add(&c_dev, devnum, 1) == -1) goto release_device;

    // create proc
    proc_create("hello_mod", 0, NULL, &hellomod_proc_fops);

    printk(KERN_INFO "hellomod: initialized.\n");
    return 0;  // Non-zero return means that the module couldn't be loaded.

release_device:
    device_destroy(clazz, devnum);
release_class:
    class_destroy(clazz);
release_region:
    unregister_chrdev_region(devnum, 1);
    return -1;
}

static void __exit hellomod_cleanup(void)
{
    remove_proc_entry("hello_mod", NULL);

    cdev_del(&c_dev);
    device_destroy(clazz, devnum);
    class_destroy(clazz);
    unregister_chrdev_region(devnum, 1);

    printk(KERN_INFO "hellomod: cleaned up.\n");
}

module_init(hellomod_init);
module_exit(hellomod_cleanup);

MODULE_LICENSE("GPL");
MODULE_AUTHOR("Chun-Ying Huang");
MODULE_DESCRIPTION("The unix programming course demo kernel module.");
