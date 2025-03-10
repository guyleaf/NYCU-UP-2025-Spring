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
#include <crypto/skcipher.h>
#include <linux/scatterlist.h>

#include "cryptomod.h"

#define MAX_DATA_SIZE 1024

struct Counter {
    unsigned long read_bytes;
    unsigned long write_bytes;
    unsigned long frequency[256];
};

struct PrivateData {
    // struct crypto_cipher *tfm;
    bool finalized;
    enum CryptoMode c_mode;
    enum IOMode io_mode;

    char *key;
    int key_len;
    char data[MAX_DATA_SIZE + CM_BLOCK_SIZE];
    size_t data_len;
};

static dev_t devnum;
static struct cdev c_dev;
static struct class *clazz;
static struct Counter counter;

static long cryptomod_dev_crypto_operation(int (*operation)(struct skcipher_request *req), char *data, size_t data_len, char *key, size_t key_len)
{
    struct crypto_skcipher *tfm = NULL;
    struct skcipher_request *req = NULL;
    struct scatterlist sg;
    DECLARE_CRYPTO_WAIT(wait);
    int err;

    /*
     * Allocate a tfm (a transformation object) and set the key.
     *
     * In real-world use, a tfm and key are typically used for many
     * encryption/decryption operations.  But in this example, we'll just do a
     * single encryption operation with it (which is not very efficient).
     */
    tfm = crypto_alloc_skcipher("ecb(aes)", 0, 0);
    if (IS_ERR(tfm)) {
        pr_err("Error allocating ecb(aes) handle: %ld\n", PTR_ERR(tfm));
        return PTR_ERR(tfm);
    }

    err = crypto_skcipher_setkey(tfm, key, key_len);
    if (err) {
        pr_err("Error setting key: %d\n", err);
        goto out;
    }

    /* Allocate a request object */
    req = skcipher_request_alloc(tfm, GFP_KERNEL);
    if (!req) {
        err = -ENOMEM;
        goto out;
    }

    /*
     * Encrypt the data in-place.
     *
     * For simplicity, in this example we wait for the request to complete
     * before proceeding, even if the underlying implementation is asynchronous.
     *
     * To decrypt instead of encrypt, just change crypto_skcipher_encrypt() to
     * crypto_skcipher_decrypt().
     */
    /* you also can init two scatterlists instead of inplace operation */
    sg_init_one(&sg, data, data_len); // You need to make sure that data size is mutiple of block size
    skcipher_request_set_callback(req, CRYPTO_TFM_REQ_MAY_BACKLOG |
                                       CRYPTO_TFM_REQ_MAY_SLEEP,
                                  crypto_req_done, &wait);
    skcipher_request_set_crypt(req, &sg, &sg, data_len, NULL);
    err = crypto_wait_req(operation(req), &wait);
    if (err) {
        pr_err("Error encrypting data: %d\n", err);
        goto out;
    }

    pr_debug("Encryption was successful\n");
out:
    crypto_free_skcipher(tfm);
    skcipher_request_free(req);
    return err;
}

static long cryptomod_dev_crypto_encrypt(struct PrivateData *priv)
{
    // TODO: apply padding (encryption)
    // 1. if it is not a multiple of CM_BLOCK_SIZE, add paddings.
    // Pad with a value equal to the total number of padding bytes added

    // 2. if it is a multiple of CM_BLOCK_SIZE, add an entire block of padding.
    // Pad with a value equal to CM_BLOCK_SIZE

    // TODO: perform encryption
    return 0;
}

static long cryptomod_dev_crypto_decrypt(struct PrivateData *priv)
{
    // TODO: remove padding (decryption)
    // TODO: perform decryption
    return 0;
}

static int cryptomod_dev_open(struct inode *i, struct file *f)
{
    pr_info("cryptomod: device opened.\n");
    return 0;
}

static int cryptomod_dev_close(struct inode *i, struct file *f)
{
    pr_info("cryptomod: device closed.\n");
    return 0;
}

static ssize_t cryptomod_dev_read(struct file *fp, char __user *buf, size_t len,
                                 loff_t *off)
{
    pr_info("cryptomod: read %zu bytes @ %llu.\n", len, *off);
    return len;
}

static ssize_t cryptomod_dev_write(struct file *fp, const char __user *buf,
                                  size_t len, loff_t *off)
{
    struct PrivateData *priv = (struct PrivateData *)fp->private_data;
    if (priv == NULL || priv->finalized)
    {
        return -EINVAL;
    }

    size_t left_data_size = (MAX_DATA_SIZE - priv->data_len);
    size_t processed_len = left_data_size > len ? len : left_data_size;

    if (processed_len == 0)
    {
        return -EAGAIN;
    }

    char *data = kmalloc(processed_len, GFP_KERNEL);
    if (copy_from_user(data, buf, processed_len))
    {
        return -EBUSY;
    }

    pr_info("cryptomod: write %zu bytes @ %llu.\n", len, *off);

    memmove(priv->data + priv->data_len, data, processed_len);
    priv->data_len += processed_len;

    kfree(data);
    return processed_len;
}

static long cryptomod_dev_ioctl_setup(struct file *fp, struct CryptoSetup * arg)
{
    if (arg == NULL)
    {
        return -EINVAL;
    }

    struct CryptoSetup setup;
    if (copy_from_user(&setup, arg, sizeof(struct CryptoSetup)))
    {
        return -EBUSY;
    }

    // validate arguments
    if (setup.key_len != 16 && setup.key_len != 24 && setup.key_len != 32)
    {
        return -EINVAL;
    }
    
    // store configurations
    struct PrivateData *priv = kmalloc(sizeof(struct PrivateData), GFP_KERNEL);
    priv->finalized = false;
    priv->key = kmalloc(setup.key_len, GFP_KERNEL);
    if (copy_from_user(priv->key, setup.key, setup.key_len))
    {
        return -EBUSY;
    }
    priv->key_len = setup.key_len;
    priv->c_mode = setup.c_mode;
    priv->io_mode = setup.io_mode;

    // initialize data buffer
    memset(priv->data, 0, sizeof(priv->data));
    priv->data_len = 0;

    // store private data
    if (fp->private_data != NULL)
    {
        struct PrivateData *old_priv = (struct PrivateData *)fp->private_data;
        kfree(old_priv->key);
        kfree(old_priv);
        fp->private_data = NULL;
    }
    fp->private_data = priv;

    return 0;
}

static long cryptomod_dev_ioctl_finalize(struct file *fp)
{
    struct PrivateData *priv = (struct PrivateData *)fp->private_data;
    if (priv == NULL)
    {
        return -EINVAL;
    }

    long status = 0;
    switch (priv->c_mode)
    {
    case ENC:
        status = cryptomod_dev_crypto_encrypt(priv);
        priv->finalized = true;
        break;
    case DEC:
        status = cryptomod_dev_crypto_decrypt(priv);
        priv->finalized = true;
        break;
    default:
        status = -EINVAL;
        break;
    }

    return status;
}

static long cryptomod_dev_ioctl_cleanup(struct file *fp)
{
    if (fp->private_data == NULL)
    {
        return -EINVAL;
    }

    struct PrivateData *priv = (struct PrivateData *)fp->private_data;
    priv->finalized = false;
    memset(priv->data, 0, sizeof(priv->data));
    priv->data_len = 0;
    return 0;
}

static long cryptomod_dev_ioctl_cnt_reset(void)
{
    counter.read_bytes = 0;
    counter.write_bytes = 0;
    memset(counter.frequency, 0, sizeof(counter.frequency));
    return 0;
}

static long cryptomod_dev_ioctl(struct file *fp, unsigned int cmd,
                               unsigned long arg)
{
    pr_info("cryptomod: ioctl cmd=%u arg=%lu.\n", cmd, arg);

    long status = 0;
    switch (cmd)
    {
    case CM_IOC_SETUP:
        status = cryptomod_dev_ioctl_setup(fp, (struct CryptoSetup *)arg);
        break;
    case CM_IOC_FINALIZE:
        status = cryptomod_dev_ioctl_finalize(fp);
        break;
    case CM_IOC_CLEANUP:
        status = cryptomod_dev_ioctl_cleanup(fp);
        break;
    case CM_IOC_CNT_RST:
        status = cryptomod_dev_ioctl_cnt_reset();
        break;
    default:
        status = -EINVAL;
        break;
    }

    return status;
}

static const struct file_operations cryptomod_dev_fops = {
    .owner = THIS_MODULE,
    .open = cryptomod_dev_open,
    .read = cryptomod_dev_read,
    .write = cryptomod_dev_write,
    .unlocked_ioctl = cryptomod_dev_ioctl,
    .release = cryptomod_dev_close};

static int cryptomod_proc_read(struct seq_file *m, void *v)
{
    seq_printf(m, "%lu %lu\n", counter.read_bytes, counter.write_bytes);

    for (int i = 0; i < 16; i++)
    {
        for (int j = 0; j < 16; j++)
        {
            seq_printf(m, "%lu ", counter.frequency[i * 16 + j]);
        }
        seq_printf(m, "\n");
    }

    return 0;
}

static int cryptomod_proc_open(struct inode *inode, struct file *file)
{
    return single_open(file, cryptomod_proc_read, NULL);
}

static const struct proc_ops cryptomod_proc_fops = {
    .proc_open = cryptomod_proc_open,
    .proc_read = seq_read,
    .proc_lseek = seq_lseek,
    .proc_release = single_release,
};

static char *cryptomod_devnode(const struct device *dev, umode_t *mode)
{
    if (mode == NULL) return NULL;
    // 0xxx <- number in octal format
    *mode = 0666;
    return NULL;
}

static int __init cryptomod_init(void)
{
    // create char dev
    if (alloc_chrdev_region(&devnum, 0, 1, "updev") < 0) return -1;
    if ((clazz = class_create("upclass")) == NULL) goto release_region;
    clazz->devnode = cryptomod_devnode;
    if (device_create(clazz, NULL, devnum, NULL, "cryptodev") == NULL)
        goto release_class;
    cdev_init(&c_dev, &cryptomod_dev_fops);
    if (cdev_add(&c_dev, devnum, 1) == -1) goto release_device;

    // create proc
    proc_create("cryptomod", 0, NULL, &cryptomod_proc_fops);

    pr_info("cryptomod: initialized.\n");
    return 0;  // Non-zero return means that the module couldn't be loaded.

release_device:
    device_destroy(clazz, devnum);
release_class:
    class_destroy(clazz);
release_region:
    unregister_chrdev_region(devnum, 1);
    return -1;
}

static void __exit cryptomod_cleanup(void)
{
    remove_proc_entry("cryptomod", NULL);

    cdev_del(&c_dev);
    device_destroy(clazz, devnum);
    class_destroy(clazz);
    unregister_chrdev_region(devnum, 1);

    printk(KERN_INFO "cryptomod: cleaned up.\n");
}

module_init(cryptomod_init);
module_exit(cryptomod_cleanup);

MODULE_LICENSE("GPL");
MODULE_AUTHOR("Yao-Te Ying");
MODULE_DESCRIPTION("The unix programming lab 2, Cryptomod: Encrypt and Decrypt Data Using a Kernel Module.");
