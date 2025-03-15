/*
 * Lab 2 for UNIX programming course
 * by Leaf Ying <leaf.ying.work@gmail.com>
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
#include <linux/minmax.h> // min

#include "cryptomod.h"

#define MAX_DATA_SIZE 1024

struct Counter {
    size_t read_bytes;
    size_t write_bytes;
    size_t frequency[256];
};

struct PrivateData {
    // struct crypto_cipher *tfm;
    bool finalized;
    enum CryptoMode c_mode;
    enum IOMode io_mode;

    char *key;
    int key_len;
    char *input_data;
    size_t input_data_len;
    char *output_data;
    size_t output_data_len;
};

static dev_t devnum;
static struct cdev c_dev;
static struct class *clazz;

static struct Counter counter = {0};
DEFINE_MUTEX(write_lock);
DEFINE_MUTEX(read_lock);

static void cryptomod_dev_free(struct PrivateData **privp)
{
    struct PrivateData *priv = *privp;
    if (priv == NULL)
    {
        return;
    }

    kfree(priv->key);
    kfree(priv->input_data);
    kfree(priv->output_data);
    kfree(priv);
    *privp = NULL;
}

static long cryptomod_dev_crypto_operation(
    int (*operation)(struct skcipher_request *req),
    char *input_data, char *output_data, size_t data_len,
    char *key, size_t key_len
)
{
    struct crypto_skcipher *tfm = NULL;
    struct skcipher_request *req = NULL;
    struct scatterlist input_sg, output_sg;
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
        pr_err("Error allocating request: %d\n", err);
        goto out;
    }

    /*
     * Encrypt the data.
     *
     * For simplicity, in this example we wait for the request to complete
     * before proceeding, even if the underlying implementation is asynchronous.
     *
     */
    sg_init_one(&input_sg, input_data, data_len); // You need to make sure that data size is mutiple of block size
    sg_init_one(&output_sg, output_data, data_len);
    skcipher_request_set_callback(req, CRYPTO_TFM_REQ_MAY_BACKLOG |
                                       CRYPTO_TFM_REQ_MAY_SLEEP,
                                  crypto_req_done, &wait);
    skcipher_request_set_crypt(req, &input_sg, &output_sg, data_len, NULL);
    err = crypto_wait_req(operation(req), &wait);
    if (err) {
        pr_err("Error encrypting/decrypting data: %d\n", err);
        goto out;
    }

    pr_info("Encryption/Decryption was successful\n");
out:
    skcipher_request_free(req);
    crypto_free_skcipher(tfm);
    return err;
}

static long cryptomod_dev_crypto_encrypt(struct PrivateData *priv)
{
    size_t data_len = priv->input_data_len;

    if (priv->finalized)
    {
        // apply padding (encryption)
        // 1. if it is not a multiple of CM_BLOCK_SIZE, add paddings.
        // Pad with a value equal to the total number of padding bytes added
        // 2. if it is a multiple of CM_BLOCK_SIZE, add an entire block of padding.
        // Pad with a value equal to CM_BLOCK_SIZE
        size_t num_paddings = CM_BLOCK_SIZE - (data_len % CM_BLOCK_SIZE);
        memset(priv->input_data + data_len, num_paddings, num_paddings);
        data_len += num_paddings;
    }

    // TODO: validate the data size is a multiple of CM_BLOCK_SIZE.

    // encrypt the data
    long error = cryptomod_dev_crypto_operation(
        crypto_skcipher_encrypt,
        priv->input_data,
        priv->output_data,
        data_len,
        priv->key,
        priv->key_len
    );
    if (error)
    {
        return error;
    }

    // update the length of data buffers
    priv->output_data_len = data_len;
    priv->input_data_len = 0;
    return 0;
}

static long cryptomod_dev_crypto_decrypt(struct PrivateData *priv)
{
    size_t data_len = priv->input_data_len;
    // validate the data size is a multiple of CM_BLOCK_SIZE
    if (data_len % CM_BLOCK_SIZE != 0)
    {
        pr_err("Error decrypting data: the data size is not a multiple of block size\n");
        return -EINVAL;
    }

    // decrypt the data
    long error = cryptomod_dev_crypto_operation(
        crypto_skcipher_decrypt,
        priv->input_data,
        priv->output_data,
        data_len,
        priv->key,
        priv->key_len
    );
    if (error)
    {
        return error;
    }

    // validate paddings
    size_t num_paddings = priv->output_data[data_len - 1];
    if (num_paddings > CM_BLOCK_SIZE)
    {
        pr_err("Error validating paddings: number of paddings is invalid.\n");
        return -EINVAL;
    }
    for (size_t i = 2; i <= num_paddings; i++)
    {
        if (priv->output_data[data_len - i] != num_paddings)
        {
            pr_err("Error validating paddings: padding is mismatched.\n");
            return -EINVAL;
        }
    }

    // remove paddings (decryption)
    data_len -= num_paddings;

    // update the length of data buffers
    priv->output_data_len = data_len;
    priv->input_data_len = 0;
    return 0;
}

static long cryptomod_dev_crypto(struct PrivateData *priv)
{
    long status;
    switch (priv->c_mode)
    {
    case ENC:
        status = cryptomod_dev_crypto_encrypt(priv);
        break;
    case DEC:
        status = cryptomod_dev_crypto_decrypt(priv);
        break;
    default:
        status = -EINVAL;
        break;
    }
    return status;
}

static int cryptomod_dev_open(struct inode *i, struct file *f)
{
    pr_info("cryptomod: device opened.\n");
    return 0;
}

static int cryptomod_dev_close(struct inode *i, struct file *f)
{
    cryptomod_dev_free((struct PrivateData **)&f->private_data);
    pr_info("cryptomod: device closed.\n");
    return 0;
}

static ssize_t cryptomod_dev_read(struct file *fp, char __user *buf, size_t len,
                                 loff_t *off)
{
    struct PrivateData *priv = (struct PrivateData *)fp->private_data;
    if (priv == NULL)
    {
        return -EINVAL;
    }

    size_t read_len = umin(priv->output_data_len, len);
    if (read_len == 0)
    {
        return priv->finalized ? 0 : -EAGAIN;
    }

    if (copy_to_user(buf, priv->output_data, read_len))
    {
        return -EBUSY;
    }
    priv->output_data_len -= read_len;

    pr_info("cryptomod: read %zu/%zu bytes, %zu bytes left.\n", read_len, len, priv->output_data_len);
    mutex_lock(&read_lock);
    counter.read_bytes += read_len;
    mutex_unlock(&read_lock);
    if (priv->c_mode == ENC)
    {
        mutex_lock(&read_lock);
        for (size_t i = 0; i < read_len; i++)
        {
            counter.frequency[(size_t)*(priv->output_data + i)] += 1;
        }
        mutex_unlock(&read_lock);
    }

    // move the output data forward (may have overlap)
    memmove(priv->output_data, priv->output_data + read_len, priv->output_data_len);
    return read_len;
}

static ssize_t cryptomod_dev_write(struct file *fp, const char __user *buf,
                                  size_t len, loff_t *off)
{
    struct PrivateData *priv = (struct PrivateData *)fp->private_data;
    if (priv == NULL || priv->finalized)
    {
        return -EINVAL;
    }

    // calculate offset and length
    size_t offset = priv->input_data_len;
    size_t write_len = umin(MAX_DATA_SIZE - offset, len);
    if (write_len == 0)
    {
        return -EAGAIN;
    }

    // store the data
    if (copy_from_user(priv->input_data + offset, buf, write_len))
    {
        return -EBUSY;
    }
    priv->input_data_len += write_len;

    pr_info("cryptomod: write %zu/%zu bytes @ %zu.\n", write_len, len, offset);
    mutex_lock(&write_lock);
    counter.write_bytes += write_len;
    mutex_unlock(&write_lock);

    // TODO: ADV mode
    // if there is a complete block in input data buffer, perform encryption/decryption.
    if (priv->io_mode == ADV && priv->input_data_len >= CM_BLOCK_SIZE)
    {
        pr_info("cryptomod: perform crypto %zu/%zu bytes.\n", priv->input_data_len - (priv->input_data_len % 16), priv->input_data_len);
        long status = cryptomod_dev_crypto(priv);
        if (status)
        {
            return status;
        }
    }
    return write_len;
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

    // release previous data if exists
    cryptomod_dev_free((struct PrivateData **)&fp->private_data);

    // save configurations
    struct PrivateData *priv = kmalloc(sizeof(struct PrivateData), GFP_KERNEL);
    priv->finalized = false;
    priv->c_mode = setup.c_mode;
    priv->io_mode = setup.io_mode;

    // copy key from user-space buffer
    priv->key = kmalloc(setup.key_len, GFP_KERNEL);
    memcpy(priv->key, setup.key, setup.key_len);
    priv->key_len = setup.key_len;

    // initialize data buffer with data size + a block size for padding
    // TODO: check menory allocation doc
    priv->input_data = kzalloc(MAX_DATA_SIZE + CM_BLOCK_SIZE, GFP_KERNEL);
    priv->input_data_len = 0;
    priv->output_data = kzalloc(MAX_DATA_SIZE + CM_BLOCK_SIZE, GFP_KERNEL);
    priv->output_data_len = 0;

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

    priv->finalized = true;
    long status = cryptomod_dev_crypto(priv);
    if (status)
    {
        priv->finalized = false;
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
    priv->input_data_len = 0;
    priv->output_data_len = 0;
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
        pr_info("cryptomod: CM_IOC_SETUP\n");
        status = cryptomod_dev_ioctl_setup(fp, (struct CryptoSetup *)arg);
        break;
    case CM_IOC_FINALIZE:
        pr_info("cryptomod: CM_IOC_FINALIZE\n");
        status = cryptomod_dev_ioctl_finalize(fp);
        break;
    case CM_IOC_CLEANUP:
        pr_info("cryptomod: CM_IOC_CLEANUP\n");
        status = cryptomod_dev_ioctl_cleanup(fp);
        break;
    case CM_IOC_CNT_RST:
        pr_info("cryptomod: CM_IOC_CNT_RST\n");
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
