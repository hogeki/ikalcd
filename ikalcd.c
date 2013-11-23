/*
 * USB Skeleton driver - 2.2
 *
 * Copyright (C) 2001-2004 Greg Kroah-Hartman (greg@kroah.com)
 *
 *	This program is free software; you can redistribute it and/or
 *	modify it under the terms of the GNU General Public License as
 *	published by the Free Software Foundation, version 2.
 *
 * This driver is based on the 2.6.3 version of drivers/usb/usb-skeleton.c
 * but has been rewritten to be easier to read and use.
 *
 */

#include <linux/kernel.h>
#include <linux/errno.h>
#include <linux/init.h>
#include <linux/slab.h>
#include <linux/module.h>
#include <linux/kref.h>
#include <linux/uaccess.h>
#include <linux/usb.h>
#include <linux/mutex.h>


/* Define these values to match your devices */
#define USB_IKALCD_VENDOR_ID	0x16c0
#define USB_IKALCD_PRODUCT_ID	0x05df

/* table of devices that work with this driver */
static const struct usb_device_id ikalcd_table[] = {
	{ USB_DEVICE(USB_IKALCD_VENDOR_ID, USB_IKALCD_PRODUCT_ID) },
	{ }					/* Terminating entry */
};
MODULE_DEVICE_TABLE(usb, ikalcd_table);


/* Get a minor range for your devices from the usb maintainer */
#define USB_IKALCD_MINOR_BASE	192

/* our private defines. if this grows any larger, use your own .h file */
#define MAX_TRANSFER		(PAGE_SIZE - 512)
/* MAX_TRANSFER is chosen so that the VM is not stressed by
   allocations > PAGE_SIZE and the number of packets in a page
   is an integer 512 is the largest possible packet on EHCI */
#define WRITES_IN_FLIGHT	8
/* arbitrarily chosen */

#define LCD_COMMAND_SIZE 12

/* Structure to hold all of our device specific stuff */
struct usb_ikalcd {
	struct usb_device	*udev;			/* the usb device for this device */
	struct usb_interface	*interface;		/* the interface for this device */
	struct semaphore	limit_sem;		/* limiting the number of writes in progress */
	struct usb_anchor	submitted;		/* in case we need to retract our submissions */
	int			errors;			/* the last request tanked */
	spinlock_t		err_lock;		/* lock for errors */
	struct kref		kref;
	struct mutex		io_mutex;		/* synchronize I/O with disconnect */
};
#define to_ikalcd_dev(d) container_of(d, struct usb_ikalcd, kref)

static struct usb_driver ikalcd_driver;
static void ikalcd_draw_down(struct usb_ikalcd *dev);

static void ikalcd_delete(struct kref *kref)
{
	struct usb_ikalcd *dev = to_ikalcd_dev(kref);

	usb_put_dev(dev->udev);
	kfree(dev);
}

static int ikalcd_open(struct inode *inode, struct file *file)
{
	struct usb_ikalcd *dev;
	struct usb_interface *interface;
	int subminor;
	int retval = 0;

	subminor = iminor(inode);

	interface = usb_find_interface(&ikalcd_driver, subminor);
	if (!interface) {
		pr_err("%s - error, can't find device for minor %d\n",
			__func__, subminor);
		retval = -ENODEV;
		goto exit;
	}

	dev = usb_get_intfdata(interface);
	if (!dev) {
		retval = -ENODEV;
		goto exit;
	}

	retval = usb_autopm_get_interface(interface);
	if (retval)
		goto exit;

	/* increment our usage count for the device */
	kref_get(&dev->kref);

	/* save our object in the file's private structure */
	file->private_data = dev;

exit:
	return retval;
}

static int ikalcd_release(struct inode *inode, struct file *file)
{
	struct usb_ikalcd *dev;

	dev = file->private_data;
	if (dev == NULL)
		return -ENODEV;

	/* allow the device to be autosuspended */
	mutex_lock(&dev->io_mutex);
	if (dev->interface)
		usb_autopm_put_interface(dev->interface);
	mutex_unlock(&dev->io_mutex);

	/* decrement the count on our device */
	kref_put(&dev->kref, ikalcd_delete);
	return 0;
}

static int ikalcd_flush(struct file *file, fl_owner_t id)
{
	struct usb_ikalcd *dev;
	int res;

	dev = file->private_data;
	if (dev == NULL)
		return -ENODEV;

	/* wait for io to stop */
	mutex_lock(&dev->io_mutex);
	ikalcd_draw_down(dev);

	/* read out errors, leave subsequent opens a clean slate */
	spin_lock_irq(&dev->err_lock);
	res = dev->errors ? (dev->errors == -EPIPE ? -EPIPE : -EIO) : 0;
	dev->errors = 0;
	spin_unlock_irq(&dev->err_lock);

	mutex_unlock(&dev->io_mutex);

	return res;
}

static ssize_t ikalcd_read(struct file *file, char *buffer, size_t count,
			 loff_t *ppos)
{
	return 0;
}

static void ikalcd_write_control_callback(struct urb *urb)
{
	struct usb_ikalcd *dev;

	dev = urb->context;

	/* sync/async unlink faults aren't errors */
	if (urb->status) {
		if (!(urb->status == -ENOENT ||
		    urb->status == -ECONNRESET ||
		    urb->status == -ESHUTDOWN))
			dev_err(&dev->interface->dev,
				"%s - nonzero write bulk status received: %d\n",
				__func__, urb->status);

		spin_lock(&dev->err_lock);
		dev->errors = urb->status;
		spin_unlock(&dev->err_lock);
	}

	/* free up our allocated buffer */
	/*
	usb_free_coherent(urb->dev, urb->transfer_buffer_length,
			  urb->transfer_buffer, urb->transfer_dma);
	*/
	kfree(urb->transfer_buffer);
	kfree(urb->setup_packet);
	up(&dev->limit_sem);
}

static ssize_t ikalcd_write(struct file *file, const char *user_buffer,
			  size_t count, loff_t *ppos)
{
	struct usb_ikalcd *dev;
	int retval = 0;
	struct urb *urb = NULL;
	char *buf = NULL;
	struct usb_ctrlrequest *cr;
	size_t writesize = min(count, (size_t)LCD_COMMAND_SIZE);
	int i;

	dev = file->private_data;

	/* verify that we actually have some data to write */
	if (count == 0)
		goto exit;

	/*
	 * limit the number of URBs in flight to stop a user from using up all
	 * RAM
	 */
	if (!(file->f_flags & O_NONBLOCK)) {
		if (down_interruptible(&dev->limit_sem)) {
			retval = -ERESTARTSYS;
			goto exit;
		}
	} else {
		if (down_trylock(&dev->limit_sem)) {
			retval = -EAGAIN;
			goto exit;
		}
	}

	spin_lock_irq(&dev->err_lock);
	retval = dev->errors;
	if (retval < 0) {
		/* any error is reported once */
		dev->errors = 0;
		/* to preserve notifications about reset */
		retval = (retval == -EPIPE) ? retval : -EIO;
	}
	spin_unlock_irq(&dev->err_lock);
	if (retval < 0)
		goto error;

	/* create a urb, and a buffer for it, and copy the data to the urb */
	urb = usb_alloc_urb(0, GFP_KERNEL);
	if (!urb) {
		retval = -ENOMEM;
		goto error;
	}

	/*
	buf = usb_alloc_coherent(dev->udev, writesize, GFP_KERNEL,
				 &urb->transfer_dma);
	*/
	buf = kmalloc(LCD_COMMAND_SIZE, GFP_KERNEL);
	if (!buf) {
		retval = -ENOMEM;
		goto error;
	}
	cr = kmalloc(sizeof(struct usb_ctrlrequest), GFP_KERNEL);
	if (!cr) {
		retval = -ENOMEM;
		goto error;
	}

	for (i=0; i<LCD_COMMAND_SIZE; i++)
		buf[i] = 0x11;
	if (copy_from_user(buf, user_buffer, writesize)) {
		retval = -EFAULT;
		goto error;
	}

	/* this lock makes sure we don't submit URBs to gone devices */
	mutex_lock(&dev->io_mutex);
	if (!dev->interface) {		/* disconnect() was called */
		mutex_unlock(&dev->io_mutex);
		retval = -ENODEV;
		goto error;
	}

	cr->bRequestType = USB_TYPE_CLASS | USB_RECIP_INTERFACE;
	cr->bRequest = 0x09;
	cr->wValue = cpu_to_le16(0x300);
	cr->wIndex = cpu_to_le16(dev->interface->cur_altsetting->desc.bInterfaceNumber);
	cr->wLength = cpu_to_le16(LCD_COMMAND_SIZE);
	/* initialize the urb properly */
	/*
	usb_fill_bulk_urb(urb, dev->udev,
			  usb_sndbulkpipe(dev->udev, dev->bulk_out_endpointAddr),
			  buf, writesize, ikalcd_write_bulk_callback, dev);
	urb->transfer_flags |= URB_NO_TRANSFER_DMA_MAP;
	*/
	usb_fill_control_urb(urb, dev->udev, usb_sndctrlpipe(dev->udev, 0),
			     (unsigned char*)cr, (void*)buf, LCD_COMMAND_SIZE,
			     ikalcd_write_control_callback, dev);
	usb_anchor_urb(urb, &dev->submitted);

	/* send the data out the bulk port */
	retval = usb_submit_urb(urb, GFP_KERNEL);
	mutex_unlock(&dev->io_mutex);
	if (retval) {
		dev_err(&dev->interface->dev,
			"%s - failed submitting write urb, error %d\n",
			__func__, retval);
		goto error_unanchor;
	}

	/*
	 * release our reference to this urb, the USB core will eventually free
	 * it entirely
	 */
	usb_free_urb(urb);


	return writesize;

error_unanchor:
	usb_unanchor_urb(urb);
error:
	if (urb) {
		usb_free_coherent(dev->udev, writesize, buf, urb->transfer_dma);
		usb_free_urb(urb);
	}
	up(&dev->limit_sem);

exit:
	return retval;
}

static const struct file_operations ikalcd_fops = {
	.owner =	THIS_MODULE,
	.read =		ikalcd_read,
	.write =	ikalcd_write,
	.open =		ikalcd_open,
	.release =	ikalcd_release,
	.flush =	ikalcd_flush,
	.llseek =	noop_llseek,
};

/*
 * usb class driver info in order to get a minor number from the usb core,
 * and to have the device registered with the driver core
 */
static struct usb_class_driver ikalcd_class = {
	.name =		"ikalcd%d",
	.fops =		&ikalcd_fops,
	.minor_base =	USB_IKALCD_MINOR_BASE,
};

static int ikalcd_probe(struct usb_interface *interface,
		      const struct usb_device_id *id)
{
	struct usb_ikalcd *dev;
	int retval = -ENOMEM;

	/* allocate memory for our device state and initialize it */
	dev = kzalloc(sizeof(*dev), GFP_KERNEL);
	if (!dev) {
		dev_err(&interface->dev, "Out of memory\n");
		goto error;
	}
	kref_init(&dev->kref);
	sema_init(&dev->limit_sem, WRITES_IN_FLIGHT);
	mutex_init(&dev->io_mutex);
	spin_lock_init(&dev->err_lock);
	init_usb_anchor(&dev->submitted);

	dev->udev = usb_get_dev(interface_to_usbdev(interface));
	dev->interface = interface;

	/* save our data pointer in this interface device */
	usb_set_intfdata(interface, dev);

	/* we can register the device now, as it is ready */
	retval = usb_register_dev(interface, &ikalcd_class);
	if (retval) {
		/* something prevented us from registering this driver */
		dev_err(&interface->dev,
			"Not able to get a minor for this device.\n");
		usb_set_intfdata(interface, NULL);
		goto error;
	}

	/* let the user know what node this device is now attached to */
	dev_info(&interface->dev,
		 "USB Skeleton device now attached to USBSkel-%d",
		 interface->minor);

	return 0;

error:
	if (dev)
		/* this frees allocated memory */
		kref_put(&dev->kref, ikalcd_delete);
	return retval;
}

static void ikalcd_disconnect(struct usb_interface *interface)
{
	struct usb_ikalcd *dev;
	int minor = interface->minor;

	dev = usb_get_intfdata(interface);
	usb_set_intfdata(interface, NULL);

	/* give back our minor */
	usb_deregister_dev(interface, &ikalcd_class);

	/* prevent more I/O from starting */
	mutex_lock(&dev->io_mutex);
	dev->interface = NULL;
	mutex_unlock(&dev->io_mutex);

	usb_kill_anchored_urbs(&dev->submitted);

	/* decrement our usage count */
	kref_put(&dev->kref, ikalcd_delete);

	dev_info(&interface->dev, "USB Skeleton #%d now disconnected", minor);
}

static void ikalcd_draw_down(struct usb_ikalcd *dev)
{
	int time;

	time = usb_wait_anchor_empty_timeout(&dev->submitted, 1000);
	if (!time)
		usb_kill_anchored_urbs(&dev->submitted);
}

static int ikalcd_suspend(struct usb_interface *intf, pm_message_t message)
{
	struct usb_ikalcd *dev = usb_get_intfdata(intf);

	if (!dev)
		return 0;
	ikalcd_draw_down(dev);
	return 0;
}

static int ikalcd_resume(struct usb_interface *intf)
{
	return 0;
}

static int ikalcd_pre_reset(struct usb_interface *intf)
{
	struct usb_ikalcd *dev = usb_get_intfdata(intf);

	mutex_lock(&dev->io_mutex);
	ikalcd_draw_down(dev);

	return 0;
}

static int ikalcd_post_reset(struct usb_interface *intf)
{
	struct usb_ikalcd *dev = usb_get_intfdata(intf);

	/* we are sure no URBs are active - no locking needed */
	dev->errors = -EPIPE;
	mutex_unlock(&dev->io_mutex);

	return 0;
}

static struct usb_driver ikalcd_driver = {
	.name =		"IKALogicLCD",
	.probe =	ikalcd_probe,
	.disconnect =	ikalcd_disconnect,
	.suspend =	ikalcd_suspend,
	.resume =	ikalcd_resume,
	.pre_reset =	ikalcd_pre_reset,
	.post_reset =	ikalcd_post_reset,
	.id_table =	ikalcd_table,
	.supports_autosuspend = 1,
};

module_usb_driver(ikalcd_driver);

MODULE_LICENSE("GPL");
