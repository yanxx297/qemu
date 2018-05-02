/*
 * QEMU USB emulation
 *
 * Copyright (c) 2005 Fabrice Bellard
 *
 * 2008 Generic packet handler rewrite by Max Krasnyansky
 *
 * Permission is hereby granted, free of charge, to any person obtaining a copy
 * of this software and associated documentation files (the "Software"), to deal
 * in the Software without restriction, including without limitation the rights
 * to use, copy, modify, merge, publish, distribute, sublicense, and/or sell
 * copies of the Software, and to permit persons to whom the Software is
 * furnished to do so, subject to the following conditions:
 *
 * The above copyright notice and this permission notice shall be included in
 * all copies or substantial portions of the Software.
 *
 * THE SOFTWARE IS PROVIDED "AS IS", WITHOUT WARRANTY OF ANY KIND, EXPRESS OR
 * IMPLIED, INCLUDING BUT NOT LIMITED TO THE WARRANTIES OF MERCHANTABILITY,
 * FITNESS FOR A PARTICULAR PURPOSE AND NONINFRINGEMENT. IN NO EVENT SHALL
 * THE AUTHORS OR COPYRIGHT HOLDERS BE LIABLE FOR ANY CLAIM, DAMAGES OR OTHER
 * LIABILITY, WHETHER IN AN ACTION OF CONTRACT, TORT OR OTHERWISE, ARISING FROM,
 * OUT OF OR IN CONNECTION WITH THE SOFTWARE OR THE USE OR OTHER DEALINGS IN
 * THE SOFTWARE.
 */
#include "qemu-common.h"
#include "usb.h"
#include "iov.h"

void usb_attach(USBPort *port)
{
    USBDevice *dev = port->dev;

    assert(dev != NULL);
    assert(dev->attached);
    assert(dev->state == USB_STATE_NOTATTACHED);
    port->ops->attach(port);
    dev->state = USB_STATE_ATTACHED;
    usb_device_handle_attach(dev);
}

void usb_detach(USBPort *port)
{
    USBDevice *dev = port->dev;

    assert(dev != NULL);
    assert(dev->state != USB_STATE_NOTATTACHED);
    port->ops->detach(port);
    dev->state = USB_STATE_NOTATTACHED;
}

void usb_reset(USBPort *port)
{
    USBDevice *dev = port->dev;

    assert(dev != NULL);
    usb_detach(port);
    usb_attach(port);
    usb_send_msg(dev, USB_MSG_RESET);
}

void usb_wakeup(USBDevice *dev)
{
    if (dev->remote_wakeup && dev->port && dev->port->ops->wakeup) {
        dev->port->ops->wakeup(dev->port);
    }
}

/**********************/

/* generic USB device helpers (you are not forced to use them when
   writing your USB device driver, but they help handling the
   protocol)
*/

#define SETUP_STATE_IDLE  0
#define SETUP_STATE_SETUP 1
#define SETUP_STATE_DATA  2
#define SETUP_STATE_ACK   3

static int do_token_setup(USBDevice *s, USBPacket *p)
{
    int request, value, index;
    int ret = 0;

    if (p->iov.size != 8) {
        return USB_RET_STALL;
    }

    usb_packet_copy(p, s->setup_buf, p->iov.size);
    s->setup_len   = (s->setup_buf[7] << 8) | s->setup_buf[6];
    s->setup_index = 0;

    request = (s->setup_buf[0] << 8) | s->setup_buf[1];
    value   = (s->setup_buf[3] << 8) | s->setup_buf[2];
    index   = (s->setup_buf[5] << 8) | s->setup_buf[4];

    if (s->setup_buf[0] & USB_DIR_IN) {
        ret = usb_device_handle_control(s, p, request, value, index,
                                        s->setup_len, s->data_buf);
        if (ret == USB_RET_ASYNC) {
             s->setup_state = SETUP_STATE_SETUP;
             return USB_RET_ASYNC;
        }
        if (ret < 0)
            return ret;

        if (ret < s->setup_len)
            s->setup_len = ret;
        s->setup_state = SETUP_STATE_DATA;
    } else {
        if (s->setup_len > sizeof(s->data_buf)) {
            fprintf(stderr,
                "usb_generic_handle_packet: ctrl buffer too small (%d > %zu)\n",
                s->setup_len, sizeof(s->data_buf));
            return USB_RET_STALL;
        }
        if (s->setup_len == 0)
            s->setup_state = SETUP_STATE_ACK;
        else
            s->setup_state = SETUP_STATE_DATA;
    }

    return ret;
}

static int do_token_in(USBDevice *s, USBPacket *p)
{
    int request, value, index;
    int ret = 0;

    if (p->devep != 0)
        return usb_device_handle_data(s, p);

    request = (s->setup_buf[0] << 8) | s->setup_buf[1];
    value   = (s->setup_buf[3] << 8) | s->setup_buf[2];
    index   = (s->setup_buf[5] << 8) | s->setup_buf[4];
 
    switch(s->setup_state) {
    case SETUP_STATE_ACK:
        if (!(s->setup_buf[0] & USB_DIR_IN)) {
            ret = usb_device_handle_control(s, p, request, value, index,
                                            s->setup_len, s->data_buf);
            if (ret == USB_RET_ASYNC) {
                return USB_RET_ASYNC;
            }
            s->setup_state = SETUP_STATE_IDLE;
            if (ret > 0)
                return 0;
            return ret;
        }

        /* return 0 byte */
        return 0;

    case SETUP_STATE_DATA:
        if (s->setup_buf[0] & USB_DIR_IN) {
            int len = s->setup_len - s->setup_index;
            if (len > p->iov.size) {
                len = p->iov.size;
            }
            usb_packet_copy(p, s->data_buf + s->setup_index, len);
            s->setup_index += len;
            if (s->setup_index >= s->setup_len)
                s->setup_state = SETUP_STATE_ACK;
            return len;
        }

        s->setup_state = SETUP_STATE_IDLE;
        return USB_RET_STALL;

    default:
        return USB_RET_STALL;
    }
}

static int do_token_out(USBDevice *s, USBPacket *p)
{
    if (p->devep != 0)
        return usb_device_handle_data(s, p);

    switch(s->setup_state) {
    case SETUP_STATE_ACK:
        if (s->setup_buf[0] & USB_DIR_IN) {
            s->setup_state = SETUP_STATE_IDLE;
            /* transfer OK */
        } else {
            /* ignore additional output */
        }
        return 0;

    case SETUP_STATE_DATA:
        if (!(s->setup_buf[0] & USB_DIR_IN)) {
            int len = s->setup_len - s->setup_index;
            if (len > p->iov.size) {
                len = p->iov.size;
            }
            usb_packet_copy(p, s->data_buf + s->setup_index, len);
            s->setup_index += len;
            if (s->setup_index >= s->setup_len)
                s->setup_state = SETUP_STATE_ACK;
            return len;
        }

        s->setup_state = SETUP_STATE_IDLE;
        return USB_RET_STALL;

    default:
        return USB_RET_STALL;
    }
}

/*
 * Generic packet handler.
 * Called by the HC (host controller).
 *
 * Returns length of the transaction or one of the USB_RET_XXX codes.
 */
int usb_generic_handle_packet(USBDevice *s, USBPacket *p)
{
    switch(p->pid) {
    case USB_MSG_RESET:
        s->remote_wakeup = 0;
        s->addr = 0;
        s->state = USB_STATE_DEFAULT;
        usb_device_handle_reset(s);
        return 0;
    }

    /* Rest of the PIDs must match our address */
    if (s->state < USB_STATE_DEFAULT || p->devaddr != s->addr)
        return USB_RET_NODEV;

    switch (p->pid) {
    case USB_TOKEN_SETUP:
        return do_token_setup(s, p);

    case USB_TOKEN_IN:
        return do_token_in(s, p);

    case USB_TOKEN_OUT:
        return do_token_out(s, p);
 
    default:
        return USB_RET_STALL;
    }
}

/* ctrl complete function for devices which use usb_generic_handle_packet and
   may return USB_RET_ASYNC from their handle_control callback. Device code
   which does this *must* call this function instead of the normal
   usb_packet_complete to complete their async control packets. */
void usb_generic_async_ctrl_complete(USBDevice *s, USBPacket *p)
{
    if (p->result < 0) {
        s->setup_state = SETUP_STATE_IDLE;
    }

    switch (s->setup_state) {
    case SETUP_STATE_SETUP:
        if (p->result < s->setup_len) {
            s->setup_len = p->result;
        }
        s->setup_state = SETUP_STATE_DATA;
        p->result = 8;
        break;

    case SETUP_STATE_ACK:
        s->setup_state = SETUP_STATE_IDLE;
        p->result = 0;
        break;

    default:
        break;
    }
    usb_packet_complete(s, p);
}

/* XXX: fix overflow */
int set_usb_string(uint8_t *buf, const char *str)
{
    int len, i;
    uint8_t *q;

    q = buf;
    len = strlen(str);
    *q++ = 2 * len + 2;
    *q++ = 3;
    for(i = 0; i < len; i++) {
        *q++ = str[i];
        *q++ = 0;
    }
    return q - buf;
}

/* Send an internal message to a USB device.  */
void usb_send_msg(USBDevice *dev, int msg)
{
    USBPacket p;
    int ret;

    memset(&p, 0, sizeof(p));
    p.pid = msg;
    ret = usb_handle_packet(dev, &p);
    /* This _must_ be synchronous */
    assert(ret != USB_RET_ASYNC);
}

/* Hand over a packet to a device for processing.  Return value
   USB_RET_ASYNC indicates the processing isn't finished yet, the
   driver will call usb_packet_complete() when done processing it. */
int usb_handle_packet(USBDevice *dev, USBPacket *p)
{
    int ret;

    assert(p->owner == NULL);
    ret = usb_device_handle_packet(dev, p);
    if (ret == USB_RET_ASYNC) {
        if (p->owner == NULL) {
            p->owner = usb_ep_get(dev, p->pid, p->devep);
        } else {
            /* We'll end up here when usb_handle_packet is called
             * recursively due to a hub being in the chain.  Nothing
             * to do.  Leave p->owner pointing to the device, not the
             * hub. */;
        }
    }
    return ret;
}

/* Notify the controller that an async packet is complete.  This should only
   be called for packets previously deferred by returning USB_RET_ASYNC from
   handle_packet. */
void usb_packet_complete(USBDevice *dev, USBPacket *p)
{
    /* Note: p->owner != dev is possible in case dev is a hub */
    assert(p->owner != NULL);
    p->owner = NULL;
    dev->port->ops->complete(dev->port, p);
}

/* Cancel an active packet.  The packed must have been deferred by
   returning USB_RET_ASYNC from handle_packet, and not yet
   completed.  */
void usb_cancel_packet(USBPacket * p)
{
    assert(p->owner != NULL);
    usb_device_cancel_packet(p->owner->dev, p);
    p->owner = NULL;
}


void usb_packet_init(USBPacket *p)
{
    qemu_iovec_init(&p->iov, 1);
}

void usb_packet_setup(USBPacket *p, int pid, uint8_t addr, uint8_t ep)
{
    p->pid = pid;
    p->devaddr = addr;
    p->devep = ep;
    p->result = 0;
    qemu_iovec_reset(&p->iov);
}

void usb_packet_addbuf(USBPacket *p, void *ptr, size_t len)
{
    qemu_iovec_add(&p->iov, ptr, len);
}

void usb_packet_copy(USBPacket *p, void *ptr, size_t bytes)
{
    assert(p->result >= 0);
    assert(p->result + bytes <= p->iov.size);
    switch (p->pid) {
    case USB_TOKEN_SETUP:
    case USB_TOKEN_OUT:
        iov_to_buf(p->iov.iov, p->iov.niov, ptr, p->result, bytes);
        break;
    case USB_TOKEN_IN:
        iov_from_buf(p->iov.iov, p->iov.niov, ptr, p->result, bytes);
        break;
    default:
        fprintf(stderr, "%s: invalid pid: %x\n", __func__, p->pid);
        abort();
    }
    p->result += bytes;
}

void usb_packet_skip(USBPacket *p, size_t bytes)
{
    assert(p->result >= 0);
    assert(p->result + bytes <= p->iov.size);
    if (p->pid == USB_TOKEN_IN) {
        iov_clear(p->iov.iov, p->iov.niov, p->result, bytes);
    }
    p->result += bytes;
}

void usb_packet_cleanup(USBPacket *p)
{
    qemu_iovec_destroy(&p->iov);
}

void usb_ep_init(USBDevice *dev)
{
    int ep;

    dev->ep_ctl.type = USB_ENDPOINT_XFER_CONTROL;
    dev->ep_ctl.ifnum = 0;
    dev->ep_ctl.dev = dev;
    for (ep = 0; ep < USB_MAX_ENDPOINTS; ep++) {
        dev->ep_in[ep].type = USB_ENDPOINT_XFER_INVALID;
        dev->ep_out[ep].type = USB_ENDPOINT_XFER_INVALID;
        dev->ep_in[ep].ifnum = 0;
        dev->ep_out[ep].ifnum = 0;
        dev->ep_in[ep].dev = dev;
        dev->ep_out[ep].dev = dev;
    }
}

void usb_ep_dump(USBDevice *dev)
{
    static const char *tname[] = {
        [USB_ENDPOINT_XFER_CONTROL] = "control",
        [USB_ENDPOINT_XFER_ISOC]    = "isoc",
        [USB_ENDPOINT_XFER_BULK]    = "bulk",
        [USB_ENDPOINT_XFER_INT]     = "int",
    };
    int ifnum, ep, first;

    fprintf(stderr, "Device \"%s\", config %d\n",
            dev->product_desc, dev->configuration);
    for (ifnum = 0; ifnum < 16; ifnum++) {
        first = 1;
        for (ep = 0; ep < USB_MAX_ENDPOINTS; ep++) {
            if (dev->ep_in[ep].type != USB_ENDPOINT_XFER_INVALID &&
                dev->ep_in[ep].ifnum == ifnum) {
                if (first) {
                    first = 0;
                    fprintf(stderr, "  Interface %d, alternative %d\n",
                            ifnum, dev->altsetting[ifnum]);
                }
                fprintf(stderr, "    Endpoint %d, IN, %s, %d max\n", ep,
                        tname[dev->ep_in[ep].type],
                        dev->ep_in[ep].max_packet_size);
            }
            if (dev->ep_out[ep].type != USB_ENDPOINT_XFER_INVALID &&
                dev->ep_out[ep].ifnum == ifnum) {
                if (first) {
                    first = 0;
                    fprintf(stderr, "  Interface %d, alternative %d\n",
                            ifnum, dev->altsetting[ifnum]);
                }
                fprintf(stderr, "    Endpoint %d, OUT, %s, %d max\n", ep,
                        tname[dev->ep_out[ep].type],
                        dev->ep_out[ep].max_packet_size);
            }
        }
    }
    fprintf(stderr, "--\n");
}

struct USBEndpoint *usb_ep_get(USBDevice *dev, int pid, int ep)
{
    struct USBEndpoint *eps = pid == USB_TOKEN_IN ? dev->ep_in : dev->ep_out;
    if (ep == 0) {
        return &dev->ep_ctl;
    }
    assert(pid == USB_TOKEN_IN || pid == USB_TOKEN_OUT);
    assert(ep > 0 && ep <= USB_MAX_ENDPOINTS);
    return eps + ep - 1;
}

uint8_t usb_ep_get_type(USBDevice *dev, int pid, int ep)
{
    struct USBEndpoint *uep = usb_ep_get(dev, pid, ep);
    return uep->type;
}

void usb_ep_set_type(USBDevice *dev, int pid, int ep, uint8_t type)
{
    struct USBEndpoint *uep = usb_ep_get(dev, pid, ep);
    uep->type = type;
}

uint8_t usb_ep_get_ifnum(USBDevice *dev, int pid, int ep)
{
    struct USBEndpoint *uep = usb_ep_get(dev, pid, ep);
    return uep->ifnum;
}

void usb_ep_set_ifnum(USBDevice *dev, int pid, int ep, uint8_t ifnum)
{
    struct USBEndpoint *uep = usb_ep_get(dev, pid, ep);
    uep->ifnum = ifnum;
}

void usb_ep_set_max_packet_size(USBDevice *dev, int pid, int ep,
                                uint16_t raw)
{
    struct USBEndpoint *uep = usb_ep_get(dev, pid, ep);
    int size, microframes;

    size = raw & 0x7ff;
    switch ((raw >> 11) & 3) {
    case 1:
        microframes = 2;
        break;
    case 2:
        microframes = 3;
        break;
    default:
        microframes = 1;
        break;
    }
    uep->max_packet_size = size * microframes;
}

int usb_ep_get_max_packet_size(USBDevice *dev, int pid, int ep)
{
    struct USBEndpoint *uep = usb_ep_get(dev, pid, ep);
    return uep->max_packet_size;
}
