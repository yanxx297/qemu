/*
 * This work is licensed under the terms of the GNU GPL, version 2 or
 * (at your option) any later version.  See the COPYING file in the
 * top-level directory.
 */

#include "qemu/iov.h"

#include "hw/qdev.h"
#include "hw/virtio/virtio.h"
#include "hw/virtio/virtio-input.h"

#include "standard-headers/linux/input.h"

/* ----------------------------------------------------------------- */

void virtio_input_send(VirtIOInput *vinput, virtio_input_event *event)
{
    VirtQueueElement elem;
    unsigned have, need;
    int i, len;

    /* queue up events ... */
    if (vinput->qindex == vinput->qsize) {
        vinput->qsize++;
        vinput->queue = realloc(vinput->queue, vinput->qsize *
                                sizeof(virtio_input_event));
    }
    vinput->queue[vinput->qindex++] = *event;

    /* ... until we see a report sync ... */
    if (event->type != cpu_to_le16(EV_SYN) ||
        event->code != cpu_to_le16(SYN_REPORT)) {
        return;
    }

    /* ... then check available space ... */
    need = sizeof(virtio_input_event) * vinput->qindex;
    virtqueue_get_avail_bytes(vinput->evt, &have, NULL, need, 0);
    if (have < need) {
        vinput->qindex = 0;
        fprintf(stderr, "%s: ENOSPC in vq, dropping events\n", __func__);
        return;
    }

    /* ... and finally pass them to the guest */
    for (i = 0; i < vinput->qindex; i++) {
        if (!virtqueue_pop(vinput->evt, &elem)) {
            /* should not happen, we've checked for space beforehand */
            fprintf(stderr, "%s: Huh?  No vq elem available ...\n", __func__);
            return;
        }
        len = iov_from_buf(elem.in_sg, elem.in_num,
                           0, vinput->queue+i, sizeof(virtio_input_event));
        virtqueue_push(vinput->evt, &elem, len);
    }
    virtio_notify(VIRTIO_DEVICE(vinput), vinput->evt);
    vinput->qindex = 0;
}

static void virtio_input_handle_evt(VirtIODevice *vdev, VirtQueue *vq)
{
    /* nothing */
}

static void virtio_input_handle_sts(VirtIODevice *vdev, VirtQueue *vq)
{
    VirtIOInputClass *vic = VIRTIO_INPUT_GET_CLASS(vdev);
    VirtIOInput *vinput = VIRTIO_INPUT(vdev);
    virtio_input_event event;
    VirtQueueElement elem;
    int len;

    while (virtqueue_pop(vinput->sts, &elem)) {
        memset(&event, 0, sizeof(event));
        len = iov_to_buf(elem.out_sg, elem.out_num,
                         0, &event, sizeof(event));
        if (vic->handle_status) {
            vic->handle_status(vinput, &event);
        }
        virtqueue_push(vinput->sts, &elem, len);
    }
    virtio_notify(vdev, vinput->sts);
}

static virtio_input_config *virtio_input_find_config(VirtIOInput *vinput,
                                                     uint8_t select,
                                                     uint8_t subsel)
{
    VirtIOInputConfig *cfg;

    QTAILQ_FOREACH(cfg, &vinput->cfg_list, node) {
        if (select == cfg->config.select &&
            subsel == cfg->config.subsel) {
            return &cfg->config;
        }
    }
    return NULL;
}

void virtio_input_add_config(VirtIOInput *vinput,
                             virtio_input_config *config)
{
    VirtIOInputConfig *cfg;

    if (virtio_input_find_config(vinput, config->select, config->subsel)) {
        /* should not happen */
        fprintf(stderr, "%s: duplicate config: %d/%d\n",
                __func__, config->select, config->subsel);
        abort();
    }

    cfg = g_new0(VirtIOInputConfig, 1);
    cfg->config = *config;
    QTAILQ_INSERT_TAIL(&vinput->cfg_list, cfg, node);
}

void virtio_input_init_config(VirtIOInput *vinput,
                              virtio_input_config *config)
{
    int i = 0;

    QTAILQ_INIT(&vinput->cfg_list);
    while (config[i].select) {
        virtio_input_add_config(vinput, config + i);
        i++;
    }
}

void virtio_input_idstr_config(VirtIOInput *vinput,
                               uint8_t select, const char *string)
{
    virtio_input_config id;

    if (!string) {
        return;
    }
    memset(&id, 0, sizeof(id));
    id.select = select;
    id.size = snprintf(id.u.string, sizeof(id.u.string), "%s", string);
    virtio_input_add_config(vinput, &id);
}

static void virtio_input_get_config(VirtIODevice *vdev, uint8_t *config_data)
{
    VirtIOInput *vinput = VIRTIO_INPUT(vdev);
    virtio_input_config *config;

    config = virtio_input_find_config(vinput, vinput->cfg_select,
                                      vinput->cfg_subsel);
    if (config) {
        memcpy(config_data, config, vinput->cfg_size);
    } else {
        memset(config_data, 0, vinput->cfg_size);
    }
}

static void virtio_input_set_config(VirtIODevice *vdev,
                                    const uint8_t *config_data)
{
    VirtIOInput *vinput = VIRTIO_INPUT(vdev);
    virtio_input_config *config = (virtio_input_config *)config_data;

    vinput->cfg_select = config->select;
    vinput->cfg_subsel = config->subsel;
    virtio_notify_config(vdev);
}

static uint32_t virtio_input_get_features(VirtIODevice *vdev, uint32_t f)
{
    return f;
}

static void virtio_input_set_status(VirtIODevice *vdev, uint8_t val)
{
    VirtIOInputClass *vic = VIRTIO_INPUT_GET_CLASS(vdev);
    VirtIOInput *vinput = VIRTIO_INPUT(vdev);

    if (val & VIRTIO_CONFIG_S_DRIVER_OK) {
        if (!vinput->active) {
            vinput->active = true;
            if (vic->change_active) {
                vic->change_active(vinput);
            }
        }
    }
}

static void virtio_input_reset(VirtIODevice *vdev)
{
    VirtIOInputClass *vic = VIRTIO_INPUT_GET_CLASS(vdev);
    VirtIOInput *vinput = VIRTIO_INPUT(vdev);

    if (vinput->active) {
        vinput->active = false;
        if (vic->change_active) {
            vic->change_active(vinput);
        }
    }
}

static void virtio_input_device_realize(DeviceState *dev, Error **errp)
{
    VirtIOInputClass *vic = VIRTIO_INPUT_GET_CLASS(dev);
    VirtIODevice *vdev = VIRTIO_DEVICE(dev);
    VirtIOInput *vinput = VIRTIO_INPUT(dev);
    VirtIOInputConfig *cfg;
    Error *local_err = NULL;

    if (vic->realize) {
        vic->realize(dev, &local_err);
        if (local_err) {
            error_propagate(errp, local_err);
            return;
        }
    }

    virtio_input_idstr_config(vinput, VIRTIO_INPUT_CFG_ID_SERIAL,
                              vinput->input.serial);

    QTAILQ_FOREACH(cfg, &vinput->cfg_list, node) {
        if (vinput->cfg_size < cfg->config.size) {
            vinput->cfg_size = cfg->config.size;
        }
    }
    vinput->cfg_size += 8;
    assert(vinput->cfg_size <= sizeof(virtio_input_config));

    virtio_init(vdev, "virtio-input", VIRTIO_ID_INPUT,
                vinput->cfg_size);
    vinput->evt = virtio_add_queue(vdev, 64, virtio_input_handle_evt);
    vinput->sts = virtio_add_queue(vdev, 64, virtio_input_handle_sts);
}

static void virtio_input_device_unrealize(DeviceState *dev, Error **errp)
{
    VirtIOInputClass *vic = VIRTIO_INPUT_GET_CLASS(dev);
    VirtIODevice *vdev = VIRTIO_DEVICE(dev);
    Error *local_err = NULL;

    if (vic->unrealize) {
        vic->unrealize(dev, &local_err);
        if (local_err) {
            error_propagate(errp, local_err);
            return;
        }
    }
    virtio_cleanup(vdev);
}

static void virtio_input_class_init(ObjectClass *klass, void *data)
{
    DeviceClass *dc = DEVICE_CLASS(klass);
    VirtioDeviceClass *vdc = VIRTIO_DEVICE_CLASS(klass);

    set_bit(DEVICE_CATEGORY_INPUT, dc->categories);
    vdc->realize      = virtio_input_device_realize;
    vdc->unrealize    = virtio_input_device_unrealize;
    vdc->get_config   = virtio_input_get_config;
    vdc->set_config   = virtio_input_set_config;
    vdc->get_features = virtio_input_get_features;
    vdc->set_status   = virtio_input_set_status;
    vdc->reset        = virtio_input_reset;
}

static const TypeInfo virtio_input_info = {
    .name          = TYPE_VIRTIO_INPUT,
    .parent        = TYPE_VIRTIO_DEVICE,
    .instance_size = sizeof(VirtIOInput),
    .class_size    = sizeof(VirtIOInputClass),
    .class_init    = virtio_input_class_init,
    .abstract      = true,
};

/* ----------------------------------------------------------------- */

static void virtio_register_types(void)
{
    type_register_static(&virtio_input_info);
}

type_init(virtio_register_types)
