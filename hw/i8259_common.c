/*
 * QEMU 8259 - common bits of emulated and KVM kernel model
 *
 * Copyright (c) 2003-2004 Fabrice Bellard
 * Copyright (c) 2011      Jan Kiszka, Siemens AG
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
#include "pc.h"
#include "i8259_internal.h"

void pic_reset_common(PICCommonState *s)
{
    s->last_irr = 0;
    s->irr &= s->elcr;
    s->imr = 0;
    s->isr = 0;
    s->priority_add = 0;
    s->irq_base = 0;
    s->read_reg_select = 0;
    s->poll = 0;
    s->special_mask = 0;
    s->init_state = 0;
    s->auto_eoi = 0;
    s->rotate_on_auto_eoi = 0;
    s->special_fully_nested_mode = 0;
    s->init4 = 0;
    s->single_mode = 0;
    /* Note: ELCR is not reset */
}

static void pic_dispatch_pre_save(void *opaque)
{
    PICCommonState *s = opaque;
    PICCommonClass *info = PIC_COMMON_GET_CLASS(s);

    if (info->pre_save) {
        info->pre_save(s);
    }
}

static int pic_dispatch_post_load(void *opaque, int version_id)
{
    PICCommonState *s = opaque;
    PICCommonClass *info = PIC_COMMON_GET_CLASS(s);

    if (info->post_load) {
        info->post_load(s);
    }
    return 0;
}

static int pic_init_common(ISADevice *dev)
{
    PICCommonState *s = DO_UPCAST(PICCommonState, dev, dev);
    PICCommonClass *info = PIC_COMMON_GET_CLASS(s);

    info->init(s);

    isa_register_ioport(NULL, &s->base_io, s->iobase);
    if (s->elcr_addr != -1) {
        isa_register_ioport(NULL, &s->elcr_io, s->elcr_addr);
    }

    qdev_set_legacy_instance_id(&s->dev.qdev, s->iobase, 1);

    return 0;
}

ISADevice *i8259_init_chip(const char *name, ISABus *bus, bool master)
{
    ISADevice *dev;

    dev = isa_create(bus, name);
    qdev_prop_set_uint32(&dev->qdev, "iobase", master ? 0x20 : 0xa0);
    qdev_prop_set_uint32(&dev->qdev, "elcr_addr", master ? 0x4d0 : 0x4d1);
    qdev_prop_set_uint8(&dev->qdev, "elcr_mask", master ? 0xf8 : 0xde);
    qdev_prop_set_bit(&dev->qdev, "master", master);
    qdev_init_nofail(&dev->qdev);

    return dev;
}

static const VMStateDescription vmstate_pic_common = {
    .name = "i8259",
    .version_id = 1,
    .minimum_version_id = 1,
    .minimum_version_id_old = 1,
    .pre_save = pic_dispatch_pre_save,
    .post_load = pic_dispatch_post_load,
    .fields = (VMStateField[]) {
        VMSTATE_UINT8(last_irr, PICCommonState),
        VMSTATE_UINT8(irr, PICCommonState),
        VMSTATE_UINT8(imr, PICCommonState),
        VMSTATE_UINT8(isr, PICCommonState),
        VMSTATE_UINT8(priority_add, PICCommonState),
        VMSTATE_UINT8(irq_base, PICCommonState),
        VMSTATE_UINT8(read_reg_select, PICCommonState),
        VMSTATE_UINT8(poll, PICCommonState),
        VMSTATE_UINT8(special_mask, PICCommonState),
        VMSTATE_UINT8(init_state, PICCommonState),
        VMSTATE_UINT8(auto_eoi, PICCommonState),
        VMSTATE_UINT8(rotate_on_auto_eoi, PICCommonState),
        VMSTATE_UINT8(special_fully_nested_mode, PICCommonState),
        VMSTATE_UINT8(init4, PICCommonState),
        VMSTATE_UINT8(single_mode, PICCommonState),
        VMSTATE_UINT8(elcr, PICCommonState),
        VMSTATE_END_OF_LIST()
    }
};

static Property pic_properties_common[] = {
    DEFINE_PROP_HEX32("iobase", PICCommonState, iobase,  -1),
    DEFINE_PROP_HEX32("elcr_addr", PICCommonState, elcr_addr,  -1),
    DEFINE_PROP_HEX8("elcr_mask", PICCommonState, elcr_mask,  -1),
    DEFINE_PROP_BIT("master", PICCommonState, master,  0, false),
    DEFINE_PROP_END_OF_LIST(),
};

static void pic_common_class_init(ObjectClass *klass, void *data)
{
    ISADeviceClass *ic = ISA_DEVICE_CLASS(klass);
    DeviceClass *dc = DEVICE_CLASS(klass);

    dc->vmsd = &vmstate_pic_common;
    dc->no_user = 1;
    dc->props = pic_properties_common;
    ic->init = pic_init_common;
}

static TypeInfo pic_common_type = {
    .name = TYPE_PIC_COMMON,
    .parent = TYPE_ISA_DEVICE,
    .instance_size = sizeof(PICCommonState),
    .class_size = sizeof(PICCommonClass),
    .class_init = pic_common_class_init,
    .abstract = true,
};

static void register_types(void)
{
    type_register_static(&pic_common_type);
}

type_init(register_types);
