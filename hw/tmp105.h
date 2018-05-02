/*
 * Texas Instruments TMP105 Temperature Sensor
 *
 * Browse the data sheet:
 *
 *    http://www.ti.com/lit/gpn/tmp105
 *
 * Copyright (C) 2012 Alex Horn <alex.horn@cs.ox.ac.uk>
 * Copyright (C) 2008-2012 Andrzej Zaborowski <balrogg@gmail.com>
 *
 * This work is licensed under the terms of the GNU GPL, version 2 or
 * later. See the COPYING file in the top-level directory.
 */
#ifndef QEMU_TMP105_H
#define QEMU_TMP105_H

#include "i2c.h"
#include "tmp105_regs.h"

/**
 * tmp105_set:
 * @i2c: dispatcher to TMP105 hardware model
 * @temp: temperature with 0.001 centigrades units in the range -40 C to +125 C
 *
 * Sets the temperature of the TMP105 hardware model.
 *
 * Bits 5 and 6 (value 32 and 64) in the register indexed by TMP105_REG_CONFIG
 * determine the precision of the temperature. See Table 8 in the data sheet.
 *
 * @see_also: I2C_SLAVE macro
 * @see_also: http://www.ti.com/lit/gpn/tmp105
 */
void tmp105_set(I2CSlave *i2c, int temp);

#endif
