/*
 * m68k gdb server stub
 *
 * Copyright (c) 2003-2005 Fabrice Bellard
 * Copyright (c) 2013 SUSE LINUX Products GmbH
 *
 * This library is free software; you can redistribute it and/or
 * modify it under the terms of the GNU Lesser General Public
 * License as published by the Free Software Foundation; either
 * version 2 of the License, or (at your option) any later version.
 *
 * This library is distributed in the hope that it will be useful,
 * but WITHOUT ANY WARRANTY; without even the implied warranty of
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the GNU
 * Lesser General Public License for more details.
 *
 * You should have received a copy of the GNU Lesser General Public
 * License along with this library; if not, see <http://www.gnu.org/licenses/>.
 */

static int cpu_gdb_read_register(CPUM68KState *env, uint8_t *mem_buf, int n)
{
    if (n < 8) {
        /* D0-D7 */
        GET_REG32(env->dregs[n]);
    } else if (n < 16) {
        /* A0-A7 */
        GET_REG32(env->aregs[n - 8]);
    } else {
        switch (n) {
        case 16:
            GET_REG32(env->sr);
        case 17:
            GET_REG32(env->pc);
        }
    }
    /* FP registers not included here because they vary between
       ColdFire and m68k.  Use XML bits for these.  */
    return 0;
}

static int cpu_gdb_write_register(CPUM68KState *env, uint8_t *mem_buf, int n)
{
    uint32_t tmp;

    tmp = ldl_p(mem_buf);

    if (n < 8) {
        /* D0-D7 */
        env->dregs[n] = tmp;
    } else if (n < 16) {
        /* A0-A7 */
        env->aregs[n - 8] = tmp;
    } else {
        switch (n) {
        case 16:
            env->sr = tmp;
            break;
        case 17:
            env->pc = tmp;
            break;
        default:
            return 0;
        }
    }
    return 4;
}
