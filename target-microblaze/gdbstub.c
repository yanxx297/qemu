/*
 * MicroBlaze gdb server stub
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

static int cpu_gdb_read_register(CPUMBState *env, uint8_t *mem_buf, int n)
{
    if (n < 32) {
        GET_REG32(env->regs[n]);
    } else {
        GET_REG32(env->sregs[n - 32]);
    }
    return 0;
}

static int cpu_gdb_write_register(CPUMBState *env, uint8_t *mem_buf, int n)
{
    MicroBlazeCPU *cpu = mb_env_get_cpu(env);
    CPUClass *cc = CPU_GET_CLASS(cpu);
    uint32_t tmp;

    if (n > cc->gdb_num_core_regs) {
        return 0;
    }

    tmp = ldl_p(mem_buf);

    if (n < 32) {
        env->regs[n] = tmp;
    } else {
        env->sregs[n - 32] = tmp;
    }
    return 4;
}
