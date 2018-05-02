#!/usr/bin/env python
# -*- coding: utf-8 -*-

"""
trace/generated-tracers.h
"""

__author__     = "Lluís Vilanova <vilanova@ac.upc.edu>"
__copyright__  = "Copyright 2012-2016, Lluís Vilanova <vilanova@ac.upc.edu>"
__license__    = "GPL version 2 or (at your option) any later version"

__maintainer__ = "Stefan Hajnoczi"
__email__      = "stefanha@linux.vnet.ibm.com"


from tracetool import out


def generate(events, backend, group):
    out('/* This file is autogenerated by tracetool, do not edit. */',
        '',
        '#ifndef TRACE_%s_GENERATED_TRACERS_H' % group.upper(),
        '#define TRACE_%s_GENERATED_TRACERS_H' % group.upper(),
        '',
        '#include "qemu-common.h"',
        '#include "trace/control.h"',
        '')

    for e in events:
        out('extern TraceEvent %(event)s;',
            event = e.api(e.QEMU_EVENT))

    for e in events:
        out('extern uint16_t %s;' % e.api(e.QEMU_DSTATE))

    # static state
    for e in events:
        if 'disable' in e.properties:
            enabled = 0
        else:
            enabled = 1
        if "tcg-exec" in e.properties:
            # a single define for the two "sub-events"
            out('#define TRACE_%(name)s_ENABLED %(enabled)d',
                name=e.original.name.upper(),
                enabled=enabled)
        out('#define TRACE_%s_ENABLED %d' % (e.name.upper(), enabled))

    backend.generate_begin(events, group)

    for e in events:
        if "vcpu" in e.properties:
            trace_cpu = next(iter(e.args))[1]
            cond = "trace_event_get_vcpu_state(%(cpu)s,"\
                   " TRACE_%(id)s)"\
                   % dict(
                       cpu=trace_cpu,
                       id=e.name.upper())
        else:
            cond = "true"

        out('',
            'static inline void %(api)s(%(args)s)',
            '{',
            '    if (%(cond)s) {',
            api=e.api(),
            args=e.args,
            cond=cond)

        if "disable" not in e.properties:
            backend.generate(e, group)

        out('    }',
            '}')

    backend.generate_end(events, group)

    out('#endif /* TRACE_%s_GENERATED_TRACERS_H */' % group.upper())
