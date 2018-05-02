#!/usr/bin/env python
# -*- coding: utf-8 -*-

"""
trace/generated-events.c
"""

__author__     = "Lluís Vilanova <vilanova@ac.upc.edu>"
__copyright__  = "Copyright 2012-2014, Lluís Vilanova <vilanova@ac.upc.edu>"
__license__    = "GPL version 2 or (at your option) any later version"

__maintainer__ = "Stefan Hajnoczi"
__email__      = "stefanha@linux.vnet.ibm.com"


from tracetool import out


def generate(events, backend):
    out('/* This file is autogenerated by tracetool, do not edit. */',
        '',
        '#include "trace.h"',
        '#include "trace/generated-events.h"',
        '#include "trace/control.h"',
        '')

    out('TraceEvent trace_events[TRACE_EVENT_COUNT] = {')

    for e in events:
        out('    { .id = %(id)s, .name = \"%(name)s\", .sstate = %(sstate)s, .dstate = 0 },',
            id = "TRACE_" + e.name.upper(),
            name = e.name,
            sstate = "TRACE_%s_ENABLED" % e.name.upper())

    out('};',
        '')
