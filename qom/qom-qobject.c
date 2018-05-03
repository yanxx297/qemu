/*
 * QEMU Object Model - QObject wrappers
 *
 * Copyright (C) 2012 Red Hat, Inc.
 *
 * Author: Paolo Bonzini <pbonzini@redhat.com>
 *
 * This work is licensed under the terms of the GNU GPL, version 2 or later.
 * See the COPYING file in the top-level directory.
 */

#include "qemu/osdep.h"
#include "qapi/error.h"
#include "qemu-common.h"
#include "qom/object.h"
#include "qom/qom-qobject.h"
#include "qapi/visitor.h"
#include "qapi/qmp-input-visitor.h"
#include "qapi/qmp-output-visitor.h"

void object_property_set_qobject(Object *obj, QObject *value,
                                 const char *name, Error **errp)
{
    Visitor *v;
    /* TODO: Should we reject, rather than ignore, excess input? */
    v = qmp_input_visitor_new(value, false);
    object_property_set(obj, v, name, errp);
    visit_free(v);
}

QObject *object_property_get_qobject(Object *obj, const char *name,
                                     Error **errp)
{
    QObject *ret = NULL;
    Error *local_err = NULL;
    QmpOutputVisitor *qov;

    qov = qmp_output_visitor_new();
    object_property_get(obj, qmp_output_get_visitor(qov), name, &local_err);
    if (!local_err) {
        ret = qmp_output_get_qobject(qov);
    }
    error_propagate(errp, local_err);
    visit_free(qmp_output_get_visitor(qov));
    return ret;
}
