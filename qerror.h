/*
 * QError Module
 *
 * Copyright (C) 2009 Red Hat Inc.
 *
 * Authors:
 *  Luiz Capitulino <lcapitulino@redhat.com>
 *
 * This work is licensed under the terms of the GNU LGPL, version 2.1 or later.
 * See the COPYING.LIB file in the top-level directory.
 */
#ifndef QERROR_H
#define QERROR_H

#include "qdict.h"
#include "qstring.h"
#include "qemu-error.h"
#include "error.h"
#include <stdarg.h>

typedef struct QErrorStringTable {
    const char *desc;
    const char *error_fmt;
} QErrorStringTable;

typedef struct QError {
    QObject_HEAD;
    QDict *error;
    Location loc;
    const QErrorStringTable *entry;
} QError;

QString *qerror_human(const QError *qerror);
void qerror_report(const char *fmt, ...) GCC_FMT_ATTR(1, 2);
void qerror_report_err(Error *err);
void assert_no_error(Error *err);
QString *qerror_format(const char *fmt, QDict *error);

/*
 * QError class list
 * Please keep the definitions in alphabetical order.
 * Use scripts/check-qerror.sh to check.
 */
#define QERR_ADD_CLIENT_FAILED \
    "{ 'class': 'AddClientFailed', 'data': {} }"

#define QERR_AMBIGUOUS_PATH \
    "{ 'class': 'AmbiguousPath', 'data': { 'path': %s } }"

#define QERR_BAD_BUS_FOR_DEVICE \
    "{ 'class': 'BadBusForDevice', 'data': { 'device': %s, 'bad_bus_type': %s } }"

#define QERR_BASE_NOT_FOUND \
    "{ 'class': 'BaseNotFound', 'data': { 'base': %s } }"

#define QERR_BLOCK_FORMAT_FEATURE_NOT_SUPPORTED \
    "{ 'class': 'BlockFormatFeatureNotSupported', 'data': { 'format': %s, 'name': %s, 'feature': %s } }"

#define QERR_BUFFER_OVERRUN \
    "{ 'class': 'BufferOverrun', 'data': {} }"

#define QERR_BUS_NO_HOTPLUG \
    "{ 'class': 'BusNoHotplug', 'data': { 'bus': %s } }"

#define QERR_BUS_NOT_FOUND \
    "{ 'class': 'BusNotFound', 'data': { 'bus': %s } }"

#define QERR_COMMAND_DISABLED \
    "{ 'class': 'CommandDisabled', 'data': { 'name': %s } }"

#define QERR_COMMAND_NOT_FOUND \
    "{ 'class': 'CommandNotFound', 'data': { 'name': %s } }"

#define QERR_DEVICE_ENCRYPTED \
    "{ 'class': 'DeviceEncrypted', 'data': { 'device': %s, 'filename': %s } }"

#define QERR_DEVICE_FEATURE_BLOCKS_MIGRATION \
    "{ 'class': 'DeviceFeatureBlocksMigration', 'data': { 'device': %s, 'feature': %s } }"

#define QERR_DEVICE_HAS_NO_MEDIUM \
    "{ 'class': 'DeviceHasNoMedium', 'data': { 'device': %s } }"

#define QERR_DEVICE_INIT_FAILED \
    "{ 'class': 'DeviceInitFailed', 'data': { 'device': %s } }"

#define QERR_DEVICE_IN_USE \
    "{ 'class': 'DeviceInUse', 'data': { 'device': %s } }"

#define QERR_DEVICE_IS_READ_ONLY \
    "{ 'class': 'DeviceIsReadOnly', 'data': { 'device': %s } }"

#define QERR_DEVICE_LOCKED \
    "{ 'class': 'DeviceLocked', 'data': { 'device': %s } }"

#define QERR_DEVICE_MULTIPLE_BUSSES \
    "{ 'class': 'DeviceMultipleBusses', 'data': { 'device': %s } }"

#define QERR_DEVICE_NO_BUS \
    "{ 'class': 'DeviceNoBus', 'data': { 'device': %s } }"

#define QERR_DEVICE_NO_HOTPLUG \
    "{ 'class': 'DeviceNoHotplug', 'data': { 'device': %s } }"

#define QERR_DEVICE_NOT_ACTIVE \
    "{ 'class': 'DeviceNotActive', 'data': { 'device': %s } }"

#define QERR_DEVICE_NOT_ENCRYPTED \
    "{ 'class': 'DeviceNotEncrypted', 'data': { 'device': %s } }"

#define QERR_DEVICE_NOT_FOUND \
    "{ 'class': 'DeviceNotFound', 'data': { 'device': %s } }"

#define QERR_DEVICE_NOT_REMOVABLE \
    "{ 'class': 'DeviceNotRemovable', 'data': { 'device': %s } }"

#define QERR_DUPLICATE_ID \
    "{ 'class': 'DuplicateId', 'data': { 'id': %s, 'object': %s } }"

#define QERR_FD_NOT_FOUND \
    "{ 'class': 'FdNotFound', 'data': { 'name': %s } }"

#define QERR_FD_NOT_SUPPLIED \
    "{ 'class': 'FdNotSupplied', 'data': {} }"

#define QERR_FEATURE_DISABLED \
    "{ 'class': 'FeatureDisabled', 'data': { 'name': %s } }"

#define QERR_INVALID_BLOCK_FORMAT \
    "{ 'class': 'InvalidBlockFormat', 'data': { 'name': %s } }"

#define QERR_INVALID_OPTION_GROUP \
    "{ 'class': 'InvalidOptionGroup', 'data': { 'group': %s } }"

#define QERR_INVALID_PARAMETER \
    "{ 'class': 'InvalidParameter', 'data': { 'name': %s } }"

#define QERR_INVALID_PARAMETER_COMBINATION \
    "{ 'class': 'InvalidParameterCombination', 'data': {} }"

#define QERR_INVALID_PARAMETER_TYPE \
    "{ 'class': 'InvalidParameterType', 'data': { 'name': %s,'expected': %s } }"

#define QERR_INVALID_PARAMETER_VALUE \
    "{ 'class': 'InvalidParameterValue', 'data': { 'name': %s, 'expected': %s } }"

#define QERR_INVALID_PASSWORD \
    "{ 'class': 'InvalidPassword', 'data': {} }"

#define QERR_IO_ERROR \
    "{ 'class': 'IOError', 'data': {} }"

#define QERR_JSON_PARSE_ERROR \
    "{ 'class': 'JSONParseError', 'data': { 'message': %s } }"

#define QERR_JSON_PARSING \
    "{ 'class': 'JSONParsing', 'data': {} }"

#define QERR_KVM_MISSING_CAP \
    "{ 'class': 'KVMMissingCap', 'data': { 'capability': %s, 'feature': %s } }"

#define QERR_MIGRATION_ACTIVE \
    "{ 'class': 'MigrationActive', 'data': {} }"

#define QERR_MIGRATION_NOT_SUPPORTED \
    "{ 'class': 'MigrationNotSupported', 'data': {'device': %s} }"

#define QERR_MIGRATION_EXPECTED \
    "{ 'class': 'MigrationExpected', 'data': {} }"

#define QERR_MISSING_PARAMETER \
    "{ 'class': 'MissingParameter', 'data': { 'name': %s } }"

#define QERR_NO_BUS_FOR_DEVICE \
    "{ 'class': 'NoBusForDevice', 'data': { 'device': %s, 'bus': %s } }"

#define QERR_NOT_SUPPORTED \
    "{ 'class': 'NotSupported', 'data': {} }"

#define QERR_OPEN_FILE_FAILED \
    "{ 'class': 'OpenFileFailed', 'data': { 'filename': %s } }"

#define QERR_PERMISSION_DENIED \
    "{ 'class': 'PermissionDenied', 'data': {} }"

#define QERR_PROPERTY_NOT_FOUND \
    "{ 'class': 'PropertyNotFound', 'data': { 'device': %s, 'property': %s } }"

#define QERR_PROPERTY_VALUE_BAD \
    "{ 'class': 'PropertyValueBad', 'data': { 'device': %s, 'property': %s, 'value': %s } }"

#define QERR_PROPERTY_VALUE_IN_USE \
    "{ 'class': 'PropertyValueInUse', 'data': { 'device': %s, 'property': %s, 'value': %s } }"

#define QERR_PROPERTY_VALUE_NOT_FOUND \
    "{ 'class': 'PropertyValueNotFound', 'data': { 'device': %s, 'property': %s, 'value': %s } }"

#define QERR_PROPERTY_VALUE_NOT_POWER_OF_2 \
    "{ 'class': 'PropertyValueNotPowerOf2', 'data': { " \
    "'device': %s, 'property': %s, 'value': %"PRId64" } }"

#define QERR_PROPERTY_VALUE_OUT_OF_RANGE \
    "{ 'class': 'PropertyValueOutOfRange', 'data': { 'device': %s, 'property': %s, 'value': %"PRId64", 'min': %"PRId64", 'max': %"PRId64" } }"

#define QERR_QGA_COMMAND_FAILED \
    "{ 'class': 'QgaCommandFailed', 'data': { 'message': %s } }"

#define QERR_QGA_LOGGING_FAILED \
    "{ 'class': 'QgaLoggingFailed', 'data': {} }"

#define QERR_QMP_BAD_INPUT_OBJECT \
    "{ 'class': 'QMPBadInputObject', 'data': { 'expected': %s } }"

#define QERR_QMP_BAD_INPUT_OBJECT_MEMBER \
    "{ 'class': 'QMPBadInputObjectMember', 'data': { 'member': %s, 'expected': %s } }"

#define QERR_QMP_EXTRA_MEMBER \
    "{ 'class': 'QMPExtraInputObjectMember', 'data': { 'member': %s } }"

#define QERR_RESET_REQUIRED \
    "{ 'class': 'ResetRequired', 'data': {} }"

#define QERR_SET_PASSWD_FAILED \
    "{ 'class': 'SetPasswdFailed', 'data': {} }"

#define QERR_TOO_MANY_FILES \
    "{ 'class': 'TooManyFiles', 'data': {} }"

#define QERR_UNDEFINED_ERROR \
    "{ 'class': 'UndefinedError', 'data': {} }"

#define QERR_UNKNOWN_BLOCK_FORMAT_FEATURE \
    "{ 'class': 'UnknownBlockFormatFeature', 'data': { 'device': %s, 'format': %s, 'feature': %s } }"

#define QERR_UNSUPPORTED \
    "{ 'class': 'Unsupported', 'data': {} }"

#define QERR_VIRTFS_FEATURE_BLOCKS_MIGRATION \
    "{ 'class': 'VirtFSFeatureBlocksMigration', 'data': { 'path': %s, 'tag': %s } }"

#define QERR_VNC_SERVER_FAILED \
    "{ 'class': 'VNCServerFailed', 'data': { 'target': %s } }"

#define QERR_SOCKET_CONNECT_IN_PROGRESS \
    "{ 'class': 'SockConnectInprogress', 'data': {} }"

#define QERR_SOCKET_CONNECT_FAILED \
    "{ 'class': 'SockConnectFailed', 'data': {} }"

#define QERR_SOCKET_LISTEN_FAILED \
    "{ 'class': 'SockListenFailed', 'data': {} }"

#define QERR_SOCKET_BIND_FAILED \
    "{ 'class': 'SockBindFailed', 'data': {} }"

#define QERR_SOCKET_CREATE_FAILED \
    "{ 'class': 'SockCreateFailed', 'data': {} }"

#endif /* QERROR_H */
