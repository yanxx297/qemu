/*
 * QEMU live migration via Unix Domain Sockets
 *
 * Copyright Red Hat, Inc. 2009-2016
 *
 * Authors:
 *  Chris Lalancette <clalance@redhat.com>
 *  Daniel P. Berrange <berrange@redhat.com>
 *
 * This work is licensed under the terms of the GNU GPL, version 2.  See
 * the COPYING file in the top-level directory.
 *
 * Contributions after 2012-01-13 are licensed under the terms of the
 * GNU GPL, version 2 or (at your option) any later version.
 */

#include "qemu/osdep.h"

#include "qemu-common.h"
#include "qemu/error-report.h"
#include "qapi/error.h"
#include "migration/migration.h"
#include "migration/qemu-file.h"
#include "io/channel-socket.h"
#include "trace.h"


static SocketAddress *tcp_build_address(const char *host_port, Error **errp)
{
    InetSocketAddress *iaddr = inet_parse(host_port, errp);
    SocketAddress *saddr;

    if (!iaddr) {
        return NULL;
    }

    saddr = g_new0(SocketAddress, 1);
    saddr->type = SOCKET_ADDRESS_KIND_INET;
    saddr->u.inet.data = iaddr;

    return saddr;
}


static SocketAddress *unix_build_address(const char *path)
{
    SocketAddress *saddr;

    saddr = g_new0(SocketAddress, 1);
    saddr->type = SOCKET_ADDRESS_KIND_UNIX;
    saddr->u.q_unix.data = g_new0(UnixSocketAddress, 1);
    saddr->u.q_unix.data->path = g_strdup(path);

    return saddr;
}


static void socket_outgoing_migration(Object *src,
                                      Error *err,
                                      gpointer opaque)
{
    MigrationState *s = opaque;
    QIOChannel *sioc = QIO_CHANNEL(src);

    if (err) {
        trace_migration_socket_outgoing_error(error_get_pretty(err));
        s->to_dst_file = NULL;
        migrate_fd_error(s, err);
    } else {
        trace_migration_socket_outgoing_connected();
        migration_set_outgoing_channel(s, sioc);
    }
    object_unref(src);
}

static void socket_start_outgoing_migration(MigrationState *s,
                                            SocketAddress *saddr,
                                            Error **errp)
{
    QIOChannelSocket *sioc = qio_channel_socket_new();
    qio_channel_socket_connect_async(sioc,
                                     saddr,
                                     socket_outgoing_migration,
                                     s,
                                     NULL);
    qapi_free_SocketAddress(saddr);
}

void tcp_start_outgoing_migration(MigrationState *s,
                                  const char *host_port,
                                  Error **errp)
{
    SocketAddress *saddr = tcp_build_address(host_port, errp);
    socket_start_outgoing_migration(s, saddr, errp);
}

void unix_start_outgoing_migration(MigrationState *s,
                                   const char *path,
                                   Error **errp)
{
    SocketAddress *saddr = unix_build_address(path);
    socket_start_outgoing_migration(s, saddr, errp);
}


static gboolean socket_accept_incoming_migration(QIOChannel *ioc,
                                                 GIOCondition condition,
                                                 gpointer opaque)
{
    QIOChannelSocket *sioc;
    Error *err = NULL;

    sioc = qio_channel_socket_accept(QIO_CHANNEL_SOCKET(ioc),
                                     &err);
    if (!sioc) {
        error_report("could not accept migration connection (%s)",
                     error_get_pretty(err));
        goto out;
    }

    trace_migration_socket_incoming_accepted();

    migration_set_incoming_channel(migrate_get_current(),
                                   QIO_CHANNEL(sioc));
    object_unref(OBJECT(sioc));

out:
    /* Close listening socket as its no longer needed */
    qio_channel_close(ioc, NULL);
    return FALSE; /* unregister */
}


static void socket_start_incoming_migration(SocketAddress *saddr,
                                            Error **errp)
{
    QIOChannelSocket *listen_ioc = qio_channel_socket_new();

    if (qio_channel_socket_listen_sync(listen_ioc, saddr, errp) < 0) {
        object_unref(OBJECT(listen_ioc));
        qapi_free_SocketAddress(saddr);
        return;
    }

    qio_channel_add_watch(QIO_CHANNEL(listen_ioc),
                          G_IO_IN,
                          socket_accept_incoming_migration,
                          listen_ioc,
                          (GDestroyNotify)object_unref);
    qapi_free_SocketAddress(saddr);
}

void tcp_start_incoming_migration(const char *host_port, Error **errp)
{
    SocketAddress *saddr = tcp_build_address(host_port, errp);
    socket_start_incoming_migration(saddr, errp);
}

void unix_start_incoming_migration(const char *path, Error **errp)
{
    SocketAddress *saddr = unix_build_address(path);
    socket_start_incoming_migration(saddr, errp);
}
