/*
 * Copyright (c) 2013
 * Guillaume Subiron, Yann Bordenave, Serigne Modou Wagne.
 */

#include "qemu/osdep.h"
#include "slirp.h"
#include "ip6_icmp.h"

/*
 * IP initialization: fill in IP protocol switch table.
 * All protocols not implemented in kernel go to raw IP protocol handler.
 */
void ip6_init(Slirp *slirp)
{
    icmp6_init(slirp);
}

void ip6_cleanup(Slirp *slirp)
{
    icmp6_cleanup(slirp);
}

void ip6_input(struct mbuf *m)
{
    struct ip6 *ip6;

    DEBUG_CALL("ip6_input");
    DEBUG_ARG("m = %lx", (long)m);
    DEBUG_ARG("m_len = %d", m->m_len);

    if (m->m_len < sizeof(struct ip6)) {
        goto bad;
    }

    ip6 = mtod(m, struct ip6 *);

    if (ip6->ip_v != IP6VERSION) {
        goto bad;
    }

    /* check ip_ttl for a correct ICMP reply */
    if (ip6->ip_hl == 0) {
        /*icmp_error(m, ICMP_TIMXCEED,ICMP_TIMXCEED_INTRANS, 0,"ttl");*/
        goto bad;
    }

    /*
     * Switch out to protocol's input routine.
     */
    switch (ip6->ip_nh) {
    case IPPROTO_TCP:
        /*tcp_input(m, hlen, (struct socket *)NULL);*/
        break;
    case IPPROTO_UDP:
        /*udp_input(m, hlen);*/
        break;
    case IPPROTO_ICMPV6:
        icmp6_input(m);
        break;
    default:
        m_free(m);
    }
    return;
bad:
    m_free(m);
}
