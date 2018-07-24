#ifndef SOCKS5_H
#define SOCKS5_H

#define SOCKS5			5
/* SOCKS5 authentication methods */
#define SOCKS5_AUTH_NOAUTH	0x00
#define SOCKS5_AUTH_GSSAPI	0x01
#define SOCKS5_AUTH_USERNAME	0x02
#define SOCKS5_AUTH_NOMETHOD	0xFF
/* SOCKS commands. */
#define SOCKS5_CMD_CONNECT	0x01
#define SOCKS5_CMD_BIND		0x02
#define SOCKS5_CMD_UDPASSOC	0x03
/* SOCKS5 address types. */
#define SOCKS5_ATYP_IPV4	0x01
#define SOCKS5_ATYP_NAME	0x03
#define SOCKS5_ATYP_IPV6	0x04

/*
 * SOCKS5 reply codes and messages:
 * 0 - Success.
 * 1 - General SOCKS server failure.
 * 2 - Connection not allowed by ruleset.
 * 3 - Network unreachable.
 * 4 - Host unreachable.
 * 5 - Connection refused.
 * 6 - TTL expired.
 * 7 - Command not supported.
 * 8 - Address type not supported.
 * 9 - Unknown error.
 */
#define SOCKS5_REP_SUCCESS	0
#define SOCKS5_REP_UNKNOWN	9

#endif /* SOCKS5_H */
