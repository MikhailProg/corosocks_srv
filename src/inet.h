#ifndef INET_H
#define INET_H

int inet_connect(const char *proto, const char *host,
		 const char *port, int (*nonblock)(int));
int inet_listen(const char *proto, const char *host, const char *port);

#define tcp_connect(h, p, n)	inet_connect("tcp", (h), (p), (n))
#define udp_connect(h, p, n)	inet_connect("udp", (h), (p), (n))
#define tcp_listen(h, p)	inet_listen("tcp", (h), (p))
#define udp_listen(h, p)	inet_listen("udp", (h), (p))

#endif /* INET_H */

