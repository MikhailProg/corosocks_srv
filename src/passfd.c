#include <sys/types.h>
#include <sys/socket.h>

#include <string.h>
#include <errno.h>

#include "passfd.h"

int send_fd(int un, int fd)
{
	struct msghdr msg;
	struct cmsghdr *cmsg;
	struct iovec v = { "", 1 };
	unsigned char buf[CMSG_SPACE(sizeof(int))];

	memset(&msg, 0, sizeof(msg));
	memset(&buf, 0, sizeof(buf));
	msg.msg_control = buf;
	msg.msg_controllen = sizeof(buf);
	msg.msg_iov = &v;
	msg.msg_iovlen = 1;

	cmsg = CMSG_FIRSTHDR(&msg);
	cmsg->cmsg_len = CMSG_LEN(sizeof(int));
	cmsg->cmsg_level = SOL_SOCKET;
	cmsg->cmsg_type = SCM_RIGHTS;
	memcpy(CMSG_DATA(cmsg), &fd, sizeof(fd));

	return sendmsg(un, &msg, 0);
}

int recv_fd(int un)
{
	struct msghdr msg;
	struct cmsghdr *cmsg;
	int fd = -1;
	unsigned char buf[CMSG_SPACE(sizeof(fd))], c;
	struct iovec v = { &c, sizeof(c) };

	memset(&msg, 0, sizeof(msg));
	msg.msg_control = buf;
	msg.msg_controllen = sizeof(buf);
	msg.msg_iov = &v; 
	msg.msg_iovlen = 1;

	if (recvmsg(un, &msg, 0) < 0)
		return -1;

	if ((msg.msg_flags & MSG_TRUNC) || (msg.msg_flags & MSG_CTRUNC)) {
		errno = EINVAL;
		return -1;
	}

	for (cmsg = CMSG_FIRSTHDR(&msg); cmsg != NULL;
			cmsg = CMSG_NXTHDR(&msg, cmsg)) {
		if (cmsg->cmsg_len == CMSG_LEN(sizeof(int)) &&
		    cmsg->cmsg_level == SOL_SOCKET &&
		    cmsg->cmsg_type == SCM_RIGHTS) {
			memcpy(&fd, CMSG_DATA(cmsg), sizeof(fd));
			break;
		}
	}

	if (fd == -1)
		errno = EINVAL;

	return fd;
}

