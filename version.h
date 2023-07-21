/* $OpenBSD: version.h,v 1.97 2023/03/15 21:19:57 djm Exp $ */

#define SSH_VERSION	"OpenSSH_9.3"

#define SSH_PORTABLE	"p2"
#define SSH_HPN         "-hpn17v14"
#define SSH_RELEASE	SSH_VERSION SSH_PORTABLE SSH_HPN

#ifdef NERSC_MOD
#undef SSH_RELEASE
#define SSH_AUDITING	"NMOD_3.19"
#define SSH_RELEASE	SSH_VERSION SSH_PORTABLE SSH_HPN SSH_AUDITING
#endif /* NERSC_MOD */
