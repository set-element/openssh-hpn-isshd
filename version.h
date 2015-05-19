/* $OpenBSD: version.h,v 1.72 2015/03/04 18:53:53 djm Exp $ */

#define SSH_VERSION	"OpenSSH_6.8"

#define SSH_PORTABLE	"p1"
#define SSH_HPN         "-hpn14v5"
#define SSH_RELEASE	SSH_VERSION SSH_PORTABLE SSH_HPN

#ifdef NERSC_MOD
#undef SSH_RELEASE
#define SSH_AUDITING	"NMOD_3.14"
#define SSH_RELEASE	SSH_VERSION SSH_PORTABLE SSH_AUDITING
#endif /* NERSC_MOD */
