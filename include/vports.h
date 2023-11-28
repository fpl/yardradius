#ifndef __VPORTS_H
#define __VPORTS_H

/*
 * Copyright (C) 1999-2002 Francesco P. Lovergine. All rights reserved.
 *
 * This program is free software; you can redistribute it and/or modify
 * it under the terms stated in the LICENSE file which should be
 * enclosed with sources.
 */

/* $Id: vports.h 84 2004-08-28 13:32:47Z  $ */

#ifdef VPORTS

#define VP_LIST_INIT	0xff
#define VP_RET_IGNORE	0
#define VP_RET_REJECT	1
#define VP_RET_ACCEPT	2
#define VP_CACHE_EXPIRE	30	/* in seconds */

typedef struct vp_callcache
{
	time_t tm;
	struct vp_callcache *next;
	struct vp_callcache *prev;
} VP_CALLCACHE;

typedef struct vp_acctid
{
	char acctid[32];
	struct vp_acctid *next;
	struct vp_acctid *prev;
} VP_ACCTID;

typedef struct vp_nas
{
	UINT4	addr;
	u_char acctidinit;
	VP_ACCTID *acctid_first;
	VP_ACCTID *acctid_last;
	struct vp_nas *next;
	struct vp_nas *prev;
} VP_NAS;

typedef struct vp_called
{
	char num[16];
	u_int max;
	u_char nasipinit;
	u_char callcacheinit;
	VP_NAS *nasip_first;
	VP_NAS *nasip_last;
	VP_CALLCACHE *cc_first;
	VP_CALLCACHE *cc_last;
	struct vp_called *next;
	struct vp_called *prev;
} VP_CALLED;

int vports_init();
VP_CALLED *begin_cidlist();
VP_CALLED  *new_cidlist();
VP_CALLED *get_cidlist(u_char *num);
void create_cidlist(u_char *num, int max);
int vports_in_use(VP_CALLED *cidcur);
int vports_in_cache(VP_CALLED *cidcur);
VP_CALLCACHE *begin_cclist(VP_CALLED *cidcur);
void free_single_cclist(VP_CALLED *cidcur, VP_CALLCACHE *cc_cur);
VP_CALLCACHE *new_cclist(VP_CALLED *cidcur);
VP_NAS *begin_nasiplist(VP_CALLED *cidcur);
void free_single_nasiplist(VP_CALLED *cidcur, VP_NAS *nasip_cur);
VP_NAS *get_nasiplist(VP_CALLED *cidcur, UINT4 addr);
VP_NAS *new_nasiplist(VP_CALLED *cidcur, UINT4 addr);
VP_ACCTID *begin_acctidlist(VP_NAS *nasip_cur);
void free_single_acctidlist(VP_NAS *nasip_cur, VP_ACCTID *acctid_cur);
VP_ACCTID *get_acctidlist(VP_NAS *nasip_cur, u_char *acctid);
VP_ACCTID *new_acctidlist(VP_NAS *nasip_cur, u_char *acctid);
int vp_check_req(AUTH_REQ *authreq);
void vp_update_cid(AUTH_REQ *authreq);

VP_CALLED	*cidfirst;
VP_CALLED	*cidlast;
u_char		vp_cidinit;


#endif /* VPORTS */

#endif /* __VPORTS_H */
