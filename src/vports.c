/*
 * Copyright (C) 1999-2002 Francesco P. Lovergine. 
 * All rights reserved.
 *
 * This program is free software; you can redistribute it and/or modify
 * it under the terms stated in the LICENSE file which should be
 * enclosed with sources.
 */

static char rcsid[] = "$Id: vports.c 81 2004-08-27 21:45:17Z flovergine $";

#include "yard.h"
#include "global.h"

#ifdef VPORTS

int 
vports_init(void)
{
	FILE	*f1;
	char	s[PATH_MAX], s2[16];
	int	max;
	u_char	cid[16];

	snprintf(s,sizeof(s),"%s/%s", radius_dir, RADIUS_VPORTS);
	f1 = fopen(s, "rt");
	if (f1 != NULL) {
		debug("Found VPORTS, reading in list\n");
		while(fgets(s, 256, f1) != NULL) {
			s[strlen(s)-1] = '\0';	/* Strip off CR */
			sscanf(s, "%s %s", cid, s2);
			max = atoi(s2);
			create_cidlist(cid, max);
		}
		fclose(f1);
		return 1;
	}
	return 0;
}

VP_CALLED * 
begin_cidlist(void)
{
	if ((cidfirst = malloc(sizeof(VP_CALLED))) == NULL) {
		log_err("begin_cidlist: Could not allocate memory!\n");
		rad_exit(-1);
	}
	cidfirst->next = NULL;
	cidfirst->prev = NULL;
	cidlast = cidfirst;
	vp_cidinit = VP_LIST_INIT;
	return (VP_CALLED *)cidfirst;
}

VP_CALLED *
new_cidlist(void)
{
	VP_CALLED *cidcur;

	if (vp_cidinit != VP_LIST_INIT) {
		cidcur = begin_cidlist();
		strcpy(cidcur->num, "");
		cidcur->max = 0;
		cidcur->nasipinit = 0;
		return (VP_CALLED *)cidcur;
	}
	if ((cidcur = malloc(sizeof(VP_CALLED))) == NULL) {
		log_err("new_cidlist: Could not allocate memory!\n");
		rad_exit(-1);
	}
	cidcur->next = NULL;
	cidcur->prev = cidlast;
	cidlast->next = cidcur;
	cidlast = cidcur;
	strcpy(cidcur->num, "");
	cidcur->max = 0;
	cidcur->nasipinit = 0;
	return (VP_CALLED *)cidcur;
}

VP_CALLED *
get_cidlist(u_char *num)
{
	VP_CALLED *cidcur;

	cidcur = cidfirst;
	while(cidcur != NULL) {
		if (!strcmp(cidcur->num, num)) {
			return (VP_CALLED *)cidcur;
		}
		cidcur = cidcur->next;
	}
	return (VP_CALLED *)NULL;
}

void 
create_cidlist(u_char*num,int max)
{
	VP_CALLED *cidcur;

	if ((cidcur = get_cidlist(num)) != NULL) {
		/* Woops!  Duplicate, reset Log a warning here maybe? */
		cidcur->max = max;
		return;
	}
	cidcur = new_cidlist();
	strcpy(cidcur->num, num);
	cidcur->max = max;
	return;
}

int 
vports_in_use(VP_CALLED *cidcur)
{
	VP_NAS	*nasip_cur;
	VP_ACCTID	*acctid_cur;
	u_int		ret;

	ret = 0;
	if (cidcur->nasipinit == VP_LIST_INIT) {
		nasip_cur = cidcur->nasip_first;
		while(nasip_cur != NULL) {
			if (nasip_cur->acctidinit == VP_LIST_INIT) {
				acctid_cur = nasip_cur->acctid_first;
				while(acctid_cur != NULL) {
					ret++;
					acctid_cur = acctid_cur->next;
				}
			}
			nasip_cur = nasip_cur->next;
		}
	}
	return ret;
}

int 
vports_in_cache(VP_CALLED *cidcur)
{
	VP_CALLCACHE	*cc_cur;
	u_int		ret;
	time_t		now;

	ret = 0;
	time(&now);
	if (cidcur->callcacheinit == VP_LIST_INIT) {
		cc_cur = cidcur->cc_first;
		while(cc_cur != NULL) {
			if (now >= (cc_cur->tm + VP_CACHE_EXPIRE)) {
				free_single_cclist(cidcur, cc_cur);
				cc_cur = cidcur->cc_first;
				continue;
			}
			cc_cur = cc_cur->next;
		}
		cc_cur = cidcur->cc_first;
		while(cc_cur != NULL) {
			ret++;
			cc_cur = cc_cur->next;
		}
	}
	return ret;
}
		
VP_NAS *
begin_nasiplist(VP_CALLED *cidcur)
{
	if ((cidcur->nasip_first = malloc(sizeof(VP_NAS))) == NULL) {
		log_err("begin_nasiplist: Could not allocate memory!\n");
		rad_exit(-1);
	}
	cidcur->nasip_first->next = NULL;
	cidcur->nasip_first->prev = NULL;
	cidcur->nasip_first->addr = 0;
	cidcur->nasip_first->acctidinit = 0;
	cidcur->nasip_last = cidcur->nasip_first;
	cidcur->nasipinit = VP_LIST_INIT;
	return (VP_NAS *)cidcur->nasip_first;
}

void 
free_single_nasiplist(VP_CALLED *cidcur,VP_NAS *nasip_cur)
{
	VP_NAS		*next, *prev;
	VP_ACCTID	*acctid_cur;

	if (nasip_cur->acctidinit == VP_LIST_INIT) {
		acctid_cur = nasip_cur->acctid_first;
		while(nasip_cur->acctid_first != NULL) {
			free_single_acctidlist(nasip_cur, nasip_cur->acctid_first);
		}
		nasip_cur->acctidinit = 0;
	}
	next = nasip_cur->next;
	prev = nasip_cur->prev;
	if (next != NULL) {
		next->prev = prev;
	}
	if (prev != NULL) {
		prev->next = next;
	}
	if (cidcur->nasip_first == nasip_cur) {
		cidcur->nasip_first = next;
	}
	if (cidcur->nasip_last == nasip_cur) {
		cidcur->nasip_last = prev;
	}
	free(nasip_cur);
	if (cidcur->nasip_first == NULL && cidcur->nasip_last == NULL) {
		cidcur->nasipinit = 0;
	}
	return;
}

VP_NAS *
get_nasiplist(VP_CALLED *cidcur,UINT4 addr)
{
	VP_NAS	*nasip_cur;

	if (cidcur->nasipinit != VP_LIST_INIT) {
		return (VP_NAS *)NULL;
	}
	nasip_cur = cidcur->nasip_first;
	while(nasip_cur != NULL && nasip_cur->addr != addr) {
		nasip_cur = nasip_cur->next; 
	} 
	return nasip_cur;
}

VP_NAS *
new_nasiplist(VP_CALLED *cidcur,UINT4 addr)
{
	VP_NAS	*nasip_cur;

	if ((nasip_cur = get_nasiplist(cidcur, addr)) != NULL) {
		return (VP_NAS *)nasip_cur;
	}
	if (cidcur->nasipinit != VP_LIST_INIT) {
		nasip_cur = begin_nasiplist(cidcur);
		nasip_cur->addr = addr;
		nasip_cur->acctidinit = 0;
		return (VP_NAS *)nasip_cur;
	}
	if ((nasip_cur = malloc(sizeof(VP_NAS))) == NULL) {
		log_err("new_nasiplist: Could not allocate memory!\n");
		rad_exit(-1);
	}
	nasip_cur->next = NULL;
	nasip_cur->prev = cidcur->nasip_last;
	nasip_cur->addr = addr;
	nasip_cur->acctidinit = 0;
	if (cidcur->nasip_last != NULL)
		cidcur->nasip_last->next = nasip_cur;
	cidcur->nasip_last = nasip_cur;
	return (VP_NAS *)nasip_cur;
}

VP_CALLCACHE* 
begin_cclist(VP_CALLED *cidcur)
{
	if ((cidcur->cc_first = malloc(sizeof(VP_CALLCACHE))) == NULL) {
		log_err("begin_cclist: Could not allocate memory!\n");
		rad_exit(-1);
	}
	cidcur->cc_first->next = NULL;
	cidcur->cc_first->prev = NULL;
	cidcur->cc_first->tm = 0;
	cidcur->cc_last = cidcur->cc_first;
	cidcur->callcacheinit = VP_LIST_INIT;
	return (VP_CALLCACHE *)cidcur->cc_first;
}

void 
free_single_cclist(VP_CALLED *cidcur,VP_CALLCACHE *cc_cur)
{
	VP_CALLCACHE	*next, *prev;

	next = cc_cur->next;
	prev = cc_cur->prev;
	if (next != NULL)
		next->prev = prev;
	if (prev != NULL)
		prev->next = next;
	if (cidcur->cc_first == cc_cur)
		cidcur->cc_first = next;
	if (cidcur->cc_last == cc_cur)
		cidcur->cc_last = prev;
	free(cc_cur);
	if (cidcur->cc_first == NULL && cidcur->cc_last == NULL)
		cidcur->callcacheinit = 0;
	return;
}

VP_CALLCACHE *
new_cclist(VP_CALLED *cidcur)
{
	VP_CALLCACHE	*cc_cur;

	if (cidcur->callcacheinit != VP_LIST_INIT) {
		cc_cur = begin_cclist(cidcur);
		time(&cc_cur->tm);
		return (VP_CALLCACHE *)cc_cur;
	}
	if ((cc_cur = malloc(sizeof(VP_CALLCACHE))) == NULL) {
		log_err("new_cclist: Could not allocate memory!\n");
		rad_exit(-1);
	}
	cc_cur->next = NULL;
	cc_cur->prev = cidcur->cc_last;
	time(&cc_cur->tm);
	if (cidcur->cc_last != NULL)
		cidcur->cc_last->next = cc_cur;
	cidcur->cc_last = cc_cur;
	return (VP_CALLCACHE *)cc_cur;
}

VP_ACCTID *
begin_acctidlist(VP_NAS *nasip_cur)
{
	if ((nasip_cur->acctid_first = malloc(sizeof(VP_ACCTID))) == NULL) {
		log_err("begin_acctidlist: Could not allocate memory!\n");
		rad_exit(-1);
	}
	nasip_cur->acctid_first->next = NULL;
	nasip_cur->acctid_first->prev = NULL;
	strcpy(nasip_cur->acctid_first->acctid, "");
	nasip_cur->acctid_last = nasip_cur->acctid_first;
	nasip_cur->acctidinit = VP_LIST_INIT;
	return (VP_ACCTID *)nasip_cur->acctid_first;
}

void 
free_single_acctidlist( VP_NAS *nasip_cur,VP_ACCTID *acctid_cur )
{
	VP_ACCTID	*next, *prev;

	next = acctid_cur->next;
	prev = acctid_cur->prev;
	if (next != NULL)
		next->prev = prev;
	if (prev != NULL)
		prev->next = next;
	if (nasip_cur->acctid_first == acctid_cur)
		nasip_cur->acctid_first = next;
	if (nasip_cur->acctid_last == acctid_cur)
		nasip_cur->acctid_last = prev;
	free(acctid_cur);
	if (nasip_cur->acctid_first == NULL && nasip_cur->acctid_last == NULL)
		nasip_cur->acctidinit = 0;
	return;
}

VP_ACCTID * 
get_acctidlist( VP_NAS *nasip_cur,u_char *acctid )
{
	VP_ACCTID	*acctid_cur;

	if (nasip_cur->acctidinit != VP_LIST_INIT)
		return (VP_ACCTID *)NULL;
	acctid_cur = nasip_cur->acctid_first;
	while(acctid_cur != NULL) {
		if (!strcmp(acctid_cur->acctid, acctid))
			return (VP_ACCTID *)acctid_cur;
		acctid_cur = acctid_cur->next;
	}
	return (VP_ACCTID *)NULL;
}

VP_ACCTID * 
new_acctidlist(VP_NAS *nasip_cur,u_char *acctid)
{
	VP_ACCTID	*acctid_cur;

	if ((acctid_cur = get_acctidlist(nasip_cur, acctid)) != NULL) {
		/* How did this happen???? */
		return (VP_ACCTID *)acctid_cur;
	}
	if (nasip_cur->acctidinit != VP_LIST_INIT) {
		acctid_cur = begin_acctidlist(nasip_cur);
		strcpy(acctid_cur->acctid, acctid);
		return (VP_ACCTID *)acctid_cur;
	}
	if ((acctid_cur = malloc(sizeof(VP_ACCTID))) == NULL) {
		log_err("new_acctidlist: Could not allocate memory!\n");
		rad_exit(-1);
	}
	acctid_cur->next = NULL;
	acctid_cur->prev = nasip_cur->acctid_last;
	strcpy(acctid_cur->acctid, acctid);
	if (nasip_cur->acctid_last != NULL)
		nasip_cur->acctid_last->next = acctid_cur;
	nasip_cur->acctid_last = acctid_cur;
	return (VP_ACCTID *)acctid_cur;
}

int 
vp_check_req(AUTH_REQ *authreq)
{
	VALUE_PAIR		*vp;
	VP_CALLED		*cidcur;
	UINT4			addr;
	u_char			called_sid[16];
	int			required;
	int			in_use;
	int			service_type;

	required = 0;

	vp = authreq->request;
	while(vp != NULL) {
		switch(vp->attribute) {
			case PW_USER_SERVICE_TYPE:
				required++;
				service_type = vp->lvalue;
				break;

			case PW_CLIENT_ID:
				required++;
				addr = vp->lvalue;
				break;

			case PW_CALLED:
				required++;
				strcpy(called_sid, vp->strvalue);
				break;
		}
		vp = vp->next;
	}
	if (required != 3)
		return VP_RET_IGNORE;
	if (service_type != PW_CALL_CHECK_USER
	    && service_type != PW_OLD_CALL_CHECK_USER)
		return VP_RET_IGNORE;
	cidcur = get_cidlist(called_sid);
	if (cidcur == NULL)
		return VP_RET_IGNORE;
	in_use = vports_in_use(cidcur) + vports_in_cache(cidcur);
	if (in_use >= cidcur->max)
	{
		debug("VPORTS: Rejecting Request, no ports available in pool %s [%d inuse, %d cached, %d max]\n",
				cidcur->num, vports_in_use(cidcur),
				vports_in_cache(cidcur), cidcur->max);
		return VP_RET_REJECT;
	}
	else
	{
		new_cclist(cidcur);
		debug("VPORTS: Accepting Request to Virtual Pool %s [%d inuse, %d cached, %d max]\n",
				cidcur->num, vports_in_use(cidcur),
				vports_in_cache(cidcur), cidcur->max);
		return VP_RET_ACCEPT;
	}
}

void 
vp_update_cid(AUTH_REQ*authreq)
{
	VALUE_PAIR		*vp;
	VP_CALLED		*cidcur;
	VP_NAS			*nasip_cur;
	VP_ACCTID		*acctid_cur;
	UINT4			addr;
	u_char			called_sid[16];
	u_char			acct_id[16];
	u_char			reboot_req;
	u_char			required;
	u_int			record_type;

	reboot_req = 0;
	required = 0;

	vp = authreq->request;
	while(vp != NULL) {
		switch(vp->attribute) {
		case PW_USER_NAME:
			if (strcmp(vp->strvalue, ""))
				reboot_req++;
			break;

		case PW_CLIENT_ID:
			required++;
			addr = vp->lvalue;
			break;

		case PW_ACCT_STATUS_TYPE:
			required++;
			record_type = vp->lvalue;
			if (record_type == PW_STATUS_STOP)
				reboot_req++;
			break;

		case PW_ACCT_SESSION_ID:
			required++;
			strcpy(acct_id, vp->strvalue);
			break;

		case PW_CALLED:
			required++;
			strcpy(called_sid, vp->strvalue);
			break;
		}
		vp = vp->next;
	}
	if (required != 4)
		return;
	if (reboot_req == 0) {
		debug("vports: NAS %s rebooted - clearing ports\n",
			ipaddr2strp(addr));
		cidcur = cidfirst;
		while(cidcur != NULL) {
			nasip_cur = get_nasiplist(cidcur, addr);
			if (nasip_cur != NULL) {
				free_single_nasiplist(cidcur, nasip_cur);
			}
			cidcur = cidcur->next;
		}
		return;
	}
	cidcur = get_cidlist(called_sid);
	if (cidcur == NULL) {
		return;
	}

	switch(record_type) {
	case PW_STATUS_START:
		if (vports_in_cache(cidcur) > 0) {
			free_single_cclist(cidcur, cidcur->cc_first);
		}
		nasip_cur = new_nasiplist(cidcur, addr);
		acctid_cur = new_acctidlist(nasip_cur, acct_id);
		debug("VPORTS: Added Session ID %s to the %s pool [%d inuse, %d cached, %d max]\n",
		acct_id, called_sid, vports_in_use(cidcur),
		vports_in_cache(cidcur), cidcur->max);
		break;

	case PW_STATUS_STOP:
		nasip_cur = get_nasiplist(cidcur, addr);
		if (nasip_cur != NULL) {
			acctid_cur = get_acctidlist(nasip_cur, acct_id);
			if (acctid_cur != NULL)
			{
				free_single_acctidlist(nasip_cur, acctid_cur);
				debug("VPORTS: Removed Session ID %s from the %s pool [%d inuse, %d cached, %d max]\n",
				acct_id, called_sid, vports_in_use(cidcur),
				vports_in_cache(cidcur), cidcur->max);
			}
		}
		break;
	default:
		break;
	}

	return;
}

#endif /* VPORTS */
