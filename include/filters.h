#ifndef __FILTERS_H
#define __FILTERS_H

/*
 * Copyright (C) 1999-2004, Francesco P. Lovergine. All rights reserved.
 *
 * This program is free software; you can redistribute it and/or modify
 * it under the terms stated in the LICENSE file which should be
 * enclosed with sources.
 */


/*
 * ASCEND extensions for ABINARY filters
 */

#define IPX_NODE_ADDR_LEN		6

typedef UINT4			IpxNet;
typedef char			IpxNode[ IPX_NODE_ADDR_LEN ];
typedef unsigned short		IpxSocket;

#if ! defined( FALSE )
# define FALSE		0
# define TRUE		(! FALSE)
#endif

/*
 * Two types of filters are supported, GENERIC and IP.  The identifiers
 * are:
 */

#define RAD_FILTER_GENERIC	0
#define RAD_FILTER_IP		1
#define RAD_FILTER_IPX		2

/*
 * Generic filters mask and match up to RAD_MAX_FILTER_LEN bytes
 * starting at some offset.  The length is:
 */
#define RAD_MAX_FILTER_LEN	6

/*
 * RadFilterComparison:
 *
 * An enumerated values for the IP filter port comparisons.
 */
typedef enum {
	RAD_NO_COMPARE,
	RAD_COMPARE_LESS,
	RAD_COMPARE_EQUAL,
	RAD_COMPARE_GREATER,
	RAD_COMPARE_NOT_EQUAL
} RadFilterComparison;

    /*
     * RadIpFilter:
     *
     * The binary format of an IP filter.  ALL fields are stored in
     * network byte order.
     *
     *	srcip:		The source IP address.
     *
     *	dstip:		The destination IP address.
     *
     *	srcmask:	The number of leading one bits in the source address
     *			mask.  Specifies the bits of interest.
     *
     *	dstmask:	The number of leading one bits in the destination
     *			address mask. Specifies the bits of interest.
     *
     *	proto:		The IP protocol number
     *
     *	establised:	A boolean value.  TRUE when we care about the
     *			established state of a TCP connection.  FALSE when
     *			we dont care.
     *
     *	srcport:	TCP or UDP source port number.
     *
     *	dstport:	TCP or UDP destination port number.
     *
     *	srcPortCmp:	One of the values of the RadFilterComparison enumeration
     *			specifying how to compare the srcport value.
     *
     *	dstPortCmp:	One of the values of the RadFilterComparison enumeration
     *			specifying how to compare the dstport value.
     *
     *	fill:		Round things out to a dword boundary.
     */
typedef struct radip {
    UINT4  		srcip;
    UINT4  		dstip;
    unsigned char 	srcmask;
    unsigned char 	dstmask;
    unsigned char	proto;
    unsigned char	established;
    unsigned short	srcport;
    unsigned short	dstport;
    unsigned char	srcPortComp;
    unsigned char	dstPortComp;
    unsigned char       fill[4];        /* used to be fill[2] */
} RadIpFilter;

    /*
     * RadIpxFilter:
     * The binary format of a GENERIC filter.  ALL fields are stored in
     * network byte order.
     *
     *  srcIpxNet:      Source IPX Net address
     *
     *  srcIpxNode:     Source IPX Node address
     *
     *  srcIpxSoc:      Source IPX socket address
     *
     *  dstIpxNet:      Destination IPX Net address
     *
     *  dstIpxNode:     Destination IPX Node address
     *
     *  dstIpxSoc:      Destination IPX socket address
     *
     *  srcSocComp:     Source socket compare value
     *
     *  dstSocComp:     Destination socket compare value
     *
     */
typedef struct radipx {                         
    IpxNet              srcIpxNet;                      /* LongWord */
    IpxNode             srcIpxNode;                     /* Byte[6] */
    IpxSocket           srcIpxSoc;                      /* Word */
    IpxNet              dstIpxNet;                      /* LongWord */
    IpxNode             dstIpxNode;                     /* Byte[6] */
    IpxSocket           dstIpxSoc;                      /* Word */
    unsigned char       srcSocComp;
    unsigned char       dstSocComp;
} RadIpxFilter;

    /*
     * RadGenericFilter:
     *
     * The binary format of a GENERIC filter.  ALL fields are stored in
     * network byte order.
     *
     *	offset:		Number of bytes into packet to start comparison.
     *
     *	len:		Number of bytes to mask and compare.  May not
     *			exceed RAD_MAX_FILTER_LEN.
     *
     *	more:		Boolean.  If non-zero the next filter entry is
     *			also to be applied to a packet.
     *
     *	mask:		A bit mask specifying the bits to compare.
     *
     *	value:		A value to compare against the masked bits at
     *			offset in a users packet.
     *			
     *	compNeq:	Defines type of comarison (Equal or Notequal)
     *			default is Equal.
     *
     *	fill:		Round things out to a dword boundary
     */
typedef struct radgeneric {
    unsigned short	offset;
    unsigned short	len;
    unsigned short	more;
    unsigned char	mask[ RAD_MAX_FILTER_LEN ];
    unsigned char	value[ RAD_MAX_FILTER_LEN ];
    unsigned char	compNeq;
    unsigned char       fill[3];        /* used to be fill */
} RadGenericFilter;

    /*
     * RadFilter:
     *
     * A binary filter element.  Contains either a RadIpFilter or a
     * RadGenericFilter.  All fields are stored in network byte order.
     *
     *	type:		Either RAD_FILTER_GENERIC or RAD_FILTER_IP.
     *
     *	forward:	TRUE if we should forward packets that match this
     *			filter, FALSE if we should drop packets that match
     *			this filter.
     *
     *	indirection:	TRUE if this is an input filter, FALSE if this is
     *			an output filter.
     *
     *	fill:		Round things out to a dword boundary.
     *
     *	u:		A union of
     *			ip:		An ip filter entry
     *			generic:	A generic filter entry
     */
typedef struct filter {
    unsigned char 	type;
    unsigned char	forward;
    unsigned char	indirection;
    unsigned char	fill;
    union {
	RadIpFilter   	 ip;
	RadIpxFilter   	 ipx;
	RadGenericFilter generic;
    } u;
} RadFilter;

#endif /* __FILTERS_H */

