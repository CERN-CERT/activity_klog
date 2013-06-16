/* This file is included for retro-compatibility purposes */

#include <linux/version.h>
#if LINUX_VERSION_CODE < KERNEL_VERSION(2, 6, 20)

#include <linux/ctype.h>
#include <linux/net.h>
#include <linux/in.h>
#include <linux/ipv6.h>

/* Ugly hack for kstrtoint */
int kstrtoint(const char *s, unsigned int base, int *res)
{
	long tmp;
	int err;

	err = strict_strtol(s, base, &tmp);
	if (err != 0)
		return err;
	if (tmp > INT_MAX || tmp < INT_MIN)
		return -1;
	*res = tmp;
	return 0;
}

/* From lib/hexdump.c */

/*
 * lib/hexdump.c
 *
 * This program is free software; you can redistribute it and/or modify
 * it under the terms of the GNU General Public License version 2 as
 * published by the Free Software Foundation. See README and COPYING for
 * more details.
 */

/**
 * hex_to_bin - convert a hex digit to its real value
 * @ch: ascii character represents hex digit
 *
 * hex_to_bin() converts one hex digit to its actual value or -1 in case of bad
 * input.
 */
static int hex_to_bin(char ch)
{
	if ((ch >= '0') && (ch <= '9'))
		return ch - '0';
	ch = tolower(ch);
	if ((ch >= 'a') && (ch <= 'f'))
		return ch - 'a' + 10;
	return -1;
}

/* From net/core/utils.c */

/*
 *	Generic address resultion entity
 *
 *	Authors:
 *	net_random Alan Cox
 *	net_ratelimit Andi Kleen
 *	in{4,6}_pton YOSHIFUJI Hideaki, Copyright (C)2006 USAGI/WIDE Project
 *
 *	Created by Alexey Kuznetsov <kuznet@ms2.inr.ac.ru>
 *
 *	This program is free software; you can redistribute it and/or
 *      modify it under the terms of the GNU General Public License
 *      as published by the Free Software Foundation; either version
 *      2 of the License, or (at your option) any later version.
 */

#define IN6PTON_XDIGIT		0x00010000
#define IN6PTON_DIGIT		0x00020000
#define IN6PTON_COLON_MASK	0x00700000
#define IN6PTON_COLON_1		0x00100000	/* single : requested */
#define IN6PTON_COLON_2		0x00200000	/* second : requested */
#define IN6PTON_COLON_1_2	0x00400000	/* :: requested */
#define IN6PTON_DOT		0x00800000	/* . */
#define IN6PTON_DELIM		0x10000000
#define IN6PTON_NULL		0x20000000	/* first/tail */
#define IN6PTON_UNKNOWN		0x40000000

static inline int xdigit2bin(char c, int delim)
{
	int val;

	if (c == delim || c == '\0')
		return IN6PTON_DELIM;
	if (c == ':')
		return IN6PTON_COLON_MASK;
	if (c == '.')
		return IN6PTON_DOT;

	val = hex_to_bin(c);
	if (val >= 0)
		return val | IN6PTON_XDIGIT | (val < 10 ? IN6PTON_DIGIT : 0);

	if (delim == -1)
		return IN6PTON_DELIM;
	return IN6PTON_UNKNOWN;
}

/**
 * in4_pton - convert an IPv4 address from literal to binary representation
 * @src: the start of the IPv4 address string
 * @srclen: the length of the string, -1 means strlen(src)
 * @dst: the binary (u8[4] array) representation of the IPv4 address
 * @delim: the delimiter of the IPv4 address in @src, -1 means no delimiter
 * @end: A pointer to the end of the parsed string will be placed here
 *
 * Return one on success, return zero when any error occurs
 * and @end will point to the end of the parsed string.
 *
 */
int in4_pton(const char *src, int srclen,
	     u8 *dst,
	     int delim, const char **end)
{
	const char *s;
	u8 *d;
	u8 dbuf[4];
	int ret = 0;
	int i;
	int w = 0;

	if (srclen < 0)
		srclen = strlen(src);
	s = src;
	d = dbuf;
	i = 0;
	while(1) {
		int c;
		c = xdigit2bin(srclen > 0 ? *s : '\0', delim);
		if (!(c & (IN6PTON_DIGIT | IN6PTON_DOT | IN6PTON_DELIM | IN6PTON_COLON_MASK))) {
			goto out;
		}
		if (c & (IN6PTON_DOT | IN6PTON_DELIM | IN6PTON_COLON_MASK)) {
			if (w == 0)
				goto out;
			*d++ = w & 0xff;
			w = 0;
			i++;
			if (c & (IN6PTON_DELIM | IN6PTON_COLON_MASK)) {
				if (i != 4)
					goto out;
				break;
			}
			goto cont;
		}
		w = (w * 10) + c;
		if ((w & 0xffff) > 255) {
			goto out;
		}
cont:
		if (i >= 4)
			goto out;
		s++;
		srclen--;
	}
	ret = 1;
	memcpy(dst, dbuf, sizeof(dbuf));
out:
	if (end)
		*end = s;
	return ret;
}

/**
 * in6_pton - convert an IPv6 address from literal to binary representation
 * @src: the start of the IPv6 address string
 * @srclen: the length of the string, -1 means strlen(src)
 * @dst: the binary (u8[16] array) representation of the IPv6 address
 * @delim: the delimiter of the IPv6 address in @src, -1 means no delimiter
 * @end: A pointer to the end of the parsed string will be placed here
 *
 * Return one on success, return zero when any error occurs
 * and @end will point to the end of the parsed string.
 *
 */
int in6_pton(const char *src, int srclen,
	     u8 *dst,
	     int delim, const char **end)
{
	const char *s, *tok = NULL;
	u8 *d, *dc = NULL;
	u8 dbuf[16];
	int ret = 0;
	int i;
	int state = IN6PTON_COLON_1_2 | IN6PTON_XDIGIT | IN6PTON_NULL;
	int w = 0;

	memset(dbuf, 0, sizeof(dbuf));

	s = src;
	d = dbuf;
	if (srclen < 0)
		srclen = strlen(src);

	while (1) {
		int c;

		c = xdigit2bin(srclen > 0 ? *s : '\0', delim);
		if (!(c & state))
			goto out;
		if (c & (IN6PTON_DELIM | IN6PTON_COLON_MASK)) {
			/* process one 16-bit word */
			if (!(state & IN6PTON_NULL)) {
				*d++ = (w >> 8) & 0xff;
				*d++ = w & 0xff;
			}
			w = 0;
			if (c & IN6PTON_DELIM) {
				/* We've processed last word */
				break;
			}
			/*
			 * COLON_1 => XDIGIT
			 * COLON_2 => XDIGIT|DELIM
			 * COLON_1_2 => COLON_2
			 */
			switch (state & IN6PTON_COLON_MASK) {
			case IN6PTON_COLON_2:
				dc = d;
				state = IN6PTON_XDIGIT | IN6PTON_DELIM;
				if (dc - dbuf >= sizeof(dbuf))
					state |= IN6PTON_NULL;
				break;
			case IN6PTON_COLON_1|IN6PTON_COLON_1_2:
				state = IN6PTON_XDIGIT | IN6PTON_COLON_2;
				break;
			case IN6PTON_COLON_1:
				state = IN6PTON_XDIGIT;
				break;
			case IN6PTON_COLON_1_2:
				state = IN6PTON_COLON_2;
				break;
			default:
				state = 0;
			}
			tok = s + 1;
			goto cont;
		}

		if (c & IN6PTON_DOT) {
			ret = in4_pton(tok ? tok : s, srclen + (int)(s - tok), d, delim, &s);
			if (ret > 0) {
				d += 4;
				break;
			}
			goto out;
		}

		w = (w << 4) | (0xff & c);
		state = IN6PTON_COLON_1 | IN6PTON_DELIM;
		if (!(w & 0xf000)) {
			state |= IN6PTON_XDIGIT;
		}
		if (!dc && d + 2 < dbuf + sizeof(dbuf)) {
			state |= IN6PTON_COLON_1_2;
			state &= ~IN6PTON_DELIM;
		}
		if (d + 2 >= dbuf + sizeof(dbuf)) {
			state &= ~(IN6PTON_COLON_1|IN6PTON_COLON_1_2);
		}
cont:
		if ((dc && d + 4 < dbuf + sizeof(dbuf)) ||
		    d + 4 == dbuf + sizeof(dbuf)) {
			state |= IN6PTON_DOT;
		}
		if (d >= dbuf + sizeof(dbuf)) {
			state &= ~(IN6PTON_XDIGIT|IN6PTON_COLON_MASK);
		}
		s++;
		srclen--;
	}

	i = 15; d--;

	if (dc) {
		while(d >= dc)
			dst[i--] = *d--;
		while(i >= dc - dbuf)
			dst[i--] = 0;
		while(i >= 0)
			dst[i--] = *d--;
	} else
		memcpy(dst, dbuf, sizeof(dbuf));

	ret = 1;
out:
	if (end)
		*end = s;
	return ret;
}

/* From inet_utils.c */

/* Needed in order to convert binary network address to readable.
 * these macros were existing in previous kernel versions but were removed.
 * NIPQUAD is for IPv4 and NIP6 for IPv6 addresses.
 */

#ifndef NIPQUAD
	#define NIPQUAD(addr) \
	    ((unsigned char *)&addr)[0], \
	    ((unsigned char *)&addr)[1], \
	    ((unsigned char *)&addr)[2], \
	    ((unsigned char *)&addr)[3]
#endif

#ifndef NIP6
	#define NIP6(addr) \
	    ntohs((addr).s6_addr16[0]), \
	    ntohs((addr).s6_addr16[1]), \
	    ntohs((addr).s6_addr16[2]), \
	    ntohs((addr).s6_addr16[3]), \
	    ntohs((addr).s6_addr16[4]), \
	    ntohs((addr).s6_addr16[5]), \
	    ntohs((addr).s6_addr16[6]), \
	    ntohs((addr).s6_addr16[7])
#endif

struct in_addr ip4;
                struct in6_addr ip6;


size_t print_ipv4(char *buf, const struct in_addr *ip4)
{
	return (size_t) sprintf(buf, "%u.%u.%u.%u", NIPQUAD(*ip4));
}

size_t print_ipv6(char *buf, const struct in6_addr *ip6)
{
	return (size_t) sprintf(buf, "[%04x:%04x:%04x:%04x:%04x:%04x:%04x:%04x]", NIP6(*ip6));
}
#endif
