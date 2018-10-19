/*
* This program is free software; you can redistribute it and/or modify
* it under the terms of the GNU General Public License as published by
* the Free Software Foundation; either version 2 of the License, or
* (at your option) any later version.
*
* This program is distributed in the hope that it will be useful,
* but WITHOUT ANY WARRANTY; without even the implied warranty of
* MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
* GNU General Public License for more details.
*
* You should have received a copy of the GNU General Public License
* along with this program; if not, write to the Free Software
* Foundation, Inc., 59 Temple Place, Suite 330, Boston, MA  02111-1307  USA
*/

/* All data returned by the network data base library are supplied in
   host order and returned in network order (suitable for use in
   system calls).  */

#ifndef	_ETHERNETDB_H
#define	_ETHERNETDB_H	1

#include <features.h>
#include <netinet/in.h>
#include <stdint.h>

/* Absolute file name for network data base files.  */
#ifndef	_XT_PATH_ETHERTYPES
#define	_XT_PATH_ETHERTYPES	"/etc/ethertypes"
#endif				/* _PATH_ETHERTYPES */

struct xt_ethertypeent {
	char *e_name;		/* Official ethernet type name.  */
	char **e_aliases;	/* Alias list.  */
	int e_ethertype;	/* Ethernet type number.  */
};

/* Return entry from ethertype data base for network with NAME.  */
extern struct xt_ethertypeent *xtables_getethertypebyname(__const char *__name);

/* Return entry from ethertype data base which number is PROTO.  */
extern struct xt_ethertypeent *xtables_getethertypebynumber(int __ethertype);

#endif				/* ethernetdb.h */
