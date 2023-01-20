/*
 *
 *  Connection Manager
 *
 *  Copyright (C) 2023 Jolla Ltd. All rights reserved.
 *
 *  This program is free software; you can redistribute it and/or modify
 *  it under the terms of the GNU General Public License version 2 as
 *  published by the Free Software Foundation.
 *
 *  This program is distributed in the hope that it will be useful,
 *  but WITHOUT ANY WARRANTY; without even the implied warranty of
 *  MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
 *  GNU General Public License for more details.
 *
 *  You should have received a copy of the GNU General Public License
 *  along with this program; if not, write to the Free Software
 *  Foundation, Inc., 51 Franklin St, Fifth Floor, Boston, MA  02110-1301  USA
 *
 */

#ifndef __CONNMAN_NAT_H
#define __CONNMAN_NAT_H

#include <connman/ipconfig.h>

#ifdef __cplusplus
extern "C" {
#endif

/**
 * SECTION:NAT
 * @title: NAT setup premitives
 * @short_description: Functions for NAT handling
 */

int connman_nat6_prepare(struct connman_ipconfig *ipconfig,
							const char *ifname_in,
							bool ndproxy);
void connman_nat6_restore(struct connman_ipconfig *ipconfig);

#ifdef __cplusplus
}
#endif

#endif /* __CONNMAN_IPCONFIG_H */
