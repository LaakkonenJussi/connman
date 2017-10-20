/*
 *  Connection Manager content from gdbus.h for external plugins.
 *
 *  Copyright (C) 2017 Jolla Ltd. All rights reserved.
 *  Contact: Jussi Laakkonen <jussi.laakkonen@jolla.com>
 *
 *  This program is free software; you can redistribute it and/or modify
 *  it under the terms of the GNU General Public License version 2 as
 *  published by the Free Software Foundation.
 *
 *  This program is distributed in the hope that it will be useful,
 *  but WITHOUT ANY WARRANTY; without even the implied warranty of
 *  MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
 *  GNU General Public License for more details.
 */
 
#ifndef __GDBUS_EXTERNAL_USE_H
#define __GDBUS_EXTERNAL_USE_H

#ifdef __cplusplus
extern "C" {
#endif

typedef DBusMessage * (* GDBusMethodFunction) (DBusConnection *connection,
					DBusMessage *message, void *user_data);

typedef void (* GDBusDestroyFunction) (void *user_data);

enum GDBusMethodFlags {
	G_DBUS_METHOD_FLAG_DEPRECATED   = (1 << 0),
	G_DBUS_METHOD_FLAG_NOREPLY      = (1 << 1),
	G_DBUS_METHOD_FLAG_ASYNC        = (1 << 2),
	G_DBUS_METHOD_FLAG_EXPERIMENTAL = (1 << 3),
};

enum GDBusSignalFlags {
	G_DBUS_SIGNAL_FLAG_DEPRECATED   = (1 << 0),
	G_DBUS_SIGNAL_FLAG_EXPERIMENTAL = (1 << 1),
};


typedef enum GDBusMethodFlags GDBusMethodFlags;
typedef enum GDBusSignalFlags GDBusSignalFlags;
typedef struct GDBusPropertyTable GDBusPropertyTable;

typedef struct GDBusArgInfo {
	const char *name;
	const char *signature;
} GDBusArgInfo;

typedef struct GDBusMethodTable {
	const char *name;
	GDBusMethodFunction function;
	GDBusMethodFlags flags;
	unsigned int privilege;
	const GDBusArgInfo *in_args;
	const GDBusArgInfo *out_args;
} GDBusMethodTable;

typedef struct GDBusSignalTable {
	const char *name;
	GDBusSignalFlags flags;
	const GDBusArgInfo *args;
} GDBusSignalTable;


#define GDBUS_ARGS(args...) (const GDBusArgInfo[]) { args, { } }

#define GDBUS_METHOD(_name, _in_args, _out_args, _function) \
	.name = _name, \
	.in_args = _in_args, \
	.out_args = _out_args, \
	.function = _function
	
#define GDBUS_ASYNC_METHOD(_name, _in_args, _out_args, _function) \
	.name = _name, \
	.in_args = _in_args, \
	.out_args = _out_args, \
	.function = _function, \
	.flags = G_DBUS_METHOD_FLAG_ASYNC

#define GDBUS_SIGNAL(_name, _args) \
	.name = _name, \
	.args = _args

gboolean g_dbus_register_interface(DBusConnection *connection,
					const char *path, const char *name,
					const GDBusMethodTable *methods,
					const GDBusSignalTable *signals,
					const GDBusPropertyTable *properties,
					void *user_data,
					GDBusDestroyFunction destroy);
gboolean g_dbus_unregister_interface(DBusConnection *connection,
					const char *path, const char *name);

gboolean g_dbus_send_message(DBusConnection *connection, DBusMessage *message);

DBusMessage *g_dbus_create_error(DBusMessage *message, const char *name,
						const char *format, ...);

#ifdef __cplusplus
}
#endif

#endif
