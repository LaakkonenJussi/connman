/*
 *
 *  Connection Manager
 *
 *  Copyright (C) 2020  Jolla Ltd.
 *  Copyright (C) 2020  Open Mobile Platform LLC.
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

#ifdef HAVE_CONFIG_H
#include <config.h>
#endif

#include <errno.h>
#include <stdio.h>
#include <string.h>

#include <glib.h>
#include <systemd/sd-login.h>

#include "connman.h"

#define DEFAULT_SEAT "seat0"

enum sd_session_state {
	/* Invalid and for handling future states, which are ignored. */
	SD_SESSION_UNDEF,
	/* user not logged in */
	SD_SESSION_OFFLINE,
	/* user not logged in, but some user services running */
	SD_SESSION_LINGERING,
	/*
	 * non-documented state - apparently preceeds session active state.
	 * https://github.com/systemd/systemd/blob/master/src/login/
	 * logind-user.c#L878
	 */
	SD_SESSION_OPENING,
	/*
	 * user logged in, but not active, i.e. has no session in the
	 *foreground
	 */
	SD_SESSION_ONLINE,
	/*
	 * user logged in, and has at least one active session, i.e. one
	 * session in the foreground.
	 */
	SD_SESSION_ACTIVE,
	/*
	 * user not logged in, and not lingering, but some processes are still
	 * around.
	 */
	SD_SESSION_CLOSING,
};

enum sl_state {
	SL_IDLE = 0,
	SL_SD_INITIALIZED,
	SL_CONNECTED,
	SL_INITIAL_STATUS_CHECK,
	SL_STATUS_CHECK,
	SL_WAITING_USER_CHANGE_REPLY,
	SL_WAITING_USER_CHANGE_REPLY_AND_DELAYED,
};

struct systemd_login_data {
	enum sl_state state;
	enum sl_state old_state;
	uid_t active_uid;
	sd_login_monitor *login_monitor;
	GIOChannel *iochannel_in;
	guint iochannel_in_id;
	guint restore_sd_connection_id;
	guint delayed_status_check_id;
	bool prepare_only;
	int pending_replies;
};

struct systemd_login_data *login_data = NULL;

static const char *state2string(enum sl_state state)
{
	switch (state) {
	case SL_IDLE:
		return "idle";
	case SL_SD_INITIALIZED:
		return "initialized";
	case SL_CONNECTED:
		return "connected";
	case SL_INITIAL_STATUS_CHECK:
		return "initial status check";
	case SL_STATUS_CHECK:
		return "status check";
	case SL_WAITING_USER_CHANGE_REPLY:
		return "waiting reply";
	case SL_WAITING_USER_CHANGE_REPLY_AND_DELAYED:
		return "waiting reply and delayed";
	}

	return "invalid state";
}

static bool change_state(struct systemd_login_data *login_data,
			enum sl_state new_state)
{
	enum sl_state old_state;

	if (!login_data)
		return false;

	old_state = login_data->old_state;

	switch (login_data->state) {
	case SL_IDLE:
		switch (new_state) {
		case SL_IDLE:
			/* fall through */
		case SL_SD_INITIALIZED:
			break;
		default:
			goto err;
		}

		break;
	case SL_SD_INITIALIZED:
		switch (new_state) {
		case SL_IDLE:
			if (old_state != SL_CONNECTED)
				goto err;

			break;
		case SL_CONNECTED:
			/* fall through */
		case SL_INITIAL_STATUS_CHECK:
			if (old_state != SL_IDLE)
				goto err;

			break;
		default:
			goto err;
		}

		break;
	case SL_CONNECTED:
		switch (new_state) {
		case SL_SD_INITIALIZED:
			/* fall through */
		case SL_STATUS_CHECK:
			break;
		default:
			goto err;
		}

		break;
	case SL_INITIAL_STATUS_CHECK:
		switch (new_state) {
		case SL_SD_INITIALIZED:
			break;
		case SL_WAITING_USER_CHANGE_REPLY:
			if (old_state != SL_SD_INITIALIZED)
				goto err;

			break;
		default:
			goto err;
		}

		break;
	case SL_STATUS_CHECK:
		switch (new_state) {
		case SL_CONNECTED:
			break;
		case SL_WAITING_USER_CHANGE_REPLY:
			if (old_state != SL_CONNECTED)
				goto err;

			break;
		default:
			goto err;
		}

		break;
	case SL_WAITING_USER_CHANGE_REPLY:
		switch (new_state) {
		case SL_SD_INITIALIZED:
			if (old_state != SL_INITIAL_STATUS_CHECK)
				goto err;

			break;
		case SL_CONNECTED:
			/*
			 * While waiting for reply connection may have been
			 * established if in initial status check state.
			 */
			if (old_state != SL_INITIAL_STATUS_CHECK &&
						old_state != SL_STATUS_CHECK)
				goto err;

			break;
		case SL_WAITING_USER_CHANGE_REPLY_AND_DELAYED:
			if (old_state != SL_INITIAL_STATUS_CHECK &&
						old_state != SL_STATUS_CHECK)
				goto err;

			break;
		default:
			goto err;
		}

		break;
	case SL_WAITING_USER_CHANGE_REPLY_AND_DELAYED:
		switch (new_state) {
		case SL_SD_INITIALIZED:
			if (old_state != SL_WAITING_USER_CHANGE_REPLY)
				goto err;

			break;
		case SL_CONNECTED:
			if (old_state != SL_WAITING_USER_CHANGE_REPLY)
				goto err;

			break;
		case SL_STATUS_CHECK:
			if (old_state != SL_WAITING_USER_CHANGE_REPLY)
				goto err;

			break;
		default:
			goto err;
		}

		break;
	}

	DBG("state %d:%-26s -> %d:%s", login_data->state,
				state2string(login_data->state), new_state,
				state2string(new_state));

	login_data->old_state = login_data->state;
	login_data->state = new_state;

	return true;

err:
	DBG("invalid state change %d:%-26s -> %d:%s (old state %d:%s)",
				login_data->state,
				state2string(login_data->state), new_state,
				state2string(new_state), old_state,
				state2string(old_state));

	login_data->old_state = login_data->state;
	login_data->state = new_state;

	return false;
}

static bool is_conn_open(struct systemd_login_data *login_data)
{
	if (!login_data)
		return false;

	return login_data->prepare_only && !login_data->iochannel_in_id;
}

static enum sd_session_state get_session_state(const char *state)
{
	if (!g_strcmp0(state, "online"))
		return SD_SESSION_ONLINE;

	if (!g_strcmp0(state, "active"))
		return SD_SESSION_ACTIVE;

	if (!g_strcmp0(state, "closing"))
		return SD_SESSION_CLOSING;

	if (!g_strcmp0(state, "offline"))
		return SD_SESSION_OFFLINE;

	if (!g_strcmp0(state, "lingering"))
		return SD_SESSION_LINGERING;

	if (!g_strcmp0(state, "opening"))
		return SD_SESSION_OPENING;

	connman_warn("unknown sd_login state %s", state);

	return SD_SESSION_UNDEF;
}

#define USE_SIMPLE_SD_ACTIVE_CHECK

static bool get_session_uid_and_state(uid_t *uid,
			enum sd_session_state *session_state)
{
#ifdef USE_SIMPLE_SD_ACTIVE_CHECK
	char *session;
	char *state;
	int err;

	DBG("simple");

	*uid = 0;
	*session_state = SD_SESSION_UNDEF;

	err = sd_seat_get_active(DEFAULT_SEAT, &session, uid);
	if (err) {
		connman_warn("failed to get active session and/or user for "
					" seat %s", DEFAULT_SEAT);
		return false;
	}

	if (sd_session_is_remote(session) == 1) {
		DBG("ignore remote session %s", session);
		return false;
	}

	err = sd_uid_get_state(*uid, &state);
	if (err) {
		connman_warn("failed to get state for uid %d session %s",
					*uid, session);
		return false;
	}

	*session_state = get_session_state(state);

	g_free(session);
	g_free(state);

	return *session_state == SD_SESSION_UNDEF && *uid == 0 ? false : true;
#else
	char **sessions = NULL;
	char *seat;
	char *state;
	int err;
	int i;
	bool ignore_session = false;

	DBG("check sessions");

	err = sd_get_sessions(&sessions);
	if (err < 1 || !sessions) {
		connman_warn("failed to get systemd logind sessions");
		return false;
	}

	*uid = 0;
	*session_state = SD_SESSION_UNDEF;

	/*
	 * This assumes that there is only one real session with the
	 * DEFAULT_SEAT.
	 */
	for (i = 0; sessions[i]; i++) {
		ignore_session = false;

		err = sd_session_get_seat(sessions[i], &seat);
		if (err)
			continue; /* Ignore if failed or no seat. */

		if (g_ascii_strcasecmp(seat, DEFAULT_SEAT))
			ignore_session = true;

		g_free(seat);

		if (ignore_session)
			continue;
	
		err = sd_session_get_state(sessions[i], &state);
		if (err) {
			connman_warn("failed to get systemd logind session "
						"%s state", sessions[i]);
			continue;
		}

		*session_state = get_session_state(state);
		g_free(state);

		err = sd_session_get_uid(sessions[i], uid);
		if (err) {
			connman_warn("failed to get systemd logind session "
						"%s uid", sessions[i]);
			continue;
		}

		/* Found session with DEFAULT_SEAT, uid and state set, stop */
		break;
	}

	g_strfreev(sessions);

	return *session_state == SD_SESSION_UNDEF && *uid == 0 ? false : true;
#endif
}

static void user_change_result_cb(uid_t uid, int err, void *user_data)
{
	struct systemd_login_data *login_data = user_data;

	if (login_data->state != SL_WAITING_USER_CHANGE_REPLY &&
				login_data->state !=
				SL_WAITING_USER_CHANGE_REPLY_AND_DELAYED)
		DBG("invalid state %s", state2string(login_data->state));

	if (!login_data->pending_replies)
		connman_warn("not expecting a reply on user change result");
	else
		login_data->pending_replies--;

	DBG("pending_replies %d", login_data->pending_replies);

	/*
	 * In case there is an error the user change is not done and the
	 * active uid should be changed what is reported back. Usually
	 * storage reverts back to using root as user. Just report the error.
	 */
	if (err && err != -EINPROGRESS)
		connman_warn("user change to %d not successful %d:%s",
						login_data->active_uid, err,
						strerror(-err));

	if (uid != login_data->active_uid) {
		connman_warn("changed to different user %d than req (%d)", uid,
					login_data->active_uid);
		login_data->active_uid = uid;
	}

	if (login_data->pending_replies && err == -EINPROGRESS) {
		DBG("user change to %d is pending for reply", uid);
	} else {
		connman_info("user changed to %d", uid);
		change_state(login_data, is_conn_open(login_data) ?
					SL_SD_INITIALIZED : SL_CONNECTED);
	}
}

static int check_session_status(struct systemd_login_data *login_data)
{
	enum sd_session_state state;
	uid_t uid;
	int err = 0;

	if (login_data->state != SL_SD_INITIALIZED &&
				login_data->state != SL_CONNECTED) {
		DBG("invalid state %d:%s", login_data->state,
					state2string(login_data->state));
		return -EINVAL;
	}

	change_state(login_data, is_conn_open(login_data) ?
				SL_INITIAL_STATUS_CHECK : SL_STATUS_CHECK);

	if (!get_session_uid_and_state(&uid, &state)) {
		DBG("failed to get uid %d and/or state %d", uid, state);
		return -ENOENT;
	}

	switch (state) {
	case SD_SESSION_OFFLINE:
		DBG("user %d is offline", uid);
		goto out;
	case SD_SESSION_LINGERING:
		DBG("user %d is lingering", uid);
		goto out;
	case SD_SESSION_OPENING:
		DBG("user %d is opening session", uid);
		goto out;
	case SD_SESSION_ACTIVE:
		if (uid == login_data->active_uid)
			goto out;

		DBG("active user changed, change to uid %d", uid);
		login_data->active_uid = uid;
		goto reply;
	case SD_SESSION_ONLINE:
		if (uid == login_data->active_uid)
			DBG("user %d left foreground, wait for logout", uid);

		goto out;
	case SD_SESSION_CLOSING:
		DBG("logout, go to root");
		login_data->active_uid = 0;
		goto reply;
	case SD_SESSION_UNDEF:
		DBG("unsupported status");
		err = -EINVAL;
		goto out;
	}

reply:
	/*
	 * Change state before because when doing initial check.
	 * __connman_storage_change_user() calls the result cb immediately.
	 */
	change_state(login_data, SL_WAITING_USER_CHANGE_REPLY);

	/* Initial check expects 2 replies */
	login_data->pending_replies = login_data->prepare_only ? 2 : 1;

	err = __connman_storage_change_user(login_data->active_uid,
				user_change_result_cb, login_data,
				login_data->prepare_only);
	/* In case of error change state */
	if (err && err != -EINPROGRESS)
		goto out;

	return err;

out:
	change_state(login_data, is_conn_open(login_data) ?
				SL_SD_INITIALIZED : SL_CONNECTED);
	return err;
}

static int init_delayed_status_check(struct systemd_login_data *login_data);
static gboolean delayed_status_check(gpointer user_data);
static void clean_delayed_status_check(gpointer user_data);

static int do_session_status_check(struct systemd_login_data *login_data)
{
	int err;

	DBG("");

	switch (login_data->state) {
	case SL_IDLE:
		DBG("invalid state %d:%s", login_data->state,
					state2string(login_data->state));
		return -ENOTCONN;
	case SL_SD_INITIALIZED:
		DBG("initial session status check");
		login_data->prepare_only = true;
		return check_session_status(login_data);
	case SL_CONNECTED:
		DBG("check session status");
		login_data->prepare_only = false;
		return check_session_status(login_data);
	case SL_INITIAL_STATUS_CHECK:
		/* fall through */
	case SL_STATUS_CHECK:
		return -EINPROGRESS;
	case SL_WAITING_USER_CHANGE_REPLY:

		DBG("user change is pending");

		err = init_delayed_status_check(login_data);
		if (err)
			return err;

		change_state(login_data,
				SL_WAITING_USER_CHANGE_REPLY_AND_DELAYED);

		return -EINPROGRESS;
	case SL_WAITING_USER_CHANGE_REPLY_AND_DELAYED:
		return -EINPROGRESS;
	}

	return 0;
}

static gboolean delayed_status_check(gpointer user_data)
{
	struct systemd_login_data *login_data = user_data;
	int err;

	DBG("");

	if (login_data->state == SL_WAITING_USER_CHANGE_REPLY_AND_DELAYED) {
		DBG("reply pending and check already delayed, continue");
		return G_SOURCE_CONTINUE;
	}

	if (login_data->state != SL_CONNECTED) {
		DBG("invalid state %d:%s - continue", login_data->state,
					state2string(login_data->state));
		return G_SOURCE_CONTINUE;
	}

	err = do_session_status_check(login_data);
	if (err && err != -EINPROGRESS) {
		DBG("failed to check session status: %d:%s", err,
					strerror(-err));
		return G_SOURCE_CONTINUE;
	}

	login_data->delayed_status_check_id = 0;
	return G_SOURCE_REMOVE;
}

#define DELAYED_STATUS_CHECK_TIMEOUT 250

static int init_delayed_status_check(struct systemd_login_data *login_data)
{
	DBG("");

	if (!login_data)
		return -EINVAL;

	if (login_data->delayed_status_check_id) {
		DBG("delayed_status_check_id exists");
		return -EINPROGRESS;
	}

	login_data->delayed_status_check_id = g_timeout_add_full(
				G_PRIORITY_DEFAULT,
				DELAYED_STATUS_CHECK_TIMEOUT,
				delayed_status_check, login_data,
				clean_delayed_status_check);

	return 0;
}

static void clean_delayed_status_check(gpointer user_data)
{
	struct systemd_login_data *login_data = user_data;

	DBG("");

	if (login_data->delayed_status_check_id) {
		g_source_remove(login_data->delayed_status_check_id);
		login_data->delayed_status_check_id = 0;
	}
}

#define RESTORE_CONNETION_TIMEOUT 250

static gboolean restore_sd_connection(gpointer user_data);
static int init_restore_sd_connection(struct systemd_login_data *login_data);
static void clean_restore_sd_connection(gpointer user_data);
static void close_io_channel(struct systemd_login_data *login_data);

static gboolean io_channel_cb(GIOChannel *source, GIOCondition condition,
			gpointer user_data)
{
	struct systemd_login_data *login_data = user_data;
	int err;

	DBG("");

	if (login_data->state < SL_CONNECTED) {
		DBG("invalid state %d:%s", login_data->state,
					state2string(login_data->state));
		return -EINVAL;
	}

	if (condition && G_IO_IN) {
		err = init_delayed_status_check(login_data);
		if (err && err != -EINPROGRESS)
			DBG("failed to check session status");

		if (sd_login_monitor_flush(login_data->login_monitor))
			connman_warn("failed to flush systemd login monitor");

	} else if (condition && G_IO_ERR) {
		DBG("iochannel error, closing");
		close_io_channel(login_data);
		init_restore_sd_connection(login_data);
		return G_SOURCE_REMOVE;
	}

	return G_SOURCE_CONTINUE;
}

static int init_io_channel(struct systemd_login_data *login_data)
{
	int fd;

	DBG("");

	if (login_data->state < SL_SD_INITIALIZED) {
		DBG("invalid state %d:%s", login_data->state,
					state2string(login_data->state));
		return -EINVAL;
	}

	if (!login_data || !login_data->login_monitor)
		return -EINVAL;

	if (login_data->iochannel_in_id)
		return -EALREADY;

	fd = sd_login_monitor_get_fd(login_data->login_monitor);
	if (fd < 0) {
		connman_error("cannot init connection to systemd logind");
		return -ECONNABORTED;
	}

	login_data->iochannel_in = g_io_channel_unix_new(fd);
	login_data->iochannel_in_id = g_io_add_watch(login_data->iochannel_in,
				G_IO_IN | G_IO_ERR, (GIOFunc)io_channel_cb,
				login_data);

	/* user_change_result_cb() will set to SL_CONNECTED after completed */
	if (login_data->state != SL_WAITING_USER_CHANGE_REPLY)
		change_state(login_data, SL_CONNECTED);

	return 0;
}

static void close_io_channel(struct systemd_login_data *login_data)
{
	DBG("");

	/* Ignore invalid state */
	if (login_data->state < SL_CONNECTED)
		DBG("invalid state %d:%s", login_data->state,
					state2string(login_data->state));

	if (login_data->iochannel_in_id) {
		g_source_remove(login_data->iochannel_in_id);
		login_data->iochannel_in_id = 0;
	}

	if (login_data->iochannel_in) {
		g_io_channel_shutdown(login_data->iochannel_in, FALSE, NULL);
		g_io_channel_unref(login_data->iochannel_in);
		login_data->iochannel_in = NULL;
	}

	change_state(login_data, SL_SD_INITIALIZED);
}

static int init_sd_login_monitor(struct systemd_login_data *login_data)
{
	int err;

	DBG("");

	if (login_data->state > SL_IDLE) {
		DBG("invalid state %s", state2string(login_data->state));
		return -EINVAL;
	}

	if (login_data->login_monitor)
		return -EALREADY;

	err = sd_login_monitor_new("session", &login_data->login_monitor);
	if (err < 0) {
		connman_error("failed to init systemd login monitor %d:%s)",
					err, strerror(-err));
		login_data->login_monitor = NULL;
		err = -ECONNABORTED;
	}

	change_state(login_data, SL_SD_INITIALIZED);

	return err;
}

static void close_sd_login_monitor(struct systemd_login_data *login_data)
{
	DBG("");

	/* When closing ignore the state and go to idle */
	if (login_data->state > SL_SD_INITIALIZED)
		DBG("invalid state %d:%s", login_data->state,
					state2string(login_data->state));

	if (!login_data || !login_data->login_monitor)
		return;

	/* sd_login_monitor_unref returns NULL according to C API. */
	login_data->login_monitor =
			sd_login_monitor_unref(login_data->login_monitor);

	change_state(login_data, SL_IDLE);
}

static gboolean restore_sd_connection(gpointer user_data)
{
	struct systemd_login_data *login_data = user_data;
	int err;

	DBG("");

	if (login_data->state < SL_SD_INITIALIZED) {
		DBG("invalid state %d:%s", login_data->state,
					state2string(login_data->state));
		return G_SOURCE_CONTINUE;
	}

	if (login_data->login_monitor)
		close_sd_login_monitor(login_data);

	err = init_sd_login_monitor(login_data);
	if (err) {
		DBG("failed to initialize sd login monitor, retry");
		return G_SOURCE_CONTINUE; /* Try again later */
	}

	err = init_io_channel(login_data);
	if (err) {
		DBG("failed to init io channel, retry");
		close_io_channel(login_data);
		return G_SOURCE_CONTINUE; /* Try again later */
	}

	login_data->restore_sd_connection_id = 0;
	return G_SOURCE_REMOVE;
}

static int init_restore_sd_connection(struct systemd_login_data *login_data)
{
	DBG("");

	if (!login_data)
		return -EINVAL;

	if (login_data->restore_sd_connection_id) {
		DBG("restore_sd_connection_id exists");
		return -EINPROGRESS;
	}

	login_data->restore_sd_connection_id = g_timeout_add_full(
				G_PRIORITY_DEFAULT, RESTORE_CONNETION_TIMEOUT,
				restore_sd_connection, login_data,
				clean_restore_sd_connection);

	return 0;
}

static void clean_restore_sd_connection(gpointer user_data)
{
	struct systemd_login_data *login_data = user_data;

	if (login_data->restore_sd_connection_id) {
		g_source_remove(login_data->restore_sd_connection_id);
		login_data->restore_sd_connection_id = 0;
	}
}

int __systemd_login_init()
{
	int err;

	DBG("");

	if (login_data)
		return -EALREADY;
	
	login_data = g_new0(struct systemd_login_data, 1);

	err = init_sd_login_monitor(login_data);
	if (err) {
		connman_warn("failed to initialize login monitor");
		goto delayed;
	}

	/*
	 * With early, initial call do only preparing steps for user change
	 * since everything is not initialized yet. Both connmand and vpnd
	 * will return replies in this case.
	 */
	login_data->prepare_only = true;

	err = do_session_status_check(login_data);
	if (err && err != -EINPROGRESS)
		DBG("failed to get initial user login status");

	err = init_io_channel(login_data);
	if (err) {
		connman_warn("failed to initialize io channel");
		goto delayed;
	}

	return 0;

delayed:
	DBG("do delayed start");

	login_data->restore_sd_connection_id = g_timeout_add_full(
					G_PRIORITY_DEFAULT,
					RESTORE_CONNETION_TIMEOUT,
					restore_sd_connection, login_data,
					clean_restore_sd_connection);

	return -EINPROGRESS;
}

void __systemd_login_cleanup()
{
	DBG("");

	if (!login_data)
		return;

	clean_restore_sd_connection(login_data);
	clean_delayed_status_check(login_data);

	close_io_channel(login_data);
	close_sd_login_monitor(login_data);
	
	g_free(login_data);
	login_data = NULL;
}

