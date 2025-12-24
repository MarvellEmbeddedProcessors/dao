/* SPDX-License-Identifier: Marvell-MIT
 * Copyright (c) 2025 Marvell.
 */

#include <errno.h>
#include <fcntl.h>
#include <stdbool.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/file.h>
#include <syslog.h>
#include <time.h>
#include <unistd.h>

#include "../utils/logging.h"
#include "lock.h"

#define OPERATION_MARKER_FILE "/var/lock/card_mgr_operation"
#define COOLDOWN_SECONDS      720 /* 12 minutes */

static int operation_fd = -1;
static char current_operation[64] = {0};
static time_t operation_start_time;

/* Check if previous operation was interrupted and enforce cooldown */
static int
check_interrupted_operation(int *age_out)
{
	char prev_operation[64] = {0};
	time_t now = time(NULL);
	long prev_time = 0;
	int age_sec;
	FILE *f;

	if (age_out)
		*age_out = 0;

	f = fopen(OPERATION_MARKER_FILE, "r");
	if (!f)
		return 0; /* No previous operation marker */

	if (fscanf(f, "%63s %ld", prev_operation, &prev_time) != 2) {
		fclose(f);
		/* Corrupted marker file, remove it */
		unlink(OPERATION_MARKER_FILE);
		return 0;
	}
	fclose(f);

	age_sec = (int)difftime(now, (time_t)prev_time);
	if (age_out)
		*age_out = age_sec;

	if (age_sec < COOLDOWN_SECONDS) {
		syslog(LOG_WARNING,
		       "OPERATION_INTERRUPTED: Previous '%s' was interrupted %d seconds ago. "
		       "Cooldown active, retry after %d seconds.",
		       prev_operation, age_sec, COOLDOWN_SECONDS - age_sec);
		return -EAGAIN;
	}

	/* Cooldown expired, log and allow new operation */
	syslog(LOG_INFO,
	       "OPERATION_RECOVERY: Previous '%s' was interrupted %d seconds ago. "
	       "Cooldown expired, allowing new operation.",
	       prev_operation, age_sec);

	return 0;
}

int
dao_card_operation_start(const char *operation)
{
	int remaining_min, remaining_sec;
	int age_sec = 0;
	int rc;
	FILE *f;

	if (!operation) {
		syslog(LOG_ERR, "OPERATION_ERROR: NULL operation name");
		return -EINVAL;
	}

	/* Check for double-start */
	if (operation_fd >= 0) {
		syslog(LOG_ERR, "OPERATION_ERROR: Operation already in progress");
		return -EALREADY;
	}

	/* Check for interrupted operation and cooldown */
	rc = check_interrupted_operation(&age_sec);
	if (rc != 0) {
		remaining_sec = COOLDOWN_SECONDS - age_sec;
		remaining_min = remaining_sec / 60;

		DAO_CARD_ERR("Previous update operation was interrupted or failed");
		DAO_CARD_ERR("Cooldown period active to allow card recovery");
		DAO_CARD_ERR("Next retry allowed in: %d minutes (%d seconds)", remaining_min,
			     remaining_sec);
		DAO_CARD_INFO("During cooldown:");
		DAO_CARD_INFO("  - Check card status via console or alternate method");
		DAO_CARD_INFO("  - Review system logs: journalctl -t dao-card-mgr");
		DAO_CARD_INFO("  - Verify network connectivity");
		DAO_CARD_INFO("  - If card not responding, boot from failsafe");
		return rc;
	}

	/* Create/open marker file with exclusive lock */
	operation_fd = open(OPERATION_MARKER_FILE, O_CREAT | O_RDWR, 0644);
	if (operation_fd < 0) {
		syslog(LOG_ERR, "OPERATION_ERROR: Failed to create marker file: %s",
		       strerror(errno));
		return -errno;
	}

	/* Try to acquire exclusive lock (non-blocking) */
	if (flock(operation_fd, LOCK_EX | LOCK_NB) != 0) {
		rc = -errno;
		close(operation_fd);
		operation_fd = -1;
		if (rc == -EWOULDBLOCK || rc == -EAGAIN) {
			syslog(LOG_ERR,
			       "OPERATION_BUSY: Another card manager process is running an update");
			DAO_CARD_ERR("Another update operation is in progress");
			return -EBUSY;
		}
		syslog(LOG_ERR, "OPERATION_ERROR: flock failed: %s", strerror(errno));
		return rc;
	}

	/* Write operation name and timestamp */
	operation_start_time = time(NULL);
	strncpy(current_operation, operation, sizeof(current_operation) - 1);
	current_operation[sizeof(current_operation) - 1] = '\0';

	f = fdopen(dup(operation_fd), "w");
	if (f) {
		fprintf(f, "%s %ld\n", current_operation, (long)operation_start_time);
		fflush(f);
		fclose(f);
	}

	syslog(LOG_INFO, "OPERATION_START: pid=%d operation=%s", getpid(), operation);

	return 0;
}

void
dao_card_operation_end(bool success)
{
	time_t now;
	int duration;

	if (operation_fd < 0) {
		syslog(LOG_WARNING, "OPERATION_WARNING: No operation to end");
		return;
	}

	now = time(NULL);
	duration = (int)difftime(now, operation_start_time);

	if (success) {
		syslog(LOG_INFO, "OPERATION_SUCCESS: pid=%d operation=%s duration=%ds", getpid(),
		       current_operation, duration);
	} else {
		syslog(LOG_WARNING,
		       "OPERATION_FAILED: pid=%d operation=%s duration=%ds "
		       "marker_preserved_for_cooldown=true",
		       getpid(), current_operation, duration);
	}

	/* Release lock and close */
	flock(operation_fd, LOCK_UN);
	close(operation_fd);
	operation_fd = -1;

	if (success) {
		/* Remove marker file only on successful completion */
		if (unlink(OPERATION_MARKER_FILE) != 0 && errno != ENOENT) {
			syslog(LOG_WARNING, "OPERATION_WARNING: Failed to remove marker file: %s",
			       strerror(errno));
		}
	} else {
		/* Keep marker file on failure - enforces cooldown */
		syslog(LOG_INFO,
		       "OPERATION_MARKER: Marker file preserved at %s for 12-minute cooldown",
		       OPERATION_MARKER_FILE);
	}

	memset(current_operation, 0, sizeof(current_operation));
	operation_start_time = 0;
}
