/*
 * Copyright (c) 2003 Niels Provos <provos@citi.umich.edu>
 * All rights reserved.
 *
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

#include <sys/types.h>
#include <sys/param.h>
#ifdef HAVE_CONFIG_H
#include "config.h"
#endif

#include <sys/queue.h>
#ifdef HAVE_SYS_TIME_H
#include <sys/time.h>
#endif
#include <sys/tree.h>

#include <err.h>
#include <errno.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include <ctype.h>
#include <dnet.h>
#ifdef HAVE_TIME_H
#include <time.h>
#endif

#undef timeout_pending
#undef timeout_initialized

#include <event.h>

#include <Python.h>

#include "honeyd.h"
#include "log.h"
#include "pyextend.h"

#ifdef PYTHON_DEBUG
#define DFPRINTF(x) fprintf x
#else
#define DFPRINTF(x)
#endif

/* 
 * Functions that we need to call for this script.
 * This is stateless and shared among connections.
 */

struct pyextend {
	SPLAY_ENTRY(pyextend) node;
	char *name;
	PyObject *pFuncInit;
	PyObject *pFuncReadData;
	PyObject *pFuncWriteData;
	PyObject *pFuncEnd;
};

SPLAY_HEAD(pyetree, pyextend) pyextends;

int
pye_compare(struct pyextend *a, struct pyextend *b)
{
	return (strcmp(a->name, b->name));
}

SPLAY_PROTOTYPE(pyetree, pyextend, node, pye_compare);
SPLAY_GENERATE(pyetree, pyextend, node, pye_compare);

struct pywrite {
	TAILQ_ENTRY(pywrite) next;

	u_char *buf;
	size_t size;
};

struct pystate {
	PyObject *state;

	struct pyextend *pye;

	int fd;

	struct event pread;
	struct event pwrite;
	
	int wantwrite;

	TAILQ_HEAD(pywbufs, pywrite) writebuffers;

	struct command *cmd;
	void *con;
};

static PyObject *pyextend_readselector(PyObject *, PyObject *);
static PyObject *pyextend_writeselector(PyObject *, PyObject *);
static PyObject *pyextend_log(PyObject *, PyObject *);

static PyMethodDef HoneydMethods[] = {
    {"read_selector", pyextend_readselector, METH_VARARGS,
     "Tells Honeyd if the embedded Python application wants to read or not."},
    {"write_selector", pyextend_writeselector, METH_VARARGS,
     "Tells Honeyd if the embedded Python application wants to write or not."},
    {"log", pyextend_log, METH_VARARGS,
     "Allows a python script to pass a string to generate service logs."},
    {NULL, NULL, 0, NULL}
};

static struct pystate *current_state;

static PyObject*
pyextend_log(PyObject *self, PyObject *args)
{
	extern FILE *honeyd_servicefp;
	struct tuple *hdr = current_state->con;
	char *string;

	if(!PyArg_ParseTuple(args, "s:read_selector", &string))
		return (NULL);

	honeyd_log_service(honeyd_servicefp,
	    hdr->type == SOCK_STREAM ? IP_PROTO_TCP : IP_PROTO_UDP,
	    hdr, string);

	return Py_BuildValue("i", 0);;
}

static PyObject*
pyextend_selector(PyObject *args, struct event *ev, char *name)
{
	int on = 0;

	if(!PyArg_ParseTuple(args, "i:read_selector", &on))
		return (NULL);
	DFPRINTF((stderr, "%s: called selector with %d\n", name, on));

	if (on)
		event_add(ev, NULL);
	else
		event_del(ev);

	return Py_BuildValue("i", 0);;
}

static PyObject*
pyextend_readselector(PyObject *self, PyObject *args)
{
	if (current_state == NULL)
		return (NULL);

	return (pyextend_selector(args, &current_state->pread, __func__));
}

static PyObject*
pyextend_writeselector(PyObject *self, PyObject *args)
{
	struct pystate *state = current_state;

	PyObject *pValue;
	if (state == NULL)
		return (NULL);

	pValue = pyextend_selector(args, &state->pwrite, __func__);
	if (pValue == NULL)
		return (NULL);

	/* 
	 * We need to keep track of this, so that in case we have buffered
	 * data to write, we know if we should schedule the python script.
	 */
	state->wantwrite = event_pending(&state->pwrite, EV_WRITE, NULL);

	return (pValue);
}

static void
pyextend_cbread(int fd, short what, void *arg)
{
	static char buf[4096];
	PyObject *pArgs, *pValue;
	struct pystate *state = arg;
	struct pyextend *pye = state->pye;
	int n;

	n = read(fd, buf, sizeof(buf));

	if (n <= 0)
		goto error;

	pArgs = Py_BuildValue("(O,s#)", state->state, buf, n);
	if (pArgs == NULL) {
		fprintf(stderr, "Failed to build value\n");
		goto error;
	}

	current_state = state;
	pValue = PyObject_CallObject(pye->pFuncReadData, pArgs);
	current_state = NULL;

	Py_DECREF(pArgs);

	if (pValue == NULL) {
		PyErr_Print();
		goto error;
	}
	Py_DECREF(pValue);

	return;

 error:
	pyextend_connection_end(state);
	return;
}

static int
pyextend_addbuffer(struct pystate *state, u_char *buf, size_t size)
{
	struct pywrite *write;

	if ((write = malloc(sizeof(struct pywrite))) == NULL)
		return (-1);

	if ((write->buf = malloc(size)) == NULL) {
		free(write);
		return (-1);
	}

	memcpy(write->buf, buf, size);
	write->size = size;

	TAILQ_INSERT_TAIL(&state->writebuffers, write, next);

	return (0);
}

static void
pyextend_cbwrite(int fd, short what, void *arg)
{
	PyObject *pArgs, *pValue;
	struct pystate *state = arg;
	struct pyextend *pye = state->pye;
	struct pywrite *writebuf;
	char *buf;
	int size, res;

	/* If we still have buffered data from before, we are going
	 * to send it now and reschedule us if necessary.
	 */
	if ((writebuf = TAILQ_FIRST(&state->writebuffers)) != NULL) {
		res = write(fd, writebuf->buf, writebuf->size);
		if (res <= 0)
			goto error;
		if (res < writebuf->size) {
			writebuf->size -= res;
			memmove(writebuf->buf, writebuf->buf + res,
			    writebuf->size);
			event_add(&state->pwrite, NULL);
		} else {
			TAILQ_REMOVE(&state->writebuffers, writebuf, next);
			free(writebuf->buf);
			free(writebuf);
			if (state->wantwrite ||
			    TAILQ_FIRST(&state->writebuffers) != NULL)
				event_add(&state->pwrite, NULL);
		}

		return;
	}
	

	pArgs = Py_BuildValue("(O)", state->state);
	if (pArgs == NULL) {
		fprintf(stderr, "Failed to build value\n");
		goto error;
	}

	current_state = state;
	pValue = PyObject_CallObject(pye->pFuncWriteData, pArgs);
	current_state = NULL;

	Py_DECREF(pArgs);

	if (pValue == NULL) {
		PyErr_Print();
		goto error;
	}

	/* 
	 * Addition to support closing connections from the server
	 * side. - AJ 2.4.2004
	 */
	if (pValue == Py_None) {
		Py_DECREF(pValue);
		goto error;
	}

	res = PyString_AsStringAndSize(pValue, &buf, &size);

	if (res == -1) {
		Py_DECREF(pValue);
		goto error;
	}

	/* XXX - What to do about left over data */
	res = write(fd, buf, size);

	if (res <= 0) {
		Py_DECREF(pValue);
		goto error;
	}

	if (res != size) {
		pyextend_addbuffer(state, buf + res, size - res);
		event_add(&state->pwrite, NULL);
	}

	Py_DECREF(pValue);
		
	return;

 error:
	pyextend_connection_end(state);
	return;
}

/* Initializes our Python extension support */

void
pyextend_init(void)
{
	PyObject *pModule;
	char path[1024];

	SPLAY_INIT(&pyextends);

	Py_Initialize();
	strlcpy(path, Py_GetPath(), sizeof(path));
	strlcat(path, ":.", sizeof(path));
	PySys_SetPath(path);

	pModule = Py_InitModule("honeyd", HoneydMethods);
	PyModule_AddIntConstant(pModule, "EVENT_ON", 1);
	PyModule_AddIntConstant(pModule, "EVENT_OFF", 0);
}

/* Cleans up all Python stuff when we exit */

void
pyextend_exit(void)
{
	Py_Finalize();
}

#define CHECK_FUNC(f, x) do { \
	f = PyDict_GetItemString(pDict, x); \
	if ((f) == NULL || !PyCallable_Check(f)) { \
		warnx("%s: Cannot find function \"%s\"", \
			__func__, x); \
		goto error; \
	} \
} while (0)

void *
pyextend_load_module(const char *name)
{
	PyObject *pName, *pModule, *pDict, *pFunc;
	struct pyextend *pye, tmp;

	char line[1024];
	char *script, *p;
	
	if (strlcpy(line, name, sizeof(line)) >= sizeof(line))
		return (NULL);
	p = line;

	script = strsep(&p, " ");

	tmp.name = script;
	if ((pye = SPLAY_FIND(pyetree, &pyextends, &tmp)) != NULL)
		return (pye);

	pName = PyString_FromString(script);
	pModule = PyImport_Import(pName);
	Py_DECREF(pName);

	if (pModule == NULL) {
		PyErr_Print();
		warn("%s: could not load python module: %s",
		    __func__, script);
		return (NULL);
	}

	pDict = PyModule_GetDict(pModule); /* Borrowed */

	CHECK_FUNC(pFunc, "honeyd_init");
	CHECK_FUNC(pFunc, "honeyd_readdata");
	CHECK_FUNC(pFunc, "honeyd_writedata");
	CHECK_FUNC(pFunc, "honeyd_end");

	if ((pye = calloc(1, sizeof(struct pyextend))) == NULL)
		err(1, "calloc");

	CHECK_FUNC(pye->pFuncInit, "honeyd_init");
	CHECK_FUNC(pye->pFuncReadData, "honeyd_readdata");
	CHECK_FUNC(pye->pFuncWriteData, "honeyd_writedata");
	CHECK_FUNC(pye->pFuncEnd, "honeyd_end");

	if ((pye->name = strdup(script)) == NULL)
		err(1, "%s: strdup", __func__);

	SPLAY_INSERT(pyetree, &pyextends, pye);
	  
	return (pye);

 error:
	Py_DECREF(pModule);
	return (NULL);
}

static struct pystate *
pyextend_newstate(struct command *cmd, void *con, struct pyextend *pye)
{
	struct pystate *state;

	if ((state = calloc(1, sizeof(struct pystate))) == NULL)
		return (NULL);

	/* Initialize structure */
	state->fd = -1;
	state->cmd = cmd;
	state->con = con;
	state->pye = pye;

	TAILQ_INIT(&state->writebuffers);

	return (state);
}

static void
pyextend_freestate(struct pystate *state)
{
	struct pywrite *writes;

	while ((writes = TAILQ_FIRST(&state->writebuffers)) != NULL) {
		TAILQ_REMOVE(&state->writebuffers, writes, next);
		free(writes->buf);
		free(writes);
	}

	/* Cleanup our state */
	event_del(&state->pread);
	event_del(&state->pwrite);

	if (state->fd != -1)
		close(state->fd);
	free(state);
}

int
pyextend_connection_start(struct tuple *hdr, struct command *cmd,
    void *con, void *pye_generic)
{
	struct pyextend *pye = pye_generic;
	struct pystate *state;
	PyObject *pArgs, *pValue;
	struct addr src, dst;

	if ((state = pyextend_newstate(cmd, con, pye)) == NULL)
		return (-1);

	if ((state->fd = cmd_python(hdr, cmd, con)) == -1) {
		free(state);
		return (-1);
	}

	/* Set up state with event callbacks */
	event_set(&state->pread, state->fd, EV_READ, pyextend_cbread, state);
	event_set(&state->pwrite, state->fd, EV_WRITE, pyextend_cbwrite,state);

	addr_pack(&src, ADDR_TYPE_IP, IP_ADDR_BITS, &hdr->ip_src,IP_ADDR_LEN);
	addr_pack(&dst, ADDR_TYPE_IP, IP_ADDR_BITS, &hdr->ip_dst,IP_ADDR_LEN);

	pArgs = PyTuple_New(1);
	pValue = Py_BuildValue("{sssssisi}",
	    "HONEYD_IP_SRC", addr_ntoa(&src),
	    "HONEYD_IP_DST", addr_ntoa(&dst),
	    "HONEYD_SRC_PORT", hdr->sport,
	    "HONEYD_DST_PORT", hdr->dport);
	if (pValue == NULL) {
		fprintf(stderr, "Failed to build value\n");
		Py_DECREF(pArgs);
		goto error;
	}

	/* Set up the current state for Python */
	current_state = state;

	/* pValue reference stolen here: */
	PyTuple_SetItem(pArgs, 0, pValue);

	pValue = PyObject_CallObject(pye->pFuncInit, pArgs);
	Py_DECREF(pArgs);

	/* Take away the current state */
	current_state = NULL;

	if (pValue == NULL) {
		PyErr_Print();
		goto error;
	}

	state->state = pValue;

	/* 
	 * Registers state with command structure so that we can do
	 * proper cleanup if things go wrong.
	 */
	cmd->state = state;
	return (0);
	
 error:
	pyextend_freestate(state);
	return (-1);
}

void
pyextend_connection_end(struct pystate *state)
{
	struct command *cmd = state->cmd;
	struct pyextend *pye = state->pye;
	PyObject *pArgs;

	pArgs = PyTuple_New(1);

	/* state->state reference stolen here: */
	PyTuple_SetItem(pArgs, 0, state->state);

	PyObject_CallObject(pye->pFuncEnd, pArgs);
	Py_DECREF(pArgs);

	pyextend_freestate(state);

	cmd->state = NULL;

	return;
}
