/**
  * Nginx HTTP Application Module
  * Embed Application into Nginx (GET/POST/WebSocket)
  *
  * Author: CUI Wei <ghostplant@qq.com>
  * Copyright (C) 2016.12 - ..
  *
  * The MIT License (MIT)
  */

#include <pty.h>
#include <termios.h>
#include <fcntl.h>
#include <signal.h>

#include "ngx_http_webshell_module.h"

typedef struct {
	ngx_connection_t conn;
	ngx_event_t in, out;
	pid_t pid;
	u_short width, height;
	u_char inbuf[1024];
	
	FILE *upload;
} shell_ctx_t;

typedef struct pid_entry_s {
	pid_t pid;
	ngx_http_request_t *r;
	struct pid_entry_s *next;
} pid_entry_t;

pid_entry_t pids = { };

void ngx_pty_recv(ngx_event_t *ev) {
	ngx_http_request_t *r = ev->data;
	shell_ctx_t *ctx = ngx_get_session(r);
	if (!ctx->in.available)
		return;
	ssize_t n = read(ctx->conn.fd, ctx->inbuf + 1, sizeof(ctx->inbuf) - 1);
	if (n < 0)
		return;
	if (n == 0) {
		ngx_websocket_do_close(r);
		return;
	}
	*ctx->inbuf = 'y';
	if (ngx_websocket_do_send(r, ctx->inbuf, n + 1) != NGX_OK) {
		ngx_websocket_do_close(r);
		return;
	}
	ctx->in.available = 0;
}

void ngx_signal_handler(ngx_event_t *ev) {
	int status;
	volatile pid_t pid;
	while ((pid = waitpid(-1, &status, WNOHANG)) > 0) {
		for (pid_entry_t *p = &pids, *q; p->next != NULL; p = p->next)
			if (p->next->pid == pid) {
				q = p->next;
				ngx_websocket_do_close(q->r);
				p->next = q->next;
				ngx_free(q);
				--pids.pid;
				break;
			}
	}
}

void signal_hander() {
	ngx_notify(ngx_signal_handler);
}

const char *get_home() {
	static char home[256] = "/home/";
	if (!home[6]) {
		FILE *fp = popen("whoami", "r");
		if (!fp || !fread(home + 6, 1, sizeof(home) - 6, fp)) {
			if (fp)
				pclose(fp);
			return NULL;
		}
		home[sizeof(home) - 1] = 0;
		for (size_t i = 0; i < sizeof(home); ++i)
			if (home[i] == '\n') {
				home[i] = 0;
				break;
			}
		pclose(fp);
		fflush(stdout);
		if (!strcmp(home + 6, "root"))
			home[1] = 'r', home[2] = 'o', home[3] = 'o', home[4] = 't', home[5] = 0;
	}
	return home;
}

void ngx_websocket_on_open(ngx_http_request_t *r) {
	shell_ctx_t *ctx = ngx_pcalloc(r->pool, sizeof(shell_ctx_t));
	if (ctx == NULL) {
		ngx_websocket_do_close(r);
		return;
	}
	if (!ngx_strncmp(r->uri.data, (u_char*)"/upload", sizeof("/upload") - 1)) {
		ngx_set_session(r, ctx);
		return;
	}
	pid_entry_t *p = ngx_alloc(sizeof(pid_entry_t), ngx_cycle->log);
	if (p == NULL) {
		ngx_websocket_do_close(r);
		return;
	}
	signal(SIGCHLD, signal_hander);
	
	ctx->conn.read = &ctx->in;
	ctx->conn.write = &ctx->out;
	ctx->conn.log = r->pool->log;
	
	ctx->in.handler = ngx_pty_recv;
	ctx->out.handler = ngx_empty_event_handler;
	ctx->in.data = ctx->out.data = r;
	ctx->in.log = ctx->out.log  = r->pool->log;
	ctx->in.available = ctx->out.available = 1;
	
	ctx->pid = forkpty(&ctx->conn.fd, NULL, NULL, NULL);
	if (ctx->pid < 0) {
		ngx_websocket_do_close(r);
		return;
	}
	const char *home = get_home();
	if (!ctx->pid) {
		setenv("PATH", "/usr/local/sbin:/usr/local/bin:/usr/sbin:/usr/bin:/sbin:/bin", 0);
		setenv("HOME", home, 0);
		setenv("TERM", "xterm", 0);
		char *sh[] = {"/bin/sh", "-c", "cd ~; umask 022; [ -e /etc/default/locale ] && . /etc/default/locale && export LANG; if which bash >/dev/null; then SHELL=$(which bash) exec bash; else SHELL=$(which sh) exec sh; fi", NULL};
		execvp(*sh, sh);
		exit(1);
	}
	if (ctx->conn.fd <= 0) {
		ngx_websocket_do_close(r);
		return;
	}
	p->pid = ctx->pid;
	p->r = r;
	p->next = pids.next;
	pids.next = p;
	++pids.pid;
	
	struct termios tios;
	tcgetattr(ctx->conn.fd, &tios);
	// tios.c_lflag &= ~(ECHO | ECHONL);
	tcsetattr(ctx->conn.fd, TCSAFLUSH, &tios);
	
	fcntl(ctx->conn.fd, F_SETFL, fcntl(ctx->conn.fd, F_GETFL, 0) | O_NONBLOCK);
	//ngx_add_event(&ctx->conn, NGX_READ_EVENT, 0);
	ngx_add_conn(&ctx->conn);
	ngx_set_session(r, ctx);
}

void ngx_websocket_on_close(ngx_http_request_t *r) {
	shell_ctx_t *ctx = ngx_get_session(r);
	if (ctx->upload != NULL) {
		fclose(ctx->upload);
		ctx->upload = NULL;
		return;
	}
	ngx_del_conn(&ctx->conn, 0);
	if (ctx->pid > 0) {
		kill(ctx->pid, SIGKILL);
		ctx->pid = 0;
	}
	if (ctx->conn.fd > 0) {
		close(ctx->conn.fd);
		ctx->conn.fd = 0;
	}
}

ngx_int_t ngx_websocket_on_message(ngx_http_request_t *r, u_char *message, size_t len) {
	shell_ctx_t *ctx = ngx_get_session(r);
	if (ctx->upload != NULL) {
		fwrite(message, 1, len, ctx->upload);
		if (ngx_websocket_do_send(r, message, 1) != NGX_OK)
			return NGX_ERROR;
	} else if (*message == 'd') {
		if (ctx->conn.fd == 0)
			return NGX_ERROR;
		size_t ulen = (len - 1) / 2;
		u_char *umsg = message + 1;
		for (size_t i = 0; i < ulen; ++i) {
			char a = (umsg[i + i] <= '9') ? (umsg[i + i] - '0') : (umsg[i + i] - 'A' + 10);
			char b = (umsg[i + i + 1] <= '9') ? (umsg[i + i + 1] - '0') : (umsg[i + i + 1] - 'A' + 10);
			umsg[i] = (a << 4) | b;
		}
		ssize_t n = write(ctx->conn.fd, umsg, ulen);
		if (len > 1 && n <= 0)
			return NGX_ERROR;
		if (!ctx->in.available) {
			ctx->in.available = 1;
			ngx_pty_recv(&ctx->in);
		}
		// FIXME: buffering again message
	} else if (*message == 's') {
		if (ctx->conn.fd == 0)
			return NGX_ERROR;
		if (!ctx->in.available) {
			ctx->in.available = 1;
			ngx_pty_recv(&ctx->in);
		}
		if (len == 1)
			return NGX_OK;
		char *p = strchr((char*)message, ',');
		if (!p)
			return NGX_ERROR;
		*p = 0;
		u_short layout[4] = {atoi((char*)message + 1), atoi(p + 1), 0, 0};
		if (layout[0] != ctx->height || layout[1] != ctx->width) {
			ctx->height = layout[0], ctx->width = layout[1];
			ioctl(ctx->conn.fd, TIOCSWINSZ, layout);
		}
	} else if (*message == 'o') {
		if (ctx->upload != NULL)
			return NGX_ERROR;
		if (message[1] == '~' && message[2] == '/') {
			const char *home = get_home();
			size_t l = strlen(home);
			char *buf = (char*)malloc(l + len);
			if (!buf)
				return NGX_ERROR;
			memcpy(buf, home, l);
			memcpy(buf + l, message + 2, len - 2);
			buf[l + len - 2] = 0;
			ctx->upload = fopen(buf, "wb");
			free(buf);
		} else if (message[1] != '/')
			return NGX_ERROR;
		else
			ctx->upload = fopen((char*)(message + 1), "wb");
		if (!ctx->upload)
			ngx_websocket_do_close(r);
		else if (ngx_websocket_do_send(r, message, 1) != NGX_OK)
			return NGX_ERROR;
	} else if (*message != 'p')
			return NGX_ERROR;
	return NGX_OK;
}

