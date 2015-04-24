/**
  * Nginx HTTP Application Module
  * Embed Application into Nginx (GET/POST/WebSocket)
  *
  * Author: CUI Wei <ghostplant@qq.com>
  * Copyright (C) 2016.12 - ..
  *
  * The MIT License (MIT)
  */

#ifndef __NGX_HTTP_APPLICATION_MODULE_H__
#define __NGX_HTTP_APPLICATION_MODULE_H__

#include <ngx_config.h>
#include <ngx_core.h>
#include <ngx_http.h>
#include <ngx_sha1.h>

//	0 1 2 3 4 5 6 7 8 9 0 1 2 3 4 5 6 7 8 9 0 1 2 3 4 5 6 7 8 9 0 1 2
//	+-+-+-+-+-------+-+-------------+-------------------------------+
//	|F|R|R|R|Copcode|M| Payload len |    Extended payload length    |
//	|I|S|S|S|T (4)  |A|     (7)     |             (16/64)           |
//	|N|V|V|V|R      |S|             |   (if payload len==126/127)   |
//	| |1|2|3|L      |K|             |                               |
//	+-+-+-+-+-------+-+-------------+ - - - - - - - - - - - - - - - +
//	|     Extended payload length continued, if payload len == 127  |
//	+ - - - - - - - - - - - - - - - +-------------------------------+
//	|                               |Masking-key, if MASK set to 1  |
//	+-------------------------------+-------------------------------+
//	| Masking-key (continued)       |          Payload Data         |
//	+-------------------------------- - - - - - - - - - - - - - - - +
//	:                     Payload Data continued ...                :
//	+ - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - +
//	|                     Payload Data continued ...                |
//	+---------------------------------------------------------------+

#define WEBSOCKET_OPCODE_CONTINUATION	0x0
#define WEBSOCKET_OPCODE_TEXT			0x1
#define WEBSOCKET_OPCODE_BINARY			0x2
#define WEBSOCKET_OPCODE_CLOSE			0x8
#define WEBSOCKET_OPCODE_PING			0x9
#define WEBSOCKET_OPCODE_PONG			0xA

#define HYBI_GUID						"258EAFA5-E914-47DA-95CA-C5AB0DC85B11"
#define HYBI10_ACCEPTHDRLEN				29
#define WEBSOCKET_RESPONSE_CLOSE		"\x03\xe8 Closed"
#define WEBSOCKET_FRAME_SIZE			65535

#define ngx_websocket_do_send(r, message, len)	(ngx_websocket_do_raw_send((r), (u_char*)(message), (len), WEBSOCKET_OPCODE_BINARY))
#define ngx_get_session(r)  (((http_webshell_ctx_t*)ngx_http_get_module_ctx(r, ngx_http_webshell_module))->ptr)
#define ngx_set_session(r, data)  (((http_webshell_ctx_t*)ngx_http_get_module_ctx(r, ngx_http_webshell_module))->ptr = (data))

#ifndef _DEBUG
#define fprintf(stdout, ...)
#define ngx_print(str)
#else
#define ngx_print(str)	(fwrite((str)->data, (str)->len, 1, stdout), fflush(stdout))
#endif

typedef struct {
	u_char *inbuf, *outbuf;
	size_t insz, outsz;
	void *ptr;
} http_webshell_ctx_t;

ngx_module_t ngx_http_webshell_module;

void ngx_websocket_on_open(ngx_http_request_t *r);
ngx_int_t ngx_websocket_on_message(ngx_http_request_t *r, u_char *message, size_t len);
void ngx_websocket_on_close(ngx_http_request_t *r);

static void ngx_empty_event_handler(ngx_event_t *ev) {
}

static void ngx_http_write_handler(ngx_http_request_t *r);

static ngx_int_t ngx_websocket_do_raw_send(ngx_http_request_t *r, u_char *message, size_t len, u_char opcode) {
	http_webshell_ctx_t *ctx = ngx_http_get_module_ctx(r, ngx_http_webshell_module);
	if (!ctx->outbuf) {
		ctx->outbuf = (u_char*)ngx_palloc(r->pool, WEBSOCKET_FRAME_SIZE), ctx->outsz = 0;
		if (!ctx->outbuf)
			return NGX_ERROR;
	}
	if (ctx->outsz + 4 + len > WEBSOCKET_FRAME_SIZE)
		return NGX_AGAIN;
	u_char *pbuf = ctx->outbuf + ctx->outsz;
	*pbuf++ = (u_char)((opcode & 0x0f) | 0x80);
	if (len < 126)
		*pbuf++ = (u_char)len;
	else
		*pbuf++ = 126, *(u_short*)pbuf = htons((u_short)len), pbuf += sizeof(u_short);
	ngx_memcpy(pbuf, message, len);
	ctx->outsz = pbuf + len - ctx->outbuf;
	
	ngx_http_write_handler(r);
	return NGX_OK;
}

static void ngx_websocket_do_close(ngx_http_request_t *r) {
	if (!r->keepalive)
		return;
	r->keepalive = 0;
	ngx_websocket_on_close(r);
	ngx_websocket_do_raw_send(r, (u_char*)WEBSOCKET_RESPONSE_CLOSE, sizeof(WEBSOCKET_RESPONSE_CLOSE) - 1, WEBSOCKET_OPCODE_CLOSE);
	
	if (r->connection->write->timer_set)
		ngx_del_timer(r->connection->write);
    ngx_http_finalize_request(r, NGX_HTTP_CLOSE);
}

static void ngx_http_read_handler(ngx_http_request_t *r) {
	http_webshell_ctx_t *ctx = ngx_http_get_module_ctx(r, ngx_http_webshell_module);
	if (!ctx->inbuf) {
		ctx->inbuf = (u_char*)ngx_palloc(r->pool, WEBSOCKET_FRAME_SIZE), ctx->insz = 0;
		if (!ctx->inbuf)
			goto err;
	}
	for (;;) {
		ssize_t n = r->connection->recv(r->connection, ctx->inbuf + ctx->insz, WEBSOCKET_FRAME_SIZE - 1 - ctx->insz);
		if (n == NGX_ERROR || n == 0)
			goto err;
		if (n == NGX_AGAIN)
			return;
		ctx->insz += n;
		while (ctx->insz >= 2) {
			u_char opcode = ctx->inbuf[0] & 0x0F, next;
			size_t hl = 2, pl = ctx->inbuf[1] & 0x7F;
			if (pl == 126)
				pl = (ctx->inbuf[2] << 8) + ctx->inbuf[3], hl += 2;
			else if (pl > 126)
				goto err;
			u_char *mask = ctx->inbuf + hl;
			hl += 4; // mask-size
			u_char *payload = ctx->inbuf + hl;
			if (ctx->insz < hl + pl) {
				if (hl + pl >= WEBSOCKET_FRAME_SIZE - 1)
					goto err;
				return;
			}
			ctx->insz -= hl + pl;
			switch (opcode) {
				case WEBSOCKET_OPCODE_TEXT:
				case WEBSOCKET_OPCODE_BINARY:
					for (size_t i = 0; i < pl; ++i)
						payload[i] ^= mask[i & 3];
					next = payload[pl], payload[pl] = 0;
					if (ngx_websocket_on_message(r, payload, pl) == NGX_ERROR)
						goto err;
					payload[pl] = next;
					break;
				case WEBSOCKET_OPCODE_PING:
				case WEBSOCKET_OPCODE_PONG:
				case WEBSOCKET_OPCODE_CONTINUATION:
					break;
				case WEBSOCKET_OPCODE_CLOSE:
				default:
					fprintf(stdout, "Unsupported OP code: %d\n", opcode);
					goto err;
			}
			if (ctx->insz)
				ngx_memmove(ctx->inbuf, ctx->inbuf + hl + pl, ctx->insz);
		}
	}
	return;
err:
	ngx_websocket_do_close(r);
}

static void ngx_http_write_handler(ngx_http_request_t *r) {
	http_webshell_ctx_t *ctx = ngx_http_get_module_ctx(r, ngx_http_webshell_module);
	ssize_t n = r->connection->send(r->connection, ctx->outbuf, ctx->outsz);
	if (n == NGX_ERROR) {
		ngx_websocket_do_close(r);
		return;
	}
	if (n > 0) {
		ngx_memmove(ctx->outbuf, ctx->outbuf + n, ctx->outsz - n);
		ctx->outsz -= n;
	}
	if (n == NGX_AGAIN || ctx->outsz)
		ngx_add_timer(r->connection->write, 100);
}

static ngx_int_t ngx_http_webshell_handler(ngx_http_request_t *r) {
	http_webshell_ctx_t *ctx = ngx_pcalloc(r->pool, sizeof(http_webshell_ctx_t));
	if (ctx == NULL)
		return NGX_HTTP_INTERNAL_SERVER_ERROR;
	ctx->inbuf = NULL;
	ctx->outbuf = NULL;
	ctx->insz = 0;
	ctx->outsz = 0;
	ctx->ptr = NULL;
	ngx_http_set_ctx(r, ctx, ngx_http_webshell_module);
	
	fprintf(stdout, "[REQUEST 0x%08lx] ", (long)r);
	ngx_print(&r->method_name);
	fprintf(stdout, "(%lu) ", r->method); // NGX_HTTP_POST | ..
	ngx_print(&r->unparsed_uri);
	fprintf(stdout, " from ");
	ngx_print(&r->connection->addr_text);
	fprintf(stdout, " using ");
	ngx_print(&r->http_protocol);
	fprintf(stdout, "\n");
	
	ngx_str_t ws_key = {0, NULL};
	
	ngx_list_part_t *part = &r->headers_in.headers.part;
	ngx_table_elt_t *h = (ngx_table_elt_t*)part->elts;
	for (ngx_uint_t i = 0; ; i++) {
		if (i >= part->nelts) {
			if (part->next == NULL)
				break;
			part = part->next;
			h = (ngx_table_elt_t*)part->elts;
			i = 0;
		}
		fprintf(stdout, " >> (header) ");
		ngx_print(&h[i].key);
		fprintf(stdout, " = ");
		ngx_print(&h[i].value);
		fprintf(stdout, "\n");
		
		if (ngx_strncasecmp(h[i].key.data, (u_char *)"Sec-WebSocket-Key", h[i].key.len) == 0) {
			ngx_sha1_t sha1;
			ngx_sha1_init(&sha1);
			ngx_sha1_update(&sha1, h[i].value.data, h[i].value.len);
			ngx_sha1_update(&sha1, HYBI_GUID, sizeof(HYBI_GUID) - 1);
			u_char src_data[20];
			ngx_str_t src = {sizeof(src_data), src_data};
			ngx_sha1_final(src.data, &sha1);
			ws_key.data = (u_char*)ngx_palloc(r->pool, HYBI10_ACCEPTHDRLEN);
			if (!ws_key.data)
				return NGX_ERROR;
			ngx_encode_base64(&ws_key, &src);
		} else if (ngx_strncasecmp(h[i].key.data, (u_char *)"Sec-WebSocket-Protocol", h[i].key.len) == 0) {
			if (!ngx_strstr(h[i].value.data, "binary"))
				return NGX_ERROR;
		}
	}
	
	if (ws_key.len == 0) {
		r->headers_out.status = NGX_HTTP_OK;
		r->headers_out.content_type.len = sizeof("text/html") - 1;
		r->headers_out.content_type.data = (u_char *)"text/html";
		ngx_chain_t *out = (ngx_chain_t*)ngx_pcalloc(r->pool, sizeof(ngx_chain_t));
		ngx_buf_t *b = (ngx_buf_t*)ngx_pcalloc(r->pool, sizeof(ngx_buf_t));
		out->buf = b;
		out->next = NULL;
		b->pos = (u_char*)"Not Accesible";
		b->last = b->pos + sizeof("Not Accesible") - 1;
		b->memory = 1;
		b->in_file = 0;
		b->last_buf = 1;
		ngx_http_send_header(r);
		ngx_http_discard_request_body(r);
		// ++r->count;
		return ngx_http_output_filter(r, out);
	}
	
	r->headers_out.status = NGX_HTTP_SWITCHING_PROTOCOLS;
	ngx_str_set(&r->headers_out.status_line, "101 Switching Protocols");
	r->headers_out.content_length_n = -1;
	
	h = (ngx_table_elt_t*)ngx_list_push(&r->headers_out.headers);
	h->hash = 1;
	ngx_str_set(&h->key, "Sec-WebSocket-Accept");
	h->value = ws_key;
	
	h = (ngx_table_elt_t*)ngx_list_push(&r->headers_out.headers);
	h->hash = 1;
	ngx_str_set(&h->key, "Upgrade");
	ngx_str_set(&h->value, "websocket");
	
	h = (ngx_table_elt_t*)ngx_list_push(&r->headers_out.headers);
	h->hash = 1;
	ngx_str_set(&h->key, "Sec-WebSocket-Protocol");
	ngx_str_set(&h->value, "binary");
	
	if (r->connection->ssl)
		r->connection->ssl->buffer = 0;
	
	r->keepalive = 1;
	ngx_http_send_header(r);
	ngx_http_write_filter(r, NULL);
	ngx_int_t rc = ngx_http_read_client_request_body(r, ngx_websocket_on_open);
	if (rc >= NGX_HTTP_SPECIAL_RESPONSE)
		return rc;
	r->read_event_handler = ngx_http_read_handler;
	r->write_event_handler = ngx_http_write_handler;
	return NGX_DONE;
}

static char *ngx_http_webshell(ngx_conf_t *cf, ngx_command_t *cmd, void *conf) {
	ngx_http_core_loc_conf_t *clcf = ngx_http_conf_get_module_loc_conf(cf, ngx_http_core_module);
	clcf->handler = ngx_http_webshell_handler;
	return NGX_CONF_OK;
}

static ngx_command_t ngx_http_webshell_commands[] = {
	{
		ngx_string("http_webshell"), /* directive */
		NGX_HTTP_LOC_CONF|NGX_CONF_NOARGS, /* location context and takes no arguments*/
		ngx_http_webshell, /* configuration setup function */
		0, /* No offset. Only one context is supported. */
		0, /* No offset when storing the module configuration on struct. */
		NULL
	},
	ngx_null_command /* command termination */
};

static ngx_http_module_t ngx_http_webshell_module_ctx = {
	NULL, /* preconfiguration */
	NULL, /* postconfiguration */

	NULL, /* create main configuration */
	NULL, /* init main configuration */

	NULL, /* create server configuration */
	NULL, /* merge server configuration */

	NULL, /* create location configuration */
	NULL /* merge location configuration */
};

ngx_module_t ngx_http_webshell_module = {
	NGX_MODULE_V1,
	&ngx_http_webshell_module_ctx, /* module context */
	ngx_http_webshell_commands, /* module directives */
	NGX_HTTP_MODULE, /* module type */
	NULL, /* init master */
	NULL, /* init module */
	NULL, /* init process */
	NULL, /* init thread */
	NULL, /* exit thread */
	NULL, /* exit process */
	NULL, /* exit master */
	NGX_MODULE_V1_PADDING
};

/*
static void ngx_http_input_handler(ngx_http_request_t *r) {
	if (r->request_body == NULL)
		return;
	printf("POST-FILE: %d %lx %lx %lx\n", (int)r->count, (long)r->request_body->temp_file, (long)r->request_body->bufs, (long)r->request_body->buf), fflush(stdout);
	//printf("TEMP-FILE: %s\n", (char*)r->request_body->temp_file->file.name.data), fflush(stdout);
	ngx_chain_t *bufs = r->request_body->bufs;
	while (bufs && bufs->buf != NULL) {
		printf("LL (%ld) (%ld)\n", bufs->buf->last - bufs->buf->pos, bufs->buf->end - bufs->buf->start);
		bufs = bufs->next;
	}
}
*/

#endif

