
/*
 * Copyright (C) Charlie Somerville (charliesome)
 */


#ifndef _NGX_HTTP_LUA_RESOLVE_H_INCLUDED_
#define _NGX_HTTP_LUA_RESOLVE_H_INCLUDED_


#include "ngx_http_lua_common.h"


typedef struct ngx_http_lua_resolve_upstream_s
    ngx_http_lua_resolve_upstream_t;


typedef
    int (*ngx_http_lua_resolve_retval_handler)(ngx_http_request_t *r,
        ngx_http_lua_resolve_upstream_t *u, lua_State *L);


typedef void (*ngx_http_lua_resolve_upstream_handler_pt)(
          ngx_http_request_t *r, ngx_http_lua_resolve_upstream_t *u);


struct ngx_http_lua_resolve_upstream_s {
    ngx_http_lua_resolve_retval_handler          prepare_retvals;
    ngx_http_lua_resolve_upstream_handler_pt     read_event_handler;

    ngx_http_lua_loc_conf_t         *conf;
    ngx_http_cleanup_pt             *cleanup;
    ngx_http_request_t              *request;

    ngx_msec_t                       read_timeout;

    ngx_http_upstream_resolved_t    *resolved;

    ngx_uint_t                       ft_type;

    ngx_http_lua_co_ctx_t           *co_ctx;

    unsigned                         waiting; /* :1 */
};


void ngx_http_lua_inject_resolve_api(lua_State *L);


#endif /* _NGX_HTTP_LUA_RESOLVE_H_INCLUDED_ */

/* vi:set ft=c ts=4 sw=4 et fdm=marker: */
