
/*
 * Copyright (C) Charlie Somerville (charliesome)
 */


#ifndef DDEBUG
#define DDEBUG 0
#endif
#include "ddebug.h"


#include "ngx_http_lua_resolve.h"
#include "ngx_http_lua_socket_tcp.h"
#include "ngx_http_lua_socket_udp.h"
#include "ngx_http_lua_util.h"
#include "ngx_http_lua_contentby.h"
#include "ngx_http_lua_output.h"
#include "ngx_http_lua_probe.h"


#if 1
#undef ngx_http_lua_probe_info
#define ngx_http_lua_probe_info(msg)
#endif

static int ngx_http_lua_ngx_resolve(lua_State *L);
static void ngx_http_lua_resolve_finalize(ngx_http_request_t *r,
    ngx_http_lua_resolve_upstream_t *u);
static int ngx_http_lua_ngx_resolve_retval_handler(ngx_http_request_t *r,
    ngx_http_lua_resolve_upstream_t *u, lua_State *L);
static void ngx_http_lua_resolve_handler(ngx_resolver_ctx_t *ctx);
static int ngx_http_lua_resolve_error_retval_handler(ngx_http_request_t *r,
    ngx_http_lua_resolve_upstream_t *u, lua_State *L);
static void ngx_http_lua_resolve_handle_error(ngx_http_request_t *r,
    ngx_http_lua_resolve_upstream_t *u, ngx_uint_t ft_type);
static void ngx_http_lua_socket_udp_cleanup(void *data);
static void ngx_http_lua_socket_dummy_handler(ngx_http_request_t *r,
    ngx_http_lua_resolve_upstream_t *u);
static ngx_int_t ngx_http_lua_resolve_resume(ngx_http_request_t *r);
static void ngx_http_lua_resolve_cleanup(void *data);


enum {
    SOCKET_CTX_INDEX = 1,
    SOCKET_TIMEOUT_INDEX = 2
};


void
ngx_http_lua_inject_resolve_api(lua_State *L)
{
    lua_pushcfunction(L, ngx_http_lua_ngx_resolve);
    lua_setfield(L, -2, "resolve");
}


static int
ngx_http_lua_ngx_resolve(lua_State *L)
{
    ngx_http_request_t          *r;
    ngx_http_lua_ctx_t          *ctx;
    ngx_str_t                    host;
    ngx_resolver_ctx_t          *rctx, temp;
    ngx_http_core_loc_conf_t    *clcf;
    int                          saved_top;
    int                          n;
    u_char                      *p;
    size_t                       len;
    ngx_http_lua_loc_conf_t     *llcf;
    ngx_http_lua_co_ctx_t       *coctx;

    ngx_http_lua_resolve_upstream_t      *u;

    /*
     * TODO: we should probably accept an extra argument to setpeername()
     * to allow the user bind the datagram unix domain socket himself,
     * which is necessary for systems without autobind support.
     */

    n = lua_gettop(L);
    if (n != 1) {
        return luaL_error(L, "ngx.resolve: expecting 1 argument, but seen %d", n);
    }

    r = ngx_http_lua_get_req(L);
    if (r == NULL) {
        return luaL_error(L, "no request found");
    }

    ctx = ngx_http_get_module_ctx(r, ngx_http_lua_module);
    if (ctx == NULL) {
        return luaL_error(L, "no ctx found");
    }

    ngx_http_lua_check_context(L, ctx, NGX_HTTP_LUA_CONTEXT_REWRITE
                               | NGX_HTTP_LUA_CONTEXT_ACCESS
                               | NGX_HTTP_LUA_CONTEXT_CONTENT
                               | NGX_HTTP_LUA_CONTEXT_TIMER);

    p = (u_char *) luaL_checklstring(L, 1, &len);

    host.data = ngx_palloc(r->pool, len + 1);
    if (host.data == NULL) {
        return luaL_error(L, "no memory");
    }

    host.len = len;

    ngx_memcpy(host.data, p, len);
    host.data[len] = '\0';

    u = lua_newuserdata(L, sizeof(ngx_http_lua_resolve_upstream_t));
    if (u == NULL) {
        return luaL_error(L, "no memory");
    }

    ngx_memzero(u, sizeof(ngx_http_lua_resolve_upstream_t));

    u->request = r; /* set the controlling request */
    llcf = ngx_http_get_module_loc_conf(r, ngx_http_lua_module);

    u->conf = llcf;

    u->read_timeout = u->conf->read_timeout;

    u->resolved = ngx_pcalloc(r->pool, sizeof(ngx_http_upstream_resolved_t));
    if (u->resolved == NULL) {
        return luaL_error(L, "no memory");
    }

    clcf = ngx_http_get_module_loc_conf(r, ngx_http_core_module);

    temp.name = host;
    rctx = ngx_resolve_start(clcf->resolver, &temp);
    if (rctx == NULL) {
        u->ft_type |= NGX_HTTP_LUA_SOCKET_FT_RESOLVER;
        lua_pushnil(L);
        lua_pushliteral(L, "failed to start the resolver");
        return 2;
    }

    if (rctx == NGX_NO_RESOLVER) {
        u->ft_type |= NGX_HTTP_LUA_SOCKET_FT_RESOLVER;
        lua_pushnil(L);
        lua_pushfstring(L, "no resolver defined to resolve \"%s\"", host.data);
        return 2;
    }

    rctx->name = host;
#if !defined(nginx_version) || nginx_version < 1005008
    rctx->type = NGX_RESOLVE_A;
#endif
    rctx->handler = ngx_http_lua_resolve_handler;
    rctx->data = u;
    rctx->timeout = clcf->resolver_timeout;

    u->co_ctx = ctx->cur_co_ctx;
    u->resolved->ctx = rctx;

    saved_top = lua_gettop(L);

    coctx = ctx->cur_co_ctx;
    ngx_http_lua_cleanup_pending_operation(coctx);
    coctx->cleanup = ngx_http_lua_resolve_cleanup;

    if (ngx_resolve_name(rctx) != NGX_OK) {
        ngx_log_debug0(NGX_LOG_DEBUG_HTTP, r->connection->log, 0,
                       "ngx.resolve fail to run resolver immediately");

        u->ft_type |= NGX_HTTP_LUA_SOCKET_FT_RESOLVER;

        u->resolved->ctx = NULL;
        lua_pushnil(L);
        lua_pushfstring(L, "%s could not be resolved", host.data);

        return 2;
    }

    if (u->waiting == 1) {
        /* resolved and already connecting */
        return lua_yield(L, 0);
    }

    n = lua_gettop(L) - saved_top;
    if (n) {
        /* errors occurred during resolving or connecting
         * or already connected */
        return n;
    }

    /* still resolving */

    u->waiting = 1;
    u->prepare_retvals = ngx_http_lua_ngx_resolve_retval_handler;

    coctx->data = u;

    if (ctx->entered_content_phase) {
        r->write_event_handler = ngx_http_lua_content_wev_handler;

    } else {
        r->write_event_handler = ngx_http_core_run_phases;
    }

    return lua_yield(L, 0);
}


static void
ngx_http_lua_resolve_handler(ngx_resolver_ctx_t *ctx)
{
    ngx_http_request_t                  *r;
    ngx_connection_t                    *c;
    ngx_http_upstream_resolved_t        *ur;
    ngx_http_lua_ctx_t                  *lctx;
    lua_State                           *L;
    ngx_http_lua_resolve_upstream_t     *u;
    size_t                               len;
    ngx_uint_t                           i;
    unsigned                             waiting;
    u_char                               addr_str[NGX_SOCKADDR_STRLEN];

    u = ctx->data;
    r = u->request;
    c = r->connection;
    ur = u->resolved;

    ngx_log_debug0(NGX_LOG_DEBUG_HTTP, c->log, 0,
                   "ngx.resolve resolve handler");

    lctx = ngx_http_get_module_ctx(r, ngx_http_lua_module);
    if (lctx == NULL) {
        return;
    }

    lctx->cur_co_ctx = u->co_ctx;

    u->co_ctx->cleanup = NULL;

    L = lctx->cur_co_ctx->co;

    dd("setting socket_ready to 1");

    waiting = u->waiting;

    if (ctx->state) {
        ngx_log_debug2(NGX_LOG_DEBUG_HTTP, c->log, 0,
                       "ngx.resolve resolver error: %s (waiting: %d)",
                       ngx_resolver_strerror(ctx->state), (int) u->waiting);

        lua_pushnil(L);
        lua_pushlstring(L, (char *) ctx->name.data, ctx->name.len);
        lua_pushfstring(L, " could not be resolved (%d: %s)",
                        (int) ctx->state,
                        ngx_resolver_strerror(ctx->state));
        lua_concat(L, 2);

        ngx_resolve_name_done(ctx);
        ur->ctx = NULL;

        u->prepare_retvals = ngx_http_lua_resolve_error_retval_handler;
        ngx_http_lua_resolve_handle_error(r, u,
                                             NGX_HTTP_LUA_SOCKET_FT_RESOLVER);

        if (waiting) {
            ngx_http_run_posted_requests(c);
        }

        return;
    }

    ur->naddrs = ctx->naddrs;
    ur->addrs = ctx->addrs;

    ngx_http_lua_assert(ur->naddrs > 0);

    if (ur->naddrs == 1) {
        i = 0;

    } else {
        i = ngx_random() % ur->naddrs;
    }

    dd("selected addr index: %d", (int) i);

#if defined(nginx_version) && nginx_version >= 1005008
    len = ngx_sock_ntop(ur->addrs[i].sockaddr, ur->addrs[i].socklen, addr_str, NGX_SOCKADDR_STRLEN, 0);
#else
    /* for nginx older than 1.5.8 */
    len = ngx_inet_ntop(AF_INET, &ur->addrs[i], addr_str, NGX_INET_ADDRSTRLEN);
#endif

    lua_pushlstring(L, (const char*)addr_str, len);

    ngx_resolve_name_done(ctx);
    ur->ctx = NULL;

    u->waiting = 0;

    if (waiting) {
        lctx->resume_handler = ngx_http_lua_resolve_resume;
        r->write_event_handler(r);
        ngx_http_run_posted_requests(c);

    } else {
        (void) ngx_http_lua_ngx_resolve_retval_handler(r, u, L);
    }

    return;
}


static int
ngx_http_lua_ngx_resolve_retval_handler(ngx_http_request_t *r,
    ngx_http_lua_resolve_upstream_t *u, lua_State *L)
{
    ngx_http_cleanup_t              *cln;
    ngx_http_upstream_resolved_t    *ur;

    ngx_log_debug0(NGX_LOG_DEBUG_HTTP, r->connection->log, 0,
                   "lua udp socket resolve retval handler");

    if (u->ft_type & NGX_HTTP_LUA_SOCKET_FT_RESOLVER) {
        return 2;
    }

    ur = u->resolved;

    if (ur->sockaddr) {
        /*
        uc->sockaddr = ur->sockaddr;
        uc->socklen = ur->socklen;
        uc->server = ur->host;
        */
        /* TODO - return addr to lua */

    } else {
        lua_pushnil(L);
        lua_pushliteral(L, "resolver not working");
        return 2;
    }

    if (u->cleanup == NULL) {
        cln = ngx_http_cleanup_add(r, 0);
        if (cln == NULL) {
            u->ft_type |= NGX_HTTP_LUA_SOCKET_FT_ERROR;
            lua_pushnil(L);
            lua_pushliteral(L, "no memory");
            return 2;
        }

        cln->handler = ngx_http_lua_socket_udp_cleanup;
        cln->data = u;
        u->cleanup = &cln->handler;
    }

    lua_pushinteger(L, 1);
    return 1;
}


static int
ngx_http_lua_resolve_error_retval_handler(ngx_http_request_t *r,
    ngx_http_lua_resolve_upstream_t *u, lua_State *L)
{
    ngx_log_debug0(NGX_LOG_DEBUG_HTTP, r->connection->log, 0,
                   "lua udp socket error retval handler");

    if (u->ft_type & NGX_HTTP_LUA_SOCKET_FT_RESOLVER) {
        return 2;
    }

    lua_pushnil(L);

    if (u->ft_type & NGX_HTTP_LUA_SOCKET_FT_PARTIALWRITE) {
        lua_pushliteral(L, "partial write");

    } else if (u->ft_type & NGX_HTTP_LUA_SOCKET_FT_TIMEOUT) {
        lua_pushliteral(L, "timeout");

    } else if (u->ft_type & NGX_HTTP_LUA_SOCKET_FT_CLOSED) {
        lua_pushliteral(L, "closed");

    } else if (u->ft_type & NGX_HTTP_LUA_SOCKET_FT_BUFTOOSMALL) {
        lua_pushliteral(L, "buffer too small");

    } else if (u->ft_type & NGX_HTTP_LUA_SOCKET_FT_NOMEM) {
        lua_pushliteral(L, "no memory");

    } else {

        lua_pushliteral(L, "error");
    }

    return 2;
}


static void
ngx_http_lua_resolve_finalize(ngx_http_request_t *r,
    ngx_http_lua_resolve_upstream_t *u)
{
    ngx_log_debug0(NGX_LOG_DEBUG_HTTP, r->connection->log, 0,
                   "lua finalize socket");

    if (u->cleanup) {
        *u->cleanup = NULL;
        u->cleanup = NULL;
    }

    if (u->resolved && u->resolved->ctx) {
        ngx_resolve_name_done(u->resolved->ctx);
        u->resolved->ctx = NULL;
    }

    if (u->waiting) {
        u->waiting = 0;
    }
}


static void
ngx_http_lua_socket_dummy_handler(ngx_http_request_t *r,
    ngx_http_lua_resolve_upstream_t *u)
{
    ngx_log_debug0(NGX_LOG_DEBUG_HTTP, r->connection->log, 0,
                   "lua udp socket dummy handler");
}


static void
ngx_http_lua_resolve_handle_error(ngx_http_request_t *r,
    ngx_http_lua_resolve_upstream_t *u, ngx_uint_t ft_type)
{
    ngx_http_lua_ctx_t          *ctx;
    ngx_http_lua_co_ctx_t       *coctx;

    ngx_log_debug0(NGX_LOG_DEBUG_HTTP, r->connection->log, 0,
                   "lua udp socket handle error");

    u->ft_type |= ft_type;

#if 0
    ngx_http_lua_socket_udp_finalize(r, u);
#endif

    u->read_event_handler = ngx_http_lua_socket_dummy_handler;

    coctx = u->co_ctx;

    if (coctx) {
        coctx->cleanup = NULL;
    }

    if (u->waiting) {
        u->waiting = 0;

        ctx = ngx_http_get_module_ctx(r, ngx_http_lua_module);
        if (ctx == NULL) {
            return;
        }

        ctx->resume_handler = ngx_http_lua_resolve_resume;
        ctx->cur_co_ctx = coctx;

        ngx_log_debug0(NGX_LOG_DEBUG_HTTP, r->connection->log, 0,
                       "lua udp socket waking up the current request");

        r->write_event_handler(r);
    }
}


static void
ngx_http_lua_socket_udp_cleanup(void *data)
{
    ngx_http_lua_resolve_upstream_t  *u = data;

    ngx_http_request_t  *r;

    r = u->request;

    ngx_log_debug1(NGX_LOG_DEBUG_HTTP, r->connection->log, 0,
                   "cleanup lua udp socket upstream request: \"%V\"", &r->uri);

    ngx_http_lua_resolve_finalize(r, u);
}


static ngx_int_t
ngx_http_lua_resolve_resume(ngx_http_request_t *r)
{
    int                          nret;
    lua_State                   *vm;
    ngx_int_t                    rc;
    ngx_connection_t            *c;
    ngx_http_lua_ctx_t          *ctx;
    ngx_http_lua_co_ctx_t       *coctx;

    ngx_http_lua_resolve_upstream_t      *u;

    ctx = ngx_http_get_module_ctx(r, ngx_http_lua_module);
    if (ctx == NULL) {
        return NGX_ERROR;
    }

    ctx->resume_handler = ngx_http_lua_wev_handler;

    ngx_log_debug0(NGX_LOG_DEBUG_HTTP, r->connection->log, 0,
                   "lua udp operation done, resuming lua thread");

    coctx = ctx->cur_co_ctx;

#if 0
    ngx_http_lua_probe_info("udp resume");
#endif

    u = coctx->data;

    ngx_log_debug2(NGX_LOG_DEBUG_HTTP, r->connection->log, 0,
                   "lua udp socket calling prepare retvals handler %p, "
                   "u:%p", u->prepare_retvals, u);

    nret = u->prepare_retvals(r, u, ctx->cur_co_ctx->co);
    if (nret == NGX_AGAIN) {
        return NGX_DONE;
    }

    c = r->connection;
    vm = ngx_http_lua_get_lua_vm(r, ctx);

    rc = ngx_http_lua_run_thread(vm, r, ctx, nret);

    ngx_log_debug1(NGX_LOG_DEBUG_HTTP, r->connection->log, 0,
                   "lua run thread returned %d", rc);

    if (rc == NGX_AGAIN) {
        return ngx_http_lua_run_posted_threads(c, vm, r, ctx);
    }

    if (rc == NGX_DONE) {
        ngx_http_lua_finalize_request(r, NGX_DONE);
        return ngx_http_lua_run_posted_threads(c, vm, r, ctx);
    }

    if (ctx->entered_content_phase) {
        ngx_http_lua_finalize_request(r, rc);
        return NGX_DONE;
    }

    return rc;
}


static void
ngx_http_lua_resolve_cleanup(void *data)
{
    ngx_resolver_ctx_t                      *rctx;
    ngx_http_lua_resolve_upstream_t      *u;
    ngx_http_lua_co_ctx_t                   *coctx = data;

    u = coctx->data;
    if (u == NULL) {
        return;
    }

    rctx = u->resolved->ctx;
    if (rctx == NULL) {
        return;
    }

    ngx_resolve_name_done(rctx);
}


/* vi:set ft=c ts=4 sw=4 et fdm=marker: */
