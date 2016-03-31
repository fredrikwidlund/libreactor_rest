#define _GNU_SOURCE

#include <stdio.h>
#include <stdint.h>
#include <string.h>
#include <signal.h>
#include <netdb.h>
#include <assert.h>
#include <err.h>
#include <regex.h>
#include <sys/socket.h>

#include <dynamic.h>
#include <clo.h>
#include <reactor_core.h>
#include <reactor_net.h>
#include <reactor_http.h>

#include "reactor_rest.h"

void reactor_rest_init(reactor_rest *server, reactor_user_call *call, void *state)
{
  *server = (reactor_rest) {0};
  reactor_http_server_init(&server->http_server, reactor_rest_event, server);
  reactor_user_init(&server->user, call, state);
  vector_init(&server->maps, sizeof(reactor_rest_map));
}

int reactor_rest_open(reactor_rest *server, char *node, char *service, int flags)
{
  server->flags = flags;

  if (flags & REACTOR_REST_ENABLE_CORS)
    reactor_rest_add_match(server, "OPTIONS", NULL, reactor_rest_cors);

  return reactor_http_server_open(&server->http_server, node, service);
}

void reactor_rest_event(void *state, int type, void *data)
{
  reactor_rest *server;
  reactor_rest_map *map;
  reactor_rest_request request;
  reactor_http_server_session *session;
  size_t i;

  server = state;
  switch (type)
    {
    case REACTOR_HTTP_SERVER_REQUEST:
      session = data;
      request = (reactor_rest_request) {.server = server, .session = session, .request = &session->request};
      for (i = 0; i < vector_size(&server->maps); i ++)
        {
          map = vector_at(&server->maps, i);
          if (reactor_rest_try_map(server, map, &request))
            return;
        }
      reactor_rest_respond_empty(&request, 404);
      break;
    }
}

void reactor_rest_cors(void *state, reactor_rest_request *request)
{
  char *cors_origin, *cors_allow_headers;

  (void) state;
  cors_origin = reactor_http_field_lookup(&request->request->fields, "Origin");
  if (!cors_origin)
    {
      reactor_rest_respond_empty(request, 404);
      return;
    }

  cors_allow_headers = reactor_http_field_lookup(&request->request->fields, "Access-Control-Request-Headers");
  reactor_rest_respond_fields(request, 204, NULL, NULL, 0, (reactor_http_field[]) {
      {.key = "Access-Control-Allow-Methods", .value = "GET, OPTIONS"},
      {.key = "Access-Control-Allow-Headers", .value = cors_allow_headers},
      {.key = "Access-Control-Max-Age", .value = "1728000"}}, 3);
}

int reactor_rest_add_match(reactor_rest *server, char *method, char *path, reactor_rest_handler *handler)
{
  reactor_rest_map map =
    {
      .type = REACTOR_REST_MAP_MATCH,
      .method = method ? strdup(method) : NULL,
      .path = path ? strdup(path) : NULL,
      .handler = handler
    };

  return vector_push_back(&server->maps, &map);
}

int reactor_rest_add_regex(reactor_rest *server, char *method, char *regex, reactor_rest_handler *handler)
{
  reactor_rest_map map = {.type = REACTOR_REST_MAP_REGEX};
  int e;

  map.regex = malloc(sizeof(regex_t));
  if (!map.regex)
    return -1;

  map.method = strdup(method);
  if (!map.method)
    return -1;

  e = regcomp(map.regex, regex, REG_EXTENDED);
  if (e == -1)
    return -1;

  map.handler = handler;
  return vector_push_back(&server->maps, &map);
}

int reactor_rest_try_map(reactor_rest *server, reactor_rest_map *map, reactor_rest_request *request)
{
  size_t nmatch = 32;
  regmatch_t match[nmatch];
  int e;

  if (map->method && strcmp(map->method, request->request->method) != 0)
    return 0;

  switch (map->type)
    {
    case REACTOR_REST_MAP_MATCH:
      if (!map->path || strcmp(map->path, request->request->path) == 0)
        {
          map->handler(server->user.state, request);
          return 1;
        }
      break;
    case REACTOR_REST_MAP_REGEX:
      e = regexec(map->regex, request->request->path, 32, match, 0);
      if (e == 0)
        {
          request->match = match;
          map->handler(server->user.state, request);
          return 1;
        }
      break;
    }
  return 0;
}

void reactor_rest_respond_fields(reactor_rest_request *request, unsigned status,
                                 char *content_type, char *content, size_t content_size,
                                 reactor_http_field *fields, size_t nfields)
{
  reactor_http_field cors_fields[nfields + 3];
  char *cors_origin;

  cors_origin = NULL;
  if (request->server->flags & REACTOR_REST_ENABLE_CORS)
    cors_origin = reactor_http_field_lookup(&request->request->fields, "Origin");
  if (!cors_origin)
    reactor_http_server_session_respond_fields(request->session, status, content_type, content, content_size,
                                                 fields, nfields);
  else
    {
      memcpy(cors_fields, fields, nfields * (sizeof *fields));
      cors_fields[nfields] = (reactor_http_field) {.key = "Access-Control-Allow-Origin", .value = cors_origin};
      nfields ++;
      cors_fields[nfields] = (reactor_http_field) {.key = "Access-Control-Allow-Credentials", .value = "true"};
      nfields ++;
      cors_fields[nfields] = (reactor_http_field) {.key = "Vary", .value = "Origin"};
      nfields ++;
      reactor_http_server_session_respond_fields(request->session, status, content_type, content, content_size,
                                                 cors_fields, nfields);
    }
}

void reactor_rest_respond(reactor_rest_request *request, unsigned status,
                          char *content_type, char *content, size_t content_size)
{
  reactor_rest_respond_fields(request, status, content_type, content, content_size, NULL, 0);
}

void reactor_rest_respond_empty(reactor_rest_request *request, unsigned status)
{
  reactor_rest_respond(request, status, NULL, NULL, 0);
}

void reactor_rest_respond_found(reactor_rest_request *request, char *location)
{
  reactor_rest_respond_fields(request, 302, NULL, NULL, 0, (reactor_http_field[]){{.key = "Location", .value = location}}, 1);
}

void reactor_rest_respond_clo(reactor_rest_request *request, unsigned status, clo *clo)
{
  buffer b;
  int e;

  buffer_init(&b);
  e = 0;
  clo_encode(clo, &b, &e);
  if (e == 0)
    reactor_rest_respond(request, status, "application/json", buffer_data(&b), buffer_size(&b));
  else
    reactor_rest_respond_empty(request, 500);
  buffer_clear(&b);
}

