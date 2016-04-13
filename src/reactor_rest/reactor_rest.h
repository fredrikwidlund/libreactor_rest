#ifndef REACTOR_REST_H_INCLUDED
#define REACTOR_REST_H_INCLUDED

enum reactor_rest_event
{
  REACTOR_REST_ERROR,
  REACTOR_REST_REQUEST,
  REACTOR_REST_CLOSE
};

enum reactor_rest_flags
{
  REACTOR_REST_ENABLE_CORS = 0x01
};

enum reactor_rest_map_type
{
  REACTOR_REST_MAP_MATCH,
  REACTOR_REST_MAP_REGEX
};

enum reactor_rest_state
{
  REACTOR_REST_CLOSED,
  REACTOR_REST_OPEN,
  REACTOR_REST_CLOSING
};

typedef struct reactor_rest reactor_rest;
struct reactor_rest
{
  int                          state;
  int                          flags;
  reactor_http_server          http_server;
  reactor_user                 user;
  vector                       maps;
};

typedef struct reactor_rest_request reactor_rest_request;
struct reactor_rest_request
{
  reactor_rest                *server;
  reactor_http_server_session *session;
  reactor_http_request        *request;
  void                        *state;
  regmatch_t                  *match;
};

typedef void reactor_rest_handler(void *, reactor_rest_request *);

typedef struct reactor_rest_map reactor_rest_map;
struct reactor_rest_map
{
  int                          type;
  char                        *method;
  char                        *path;
  reactor_rest_handler        *handler;
  regex_t                     *regex;
};

void reactor_rest_init(reactor_rest *, reactor_user_call *, void *);
int  reactor_rest_open(reactor_rest *, char *, char *, int);
void reactor_rest_close(reactor_rest *);
void reactor_rest_event(void *, int, void *);
void reactor_rest_cors(void *, reactor_rest_request *);
int  reactor_rest_add_match(reactor_rest *, char *, char *, reactor_rest_handler *);
int  reactor_rest_add_regex(reactor_rest *, char *, char *, reactor_rest_handler *);
int  reactor_rest_try_map(reactor_rest *, reactor_rest_map *, reactor_rest_request *);
void reactor_rest_release_map(void *);
int  reactor_rest_match(char *, const char *, size_t);
void reactor_rest_respond_fields(reactor_rest_request *, unsigned, char *, char *, size_t, reactor_http_field *, size_t);
void reactor_rest_respond(reactor_rest_request *, unsigned, char *, char *, size_t);
void reactor_rest_respond_empty(reactor_rest_request *, unsigned);
void reactor_rest_respond_found(reactor_rest_request *, char *);
void reactor_rest_respond_clo(reactor_rest_request *, unsigned, clo *);

#endif /* REACTOR_REST_H_INCLUDED */
