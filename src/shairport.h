#ifndef __SHAIRPORT_H__
#define __SHAIRPORT_H__

#include <ao/ao.h>

#include <stdint.h>

#define HWID_SIZE 6
#define SHAIRPORT_LOG 1

#ifndef LOG_INFO
#define LOG_INFO     5
#endif

#ifndef LOG_DEBUG
#define LOG_DEBUG    6
#endif

#define LOG_DEBUG_V  7
#define LOG_DEBUG_VV 8

struct shairbuffer
{
  char *data;
  int   current;
  int   maxsize;
  int   marker;
};

struct keyring
{
  char *aeskey;
  char *aesiv;
  char *fmt;
};

struct comms
{
  int  in[2];
  int  out[2];
};

struct connection
{
  struct shairbuffer  recv;
  struct shairbuffer  resp;
  struct keyring      *keys; // Does not point to malloc'd memory.
#ifndef XBMC
  struct comms        *hairtunes;
#endif
  int                 clientSocket;
  char                *password;
};

#ifdef __cplusplus
extern "C"
{
#endif /* __cplusplus */

struct printfPtr
{
  int (*extprintf)(const char* msg, size_t msgSize);
};

#define SHAIRPORT_AUDIOOUTPUT_VERSION 2
struct AudioOutput
{
  void (*ao_initialize)(void);
  int (*ao_play)(ao_device *, char *, uint32_t);
  int (*ao_default_driver_id)(void);
  ao_device* (*ao_open_live)( int, ao_sample_format *, ao_option *);
  int (*ao_close)(ao_device *);
  /* -- Device Setup/Playback/Teardown -- */
  int (*ao_append_option)(ao_option **, const char *, const char *);
  void (*ao_free_options)(ao_option *);
  char* (*ao_get_option)(ao_option *, const char* );
  void (*ao_set_metadata)(const char *buffer, unsigned int size);                                                                                                                                                
  void (*ao_set_metadata_coverart)(const char *buffer, unsigned int size);
  void (*ao_set_volume)(float volume);
};

int shairport_main(int argc, char **argv);
void shairport_exit(void);
int shairport_loop(void);
int shairport_is_running(void);
void shairport_set_ao(struct AudioOutput *ao);
void shairport_set_printf(struct printfPtr *funcPtr);

#ifdef __cplusplus
}
#endif /* __cplusplus */

#endif

