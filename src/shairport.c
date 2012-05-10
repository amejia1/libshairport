/*
 * ShairPort Initializer - Network Initializer/Mgr for Hairtunes RAOP
 * Copyright (c) M. Andrew Webster 2011
 * All rights reserved.
 *
 * Permission is hereby granted, free of charge, to any person
 * obtaining a copy of this software and associated documentation
 * files (the "Software"), to deal in the Software without
 * restriction, including without limitation the rights to use,
 * copy, modify, merge, publish, distribute, sublicense, and/or
 * sell copies of the Software, and to permit persons to whom the
 * Software is furnished to do so, subject to the following conditions:
 *
 * The above copyright notice and this permission notice shall be
 * included in all copies or substantial portions of the Software.
 *
 * THE SOFTWARE IS PROVIDED "AS IS", WITHOUT WARRANTY OF ANY KIND,
 * EXPRESS OR IMPLIED, INCLUDING BUT NOT LIMITED TO THE WARRANTIES
 * OF MERCHANTABILITY, FITNESS FOR A PARTICULAR PURPOSE AND
 * NONINFRINGEMENT. IN NO EVENT SHALL THE AUTHORS OR COPYRIGHT
 * HOLDERS BE LIABLE FOR ANY CLAIM, DAMAGES OR OTHER LIABILITY,
 * WHETHER IN AN ACTION OF CONTRACT, TORT OR OTHERWISE, ARISING
 * FROM, OUT OF OR IN CONNECTION WITH THE SOFTWARE OR THE USE OR
 * OTHER DEALINGS IN THE SOFTWARE.
 */

#define XBMC

#include "shairport.h"
#include "shairport_private.h"
#include "socketlib.h"
#include "hairtunes.h"

#include <stdio.h>
#include <string.h>
#include <unistd.h>
#include <regex.h>
#include <sys/types.h>
#include <fcntl.h>
#include <openssl/bio.h>
#include <openssl/ssl.h>
#include <openssl/err.h>

static struct printfPtr g_printf={NULL};

int __shairport_xprintf(const char *format, ...)
{
  char dbg[2048];
  va_list args;
  va_start(args, format);
  vsnprintf(dbg, sizeof(dbg), format, args);
  va_end(args);
  if(g_printf.extprintf)
  {
    g_printf.extprintf(dbg, sizeof(dbg));
  }
  else 
  {
    printf("%s", dbg);
  }

  return 1;
}

#ifndef TRUE
#define TRUE (-1)
#endif
#ifndef FALSE
#define FALSE (0)
#endif

static RSA *loadKey();
#ifndef XBMC
static int startAvahi(const char *pHwAddr, const char *pServerName, int pPort);
#endif
static void cleanupBuffers(struct connection *pConnection);
static void cleanup(struct connection *pConnection);
static void handleClient(int pSock, char *pPassword, char *pHWADDR);
static int getAvailChars(struct shairbuffer *pBuf);

static char *getTrimmedMalloc(char *pChar, int pSize, int pEndStr, int pAddNL);
static char *getTrimmed(char *pChar, int pSize, int pEndStr, int pAddNL, char *pTrimDest);
static void initBuffer(struct shairbuffer *pBuf, int pNumChars);
// static void printBufferInfo(struct shairbuffer *pBuf, int pLevel);
static void addToShairBuffer(struct shairbuffer *pBuf, char *pNewBuf);
static void addNToShairBuffer(struct shairbuffer *pBuf, char *pNewBuf, int pNofNewBuf);

static int readDataFromClient(int pSock, struct shairbuffer *pClientBuffer);
static int  parseMessage(struct connection *pConn, unsigned char *pIpBin, unsigned int pIpBinLen, char *pHWADDR);

// static void closePipe(int *pPipe);
static void setKeys(struct keyring *pKeys, char *pIV, char* pAESKey, char *pFmtp);
static void initConnection(struct connection *pConn, struct keyring *pKeys,
                struct comms *pComms, int pSocket, char *pPassword);

static void writeDataToClient(int pSock, struct shairbuffer *pResponse);
static void propogateCSeq(struct connection *pConn);
static int buildAppleResponse(struct connection *pConn, unsigned char *pIpBin, unsigned int pIpBinLen, char *pHwAddr);
#ifdef SIM_INCL
static void sim(int pLevel, char *pValue1, char *pValue2);
#endif
// static void slog(int pLevel, char *pFormat, ...);
static int  isLogEnabledFor(int pLevel);

// TEMP

static int kCurrentLogLevel = LOG_INFO;

#ifdef _WIN32
#define DEVNULL "nul"
#else
#define DEVNULL "/dev/null"
#endif
#define RSA_LOG_LEVEL LOG_DEBUG_VV
#define SOCKET_LOG_LEVEL LOG_DEBUG_VV
#define HEADER_LOG_LEVEL LOG_DEBUG
#define AVAHI_LOG_LEVEL LOG_DEBUG

static int m_running = 0;
static int tServerSock = -1;
static struct addrinfo *tAddrInfo;
static char tPassword[56] = "";
static char tHWID[HWID_SIZE] = {0,51,52,53,54,55};

#ifdef XBMC
struct AudioOutput g_ao;
void shairport_set_ao(struct AudioOutput *ao)
{
 g_ao=*ao;
}

void shairport_set_printf(struct printfPtr *funcPtr)
{
  g_printf = *funcPtr;
}
#endif

#ifndef XBMC
int main(int argc, char **argv)
#else
int shairport_main(int argc, char **argv)
#endif
{
  __shairport_xprintf("initializing shairport\n",NULL);
  char tHWID_Hex[HWID_SIZE * 2 + 1];
  char tKnownHwid[32];

  memset(tHWID_Hex, 0, sizeof(tHWID_Hex));

  char tServerName[56] = "ShairPort";

  int  tSimLevel = 0;
  int  tUseKnownHWID = FALSE;
  int  tDaemonize = FALSE;
  int  tPort = PORT;

  char *arg;
  while ( (arg = *++argv) ) {
    if(!strcmp(arg, "-a"))
    {
       strncpy(tServerName, *++argv, 55);
       argc--;
    }
    else if(!strncmp(arg, "--apname=", 9))
    {
      strncpy(tServerName, arg+9, 55);
    }
    else if(!strcmp(arg, "-p"))
    {
      strncpy(tPassword, *++argv, 55);
      argc--;
    }
    else if(!strncmp(arg, "--password=",11 ))
    {
      strncpy(tPassword, arg+11, 55);
    }
    else if(!strcmp(arg, "-o"))
    {
      tPort = atoi(*++argv);
      argc--;
    }
    else if(!strncmp(arg, "--server_port=", 14))
    {
      tPort = atoi(arg+14);
    }
    else if(!strcmp(arg, "-b")) 
    {
      __shairport_buffer_start_fill = atoi(*++argv);
      argc--;
    }
    else if(!strncmp(arg, "--buffer=", 9))
    {
      __shairport_buffer_start_fill = atoi(arg + 9);
    }
    else if(!strncmp(arg, "--mac=", 6))
    {
      tUseKnownHWID = TRUE;
      strcpy(tKnownHwid, arg+6);
    }
    else if(!strcmp(arg, "-q") || !strncmp(arg, "--quiet", 7))
    {
      kCurrentLogLevel = 0;
    }
    else if(!strcmp(arg, "-d"))
    {
      tDaemonize = TRUE;
      kCurrentLogLevel = 0;
    }
    else if(!strcmp(arg, "-v"))
    {
      kCurrentLogLevel = LOG_DEBUG;
    }
    else if(!strcmp(arg, "-v2"))
    {
      kCurrentLogLevel = LOG_DEBUG_V;
    }
    else if(!strcmp(arg, "-vv") || !strcmp(arg, "-v3"))
    {
      kCurrentLogLevel = LOG_DEBUG_VV;
    }    
    else if(!strcmp(arg, "-h") || !strcmp(arg, "--help"))
    {
      __shairport_xprintf("ShairPort version 0.05 C port - Airport Express emulator\n");
      __shairport_xprintf("Usage:\nshairport [OPTION...]\n\nOptions:\n");
      __shairport_xprintf("  -a, --apname=AirPort    Sets Airport name\n");
      __shairport_xprintf("  -p, --password=secret   Sets Password (not working)\n");
      __shairport_xprintf("  -o, --server_port=5000  Sets Port for Avahi/dns-sd\n");
      __shairport_xprintf("  -b, --buffer=282        Sets Number of frames to buffer before beginning playback\n");
      __shairport_xprintf("  -d                      Daemon mode\n");
      __shairport_xprintf("  -q, --quiet             Supresses all output.\n");
      __shairport_xprintf("  -v,-v2,-v3,-vv          Various debugging levels\n");
      __shairport_xprintf("\n");
      return 0;
    }    
  }

  if ( __shairport_buffer_start_fill < 30 || __shairport_buffer_start_fill > BUFFER_FRAMES ) {
     __shairport_xprintf("buffer value must be > 30 and < %d\n", BUFFER_FRAMES);
     return(0);
  }

  if(tDaemonize)
  {
    int tPid = fork();
    if(tPid < 0)
    {
      //exit(1); // Error on fork
    }
    else if(tPid > 0)
    {
      //exit(0);
    }
    else
    {
      setsid();
      int tIdx = 0;
      for(tIdx = getdtablesize(); tIdx >= 0; --tIdx)
      {
        close(tIdx);
      }
      tIdx = open(DEVNULL, O_RDWR);
      dup(tIdx);
      dup(tIdx);
    }
  }
  srand ( time(NULL) );

  if (!tUseKnownHWID)
  {
    srandom ( time(NULL) );

    int tIdx = 0;
    for(tIdx=0;tIdx<HWID_SIZE;tIdx++)
    {
      if(tIdx > 0)
      {
        if(!tUseKnownHWID)
        {
          int tVal = ((random() % 80) + 33);
          tHWID[tIdx] = tVal;
        }
      }
      sprintf(tHWID_Hex+(tIdx*2), "%02X",tHWID[tIdx]);
    }
  }
  else
  {
    strcpy(tHWID_Hex, tKnownHwid);
    sscanf(tHWID_Hex, "%02X%02X%02X%02X%02X%02X", (unsigned *)&tHWID[0],
           (unsigned *)&tHWID[1], (unsigned *)&tHWID[2], (unsigned *)&tHWID[3],
           (unsigned *)&tHWID[4], (unsigned *)&tHWID[5]);
  }

  __shairport_xprintf("LogLevel: %d\n", kCurrentLogLevel);
  __shairport_xprintf("AirName: %s\n", tServerName);
  __shairport_xprintf("HWID: %.*s\n", HWID_SIZE, tHWID+1);
  __shairport_xprintf("HWID_Hex(%d): %s\n", strlen(tHWID_Hex), tHWID_Hex);

  if(tSimLevel >= 1)
  {
    #ifdef SIM_INCL
    sim(tSimLevel, tTestValue, tHWID);
    #endif
    return(1);
  }
  else
  {
#ifndef XBMC
    startAvahi(tHWID_Hex, tServerName, tPort);
#endif
    __shairport_xprintf("Starting connection server: specified server port: %d\n", tPort);
    tServerSock = __shairport_setupListenServer(&tAddrInfo, tPort);
    if(tServerSock < 0)
    {
      freeaddrinfo(tAddrInfo);
      __shairport_xprintf("Error setting up server socket on port %d, try specifying a different port\n", tPort);
      return 0;
    }

    m_running = 1;

    return 1;
  }
}

int shairport_loop(void)
{
    if (!m_running || tServerSock <= 0)
        return 0;

    int tClientSock = 0;

    fd_set fds;
    FD_ZERO(&fds);
    FD_SET(tServerSock, &fds);

    struct timeval timeout;
    timeout.tv_sec = 1;
    timeout.tv_usec = 0;

    int readsock;

    __shairport_xprintf("Waiting for clients to connect\n");

    while(m_running)
    {
      int rc = select(tServerSock + 1, &fds, 0, 0, &timeout);
      if (rc == -1 && errno != EINTR)
        return 0;

      readsock = -1;
      if (FD_ISSET(tServerSock, &fds))
      {
        readsock = tServerSock;
      }

      FD_ZERO(&fds);
      FD_SET(tServerSock, &fds);
      timeout.tv_sec = 1;
      timeout.tv_usec = 0;

      if (readsock == -1)
        continue;

      tClientSock = __shairport_acceptClient(tServerSock, tAddrInfo);
      if(tClientSock > 0)
      {
#ifndef XBMC
        int tPid = 0;
        fork();
        if(tPid == 0)
        {
          freeaddrinfo(tAddrInfo);
          tAddrInfo = NULL;
          __shairport_xprintf("...Accepted Client Connection..\n");
          close(tServerSock);
          handleClient(tClientSock, tPassword, tHWID);
          //close(tClientSock);
          return 0;
        }
        else
        {
          __shairport_xprintf("Child now busy handling new client\n");
          close(tClientSock);
        }
#else
      __shairport_xprintf("...Accepted Client Connection..\n");
      handleClient(tClientSock, tPassword, tHWID);
#endif
      }
      else
      {
          return 0;
      }
  }

  __shairport_xprintf("Finished\n");
  if(tAddrInfo != NULL)
  {
    freeaddrinfo(tAddrInfo);
  }
  return 1;
}

void shairport_exit(void)
{
  m_running = 0;
  close(tServerSock);
}

int shairport_is_running(void)
{
  return m_running;
}

static int findEnd(char *tReadBuf)
{
  // find \n\n, \r\n\r\n, or \r\r is found
  int tIdx = 0;
  int tLen = strlen(tReadBuf);
  for(tIdx = 0; tIdx < tLen; tIdx++)
  {
    if(tReadBuf[tIdx] == '\r')
    {
      if(tIdx + 1 < tLen)
      {
        if(tReadBuf[tIdx+1] == '\r')
        {
          return (tIdx+1);
        }
        else if(tIdx+3 < tLen)
        {
          if(tReadBuf[tIdx+1] == '\n' &&
             tReadBuf[tIdx+2] == '\r' &&
             tReadBuf[tIdx+3] == '\n')
          {
            return (tIdx+3);
          }
        }
      }
    }
    else if(tReadBuf[tIdx] == '\n')
    {
      if(tIdx + 1 < tLen && tReadBuf[tIdx+1] == '\n')
      {
        return (tIdx + 1);
      }
    }
  }
  // Found nothing
  return -1;
}

static void handleClient(int pSock, char *pPassword, char *pHWADDR)
{
  __shairport_xprintf("In Handle Client\n");
  fflush(stdout);

  socklen_t len;
  struct sockaddr_storage addr;
  #ifdef AF_INET6
  unsigned char ipbin[INET6_ADDRSTRLEN];
  #else
  unsigned char ipbin[INET_ADDRSTRLEN];
  #endif
  unsigned int ipbinlen;
  int port;
  char ipstr[64];

  len = sizeof addr;
  getsockname(pSock, (struct sockaddr*)&addr, &len);

  // deal with both IPv4 and IPv6:
  if (addr.ss_family == AF_INET) {
      __shairport_xprintf("Constructing ipv4 address\n");
      struct sockaddr_in *s = (struct sockaddr_in *)&addr;
      port = ntohs(s->sin_port);
      inet_ntop(AF_INET, &s->sin_addr, ipstr, sizeof ipstr);
      memcpy(ipbin, &s->sin_addr, 4);
      ipbinlen = 4;
  } else { // AF_INET6
      struct sockaddr_in6 *s = (struct sockaddr_in6 *)&addr;
      port = ntohs(s->sin6_port);
      inet_ntop(AF_INET6, &s->sin6_addr, ipstr, sizeof ipstr);

      union {
        struct sockaddr_in6 s;
        unsigned char bin[sizeof(struct sockaddr_in6)];
      } addr;
      memcpy(&addr.s, &s->sin6_addr, sizeof(struct sockaddr_in6));

      if(memcmp(&addr.bin[0], "\x00\x00\x00\x00" "\x00\x00\x00\x00" "\x00\x00\xff\xff", 12) == 0)
      {
        // its ipv4...
        __shairport_xprintf("Constructing ipv4 from ipv6 address\n");
        memcpy(ipbin, &addr.bin[12], 4);
        ipbinlen = 4;
      }
      else
      {
        __shairport_xprintf("Constructing ipv6 address\n");
        memcpy(ipbin, &s->sin6_addr, 16);
        ipbinlen = 16;
      }
  }

  __shairport_xprintf("Peer IP address: %s\n", ipstr);
  __shairport_xprintf("Peer port      : %d\n", port);

  int tMoreDataNeeded = 1;
  struct keyring     tKeys;
  struct comms       tComms;
  struct connection  tConn;
  initConnection(&tConn, &tKeys, &tComms, pSock, pPassword);

  while(1)
  {
    tMoreDataNeeded = 1;

    initBuffer(&tConn.recv, 80); // Just a random, small size to seed the buffer with.
    initBuffer(&tConn.resp, 80);
    
    int tError = FALSE;
    while(1 == tMoreDataNeeded)
    {
      tError = readDataFromClient(pSock, &(tConn.recv));
      if(!tError && tConn.recv.current > 0)
      {
        __shairport_xprintf("Finished Reading some data from client\n");
        // parse client request
        tMoreDataNeeded = parseMessage(&tConn, ipbin, ipbinlen, pHWADDR);
        if(1 == tMoreDataNeeded)
        {
          __shairport_xprintf("\n\nNeed to read more data\n");
        }
        else if(-1 == tMoreDataNeeded) // Forked process down below ended.
        {
          __shairport_xprintf("Forked Process ended...cleaning up\n");
          cleanup(&tConn);
          // pSock was already closed
          return;
        }
        // if more data needed,
      }
      else
      {
        __shairport_xprintf("Error reading from socket, closing client\n");
        // Error reading data....quit.
        cleanup(&tConn);
        return;
      }
    }
    __shairport_xprintf("Writing: %d chars to socket\n", tConn.resp.current);
    //tConn->resp.data[tConn->resp.current-1] = '\0';
    writeDataToClient(pSock, &(tConn.resp));
   // Finished reading one message...
    cleanupBuffers(&tConn);
  }
  cleanup(&tConn);
  fflush(stdout);
}


static void writeDataToClient(int pSock, struct shairbuffer *pResponse)
{
  __shairport_xprintf("\n----Beg Send Response Header----\n%.*s\n", pResponse->current, pResponse->data);
  send(pSock, pResponse->data, pResponse->current,0);
  __shairport_xprintf("----Send Response Header----\n");
}

static int readDataFromClient(int pSock, struct shairbuffer *pClientBuffer)
{
  char tReadBuf[MAX_SIZE];
  strcpy(tReadBuf, "");

  int tRetval = 1;
  int tEnd = -1;
  while(tRetval > 0 && tEnd < 0)
  {
     // Read from socket until \n\n, \r\n\r\n, or \r\r is found
      __shairport_xprintf("Waiting To Read...\n");
      fflush(stdout);
      tRetval = read(pSock, tReadBuf, MAX_SIZE);
      // if new buffer contains the end of request string, only copy partial buffer?
      tEnd = findEnd(tReadBuf);
      if(tEnd >= 0)
      {
        if(pClientBuffer->marker == 0)
        {
          pClientBuffer->marker = tEnd+1; // Marks start of content
        }
        __shairport_xprintf("Found end of http request at: %d\n", tEnd);
        fflush(stdout);        
      }
      else
      {
        tEnd = MAX_SIZE;
        __shairport_xprintf("Read %d of data so far\n%s\n", tRetval, tReadBuf);
        fflush(stdout);
      }
      if(tRetval > 0)
      {
        // Copy read data into tReceive;
        __shairport_xprintf("Read %d data, using %d of it\n", tRetval, tEnd);
        addNToShairBuffer(pClientBuffer, tReadBuf, tRetval);
        __shairport_xprintf("Finished copying data\n");
      }
      else
      {
        __shairport_xprintf("Error reading data from socket, got: %d bytes", tRetval);
        return tRetval;
      }
  }
  if(tEnd + 1 != tRetval)
  {
    __shairport_xprintf("Read more data after end of http request. %d instead of %d\n", tRetval, tEnd+1);
  }
  __shairport_xprintf("Finished Reading Data:\n%s\nEndOfData\n", pClientBuffer->data);
  fflush(stdout);
  return 0;
}

static char *getFromBuffer(char *pBufferPtr, const char *pField, int pLenAfterField, int *pReturnSize, char *pDelims)
{
  __shairport_xprintf("GettingFromBuffer: %s\n", pField);
  char* tFound = strstr(pBufferPtr, pField);
  int tSize = 0;
  if(tFound != NULL)
  {
    tFound += (strlen(pField) + pLenAfterField);
    int tIdx = 0;
    char tDelim = pDelims[tIdx];
    char *tShortest = NULL;
    char *tEnd = NULL;
    while(tDelim != '\0')
    {
      tDelim = pDelims[tIdx++]; // Ensures that \0 is also searched.
      tEnd = strchr(tFound, tDelim);
      if(tEnd != NULL && (NULL == tShortest || tEnd < tShortest))
      {
        tShortest = tEnd;
      }
    }
    
    tSize = (int) (tShortest - tFound);
    __shairport_xprintf("Found %s  length: %d\n",tFound, tSize);
    if(pReturnSize != NULL)
    {
      *pReturnSize = tSize;
    }
  }
  else
  {
    __shairport_xprintf("Not Found\n");
  }
  return tFound;
}


static char *getFromHeader(char *pHeaderPtr, const char *pField, int *pReturnSize)
{
  return getFromBuffer(pHeaderPtr, pField, 2, pReturnSize, "\r\n");
}

static char *getFromContent(char *pContentPtr, const char* pField, int *pReturnSize)
{
  return getFromBuffer(pContentPtr, pField, 1, pReturnSize, "\r\n");
}

static char *getFromSetup(char *pContentPtr, const char* pField, int *pReturnSize)
{
  return getFromBuffer(pContentPtr, pField, 1, pReturnSize, ";\r\n");
}

// Handles compiling the Apple-Challenge, HWID, and Server IP Address
// Into the response the airplay client is expecting.
static int buildAppleResponse(struct connection *pConn, unsigned char *pIpBin, unsigned int pIpBinLen, char *pHWID)
{
  // Find Apple-Challenge
  char *tResponse = NULL;

  int tFoundSize = 0;
  char* tFound = getFromHeader(pConn->recv.data, "Apple-Challenge", &tFoundSize);
  if(tFound != NULL)
  {
    char tTrim[tFoundSize + 2];
    getTrimmed(tFound, tFoundSize, TRUE, TRUE, tTrim);
    __shairport_xprintf("HeaderChallenge:  [%s] len: %d  sizeFound: %d\n", tTrim, strlen(tTrim), tFoundSize);
    int tChallengeDecodeSize = 16;
    char *tChallenge = __shairport_decode_base64((unsigned char *)tTrim, tFoundSize, &tChallengeDecodeSize);
    __shairport_xprintf("Challenge Decode size: %d  expected 16\n", tChallengeDecodeSize);

    int tCurSize = 0;
    unsigned char tChalResp[38];

    memcpy(tChalResp, tChallenge, tChallengeDecodeSize);
    tCurSize += tChallengeDecodeSize;
    
    memcpy(tChalResp+tCurSize, pIpBin, pIpBinLen);
    tCurSize += pIpBinLen;

    memcpy(tChalResp+tCurSize, pHWID, HWID_SIZE);
    tCurSize += HWID_SIZE;

    int tPad = 32 - tCurSize;
    if (tPad > 0)
    {
      memset(tChalResp+tCurSize, 0, tPad);
      tCurSize += tPad;
    }

    char *tTmp = __shairport_encode_base64((unsigned char *)tChalResp, tCurSize);
    __shairport_xprintf("Full sig: %s\n", tTmp);
    free(tTmp);

    // RSA Encrypt
    RSA *rsa = loadKey();  // Free RSA
    int tSize = RSA_size(rsa);
    unsigned char tTo[tSize];
    RSA_private_encrypt(tCurSize, (unsigned char *)tChalResp, tTo, rsa, RSA_PKCS1_PADDING);
    
    // Wrap RSA Encrypted binary in Base64 encoding
    tResponse = __shairport_encode_base64(tTo, tSize);
    int tLen = strlen(tResponse);
    while(tLen > 1 && tResponse[tLen-1] == '=')
    {
      tResponse[tLen-1] = '\0';
    }
    free(tChallenge);
    RSA_free(rsa);
  }

  if(tResponse != NULL)
  {
    // Append to current response
    addToShairBuffer(&(pConn->resp), "Apple-Response: ");
    addToShairBuffer(&(pConn->resp), tResponse);
    addToShairBuffer(&(pConn->resp), "\r\n");
    free(tResponse);
    return TRUE;
  }
  return FALSE;
}

//parseMessage(tConn->recv.data, tConn->recv.mark, &tConn->resp, ipstr, pHWADDR, tConn->keys);
static int parseMessage(struct connection *pConn, unsigned char *pIpBin, unsigned int pIpBinLen, char *pHWID)
{
  int tReturn = 0; // 0 = good, 1 = Needs More Data, -1 = close client socket.
  if(pConn->resp.data == NULL)
  {
    initBuffer(&(pConn->resp), MAX_SIZE);
  }

  char *tContent = getFromHeader(pConn->recv.data, "Content-Length", NULL);
  if(tContent != NULL)
  {
    unsigned int tContentSize = atoi(tContent);
    if(pConn->recv.marker == 0 || pConn->recv.current-pConn->recv.marker != tContentSize)
    {
      if(isLogEnabledFor(HEADER_LOG_LEVEL))
      {
        __shairport_xprintf("Content-Length: %s value -> %d\n", tContent, tContentSize);
        if(pConn->recv.marker != 0)
        {
          __shairport_xprintf("ContentPtr has %d, but needs %d\n",
                               (pConn->recv.current-pConn->recv.marker), tContentSize);
        }
      }
      // check if value in tContent > 2nd read from client.
      return 1; // means more content-length needed
    }
  }
  else
  {
    __shairport_xprintf("No content, header only\n");
  }

  // "Creates" a new Response Header for our response message
  addToShairBuffer(&(pConn->resp), "RTSP/1.0 200 OK\r\n");

  if(isLogEnabledFor(LOG_INFO))
  {
    int tLen = strchr(pConn->recv.data, ' ') - pConn->recv.data;
    if(tLen < 0 || tLen > 20)
    {
      tLen = 20;
    }
    __shairport_xprintf("********** RECV %.*s **********\n", tLen, pConn->recv.data);
  }

  if(pConn->password != NULL)
  {
    
  }

  if(buildAppleResponse(pConn, pIpBin, pIpBinLen, pHWID)) // need to free sig
  {
    __shairport_xprintf("Added AppleResponse to Apple-Challenge request\n");
  }

  // Find option, then based on option, do different actions.
  if(strncmp(pConn->recv.data, "OPTIONS", 7) == 0)
  {
    propogateCSeq(pConn);
    addToShairBuffer(&(pConn->resp),
      "Public: ANNOUNCE, SETUP, RECORD, PAUSE, FLUSH, TEARDOWN, OPTIONS, GET_PARAMETER, SET_PARAMETER\r\n");
  }
  else if(!strncmp(pConn->recv.data, "ANNOUNCE", 8))
  {
    char *tContent = pConn->recv.data + pConn->recv.marker;
    int tSize = 0;
    char *tHeaderVal = getFromContent(tContent, "a=aesiv", &tSize); // Not allocated memory, just pointing
    if(tSize > 0)
    {
      int tKeySize = 0;
      char tEncodedAesIV[tSize + 2];
      getTrimmed(tHeaderVal, tSize, TRUE, TRUE, tEncodedAesIV);
      __shairport_xprintf("AESIV: [%.*s] Size: %d  Strlen: %d\n", tSize, tEncodedAesIV, tSize, strlen(tEncodedAesIV));
      char *tDecodedIV =  __shairport_decode_base64((unsigned char*) tEncodedAesIV, tSize, &tSize);

      // grab the key, copy it out of the receive buffer
      tHeaderVal = getFromContent(tContent, "a=rsaaeskey", &tKeySize);
      char tEncodedAesKey[tKeySize + 2]; // +1 for nl, +1 for \0
      getTrimmed(tHeaderVal, tKeySize, TRUE, TRUE, tEncodedAesKey);
      __shairport_xprintf("AES KEY: [%s] Size: %d  Strlen: %d\n", tEncodedAesKey, tKeySize, strlen(tEncodedAesKey));
      // remove base64 coding from key
      char *tDecodedAesKey = __shairport_decode_base64((unsigned char*) tEncodedAesKey,
                              tKeySize, &tKeySize);  // Need to free DecodedAesKey

      // Grab the formats
      int tFmtpSize = 0;
      char *tFmtp = getFromContent(tContent, "a=fmtp", &tFmtpSize);  // Don't need to free
      tFmtp = getTrimmedMalloc(tFmtp, tFmtpSize, TRUE, FALSE); // will need to free
      __shairport_xprintf("Format: %s\n", tFmtp);

      RSA *rsa = loadKey();
      // Decrypt the binary aes key
      char *tDecryptedKey = malloc(RSA_size(rsa) * sizeof(char)); // Need to Free Decrypted key
      //char tDecryptedKey[RSA_size(rsa)];
      if(RSA_private_decrypt(tKeySize, (unsigned char *)tDecodedAesKey, 
      (unsigned char*) tDecryptedKey, rsa, RSA_PKCS1_OAEP_PADDING) >= 0)
      {
        __shairport_xprintf("Decrypted AES key from RSA Successfully\n");
      }
      else
      {
        __shairport_xprintf("Error Decrypting AES key from RSA\n");
      }
      free(tDecodedAesKey);
      RSA_free(rsa);

      setKeys(pConn->keys, tDecodedIV, tDecryptedKey, tFmtp);

      propogateCSeq(pConn);
    }
  }
  else if(!strncmp(pConn->recv.data, "SETUP", 5))
  {
    // Setup pipes
//    struct comms *tComms = pConn->hairtunes;
//   if (! (pipe(tComms->in) == 0 && pipe(tComms->out) == 0))
//    {
//      __shairport_xprintf("Error setting up hairtunes communications...some things probably wont work very well.\n");
//    }
    
    // Setup fork
    char tPort[8] = "6000";  // get this from dup()'d stdout of child pid

    __shairport_xprintf("******** SETUP!!!!!\n",NULL);
#ifndef XBMC
    int tPid = fork();
    if(tPid == 0)
    {
#endif
      int tDataport=0;
      char tCPortStr[8] = "59010";
      char tTPortStr[8] = "59012";
      int tSize = 0;

      char *tFound  =getFromSetup(pConn->recv.data, "control_port", &tSize);
      getTrimmed(tFound, tSize, 1, 0, tCPortStr);
      tFound = getFromSetup(pConn->recv.data, "timing_port", &tSize);
      getTrimmed(tFound, tSize, 1, 0, tTPortStr);

      __shairport_xprintf("converting %s and %s from str->int\n", tCPortStr, tTPortStr);
      int tControlport = atoi(tCPortStr);
      int tTimingport = atoi(tTPortStr);

      __shairport_xprintf("Got %d for CPort and %d for TPort\n", tControlport, tTimingport);
      char *tRtp = NULL;
      char *tPipe = NULL;
      char *tAoDriver = NULL;
      char *tAoDeviceName = NULL;
      char *tAoDeviceId = NULL;
      struct keyring *tKeys = pConn->keys;

#ifndef XBMC
      // *************************************************
      // ** Setting up Pipes, AKA no more debug/output  **
      // *************************************************
      dup2(tComms->in[0],0);   // Input to child
      closePipe(&(tComms->in[0]));
      closePipe(&(tComms->in[1]));

      dup2(tComms->out[1], 1); // Output from child
      closePipe(&(tComms->out[1]));
      closePipe(&(tComms->out[0]));

      pConn->keys = NULL;
      pConn->hairtunes = NULL;

      // Free up any recv buffers, etc..
      if(pConn->clientSocket != -1)
      {
        close(pConn->clientSocket);
        pConn->clientSocket = -1;
      }
      cleanupBuffers(pConn);
#endif
      __shairport_hairtunes_init(tKeys->aeskey, tKeys->aesiv, tKeys->fmt, tControlport, tTimingport,
                      tDataport, tRtp, tPipe, tAoDriver, tAoDeviceName, tAoDeviceId);
#ifndef XBMC
      // Quit when finished.
      __shairport_xprintf("Returned from hairtunes init....returning -1, should close out this whole side of the fork\n");
      return -1;
    }
    else if(tPid >0)
    {
      // Ensure Connection has access to the pipe.
      closePipe(&(tComms->in[0]));
      closePipe(&(tComms->out[1]));

      char tFromHairtunes[80];
      int tRead = read(tComms->out[0], tFromHairtunes, 80);
      if(tRead <= 0)
      {
        __shairport_xprintf("Error reading port from hairtunes function, assuming default port: %d\n", tPort);
      }
      else
      {
        int tSize = 0;
        char *tPortStr = getFromHeader(tFromHairtunes, "port", &tSize);
        if(tPortStr != NULL)
        {
          getTrimmed(tPortStr, tSize, TRUE, FALSE, tPort);
        }
        else
        {
          __shairport_xprintf("Read %d bytes, Error translating %s into a port\n", tRead, tFromHairtunes);
        }
      }

      int tSize;
#endif

      //  READ Ports from here?close(pConn->hairtunes_pipes[0]);
      propogateCSeq(pConn);
      tSize = 0;
      char *tTransport = getFromHeader(pConn->recv.data, "Transport", &tSize);
      addToShairBuffer(&(pConn->resp), "Transport: ");
      addNToShairBuffer(&(pConn->resp), tTransport, tSize);
      // Append server port:
      addToShairBuffer(&(pConn->resp), ";server_port=");
      addToShairBuffer(&(pConn->resp), tPort);
      addToShairBuffer(&(pConn->resp), "\r\nSession: DEADBEEF\r\n");
#ifndef XBMC
    }
    else
    {
      __shairport_xprintf("Error forking process....dere' be errors round here.\n");
      return -1;
    }
#endif
  }
  else if(!strncmp(pConn->recv.data, "TEARDOWN", 8))
  {
    // Be smart?  Do more finish up stuff...
    addToShairBuffer(&(pConn->resp), "Connection: close\r\n");
    propogateCSeq(pConn);
#ifndef XBMC
    close(pConn->hairtunes->in[1]);
    __shairport_xprintf("Tearing down connection, closing pipes\n");
#else
    __shairport_hairtunes_cleanup();
#endif
    //close(pConn->hairtunes->out[0]);
    tReturn = -1;  // Close client socket, but sends an ACK/OK packet first
  }
  else if(!strncmp(pConn->recv.data, "FLUSH", 5))
  {
    // TBD FLUSH
#ifndef XBMC
    write(pConn->hairtunes->in[1], "flush\n", 6);
#else
    __shairport_hairtunes_flush();
#endif
    propogateCSeq(pConn);
  }
  else if(!strncmp(pConn->recv.data, "SET_PARAMETER", 13))
  {
    propogateCSeq(pConn);
    int tSize = 0;
    char *buffer = NULL;
    char *contentType = getFromHeader(pConn->recv.data, "Content-Type", &tSize);
    char *tContent = getFromHeader(pConn->recv.data, "Content-Length", NULL);
    int iContentSize = 0;
    int isJpg = 0;
    
    if(tContent != NULL)
    {
      iContentSize = atoi(tContent);
    }

    if( tSize > 1 && 
        (strncmp(contentType, "application/x-dmap-tagged", tSize) == 0) ||
        (strncmp(contentType, "image/jpeg", tSize) == 0)                 )
    {
      if( (pConn->recv.current - pConn->recv.marker) == iContentSize && pConn->recv.marker != 0)
      {
        if(strncmp(contentType, "image/jpeg", tSize) == 0)
        {
          isJpg = 1;
        }
        buffer = (char *)malloc(iContentSize * sizeof(char));
        memcpy(buffer, pConn->recv.data + pConn->recv.marker, iContentSize);                                                                                                                                     
      }
      else
      {
        iContentSize = 0;
      }
    }
    else
    {
      iContentSize = 0;
    }
    char *tVol = getFromHeader(pConn->recv.data, "volume", &tSize);
    if( tVol)
    {
      __shairport_xprintf("About to write [vol: %.*s] data to hairtunes\n", tSize, tVol);
    }
    // TBD VOLUME
#ifndef XBMC
    write(pConn->hairtunes->in[1], "vol: ", 5);
    write(pConn->hairtunes->in[1], tVol, tSize);
    write(pConn->hairtunes->in[1], "\n", 1);
#else
    if(tVol)
    {
      __shairport_hairtunes_setvolume(atof(tVol));
    }
    
    if(iContentSize)
    {
      if(isJpg)
      {
        __shairport_hairtunes_set_metadata_coverart(buffer, iContentSize);      
      }
      else
      {
        __shairport_hairtunes_set_metadata(buffer, iContentSize);
      }
      free(buffer);
    }
#endif
    __shairport_xprintf("Finished writing data write data to hairtunes\n");
  }
  else
  {
    __shairport_xprintf("\n\nUn-Handled recv: %s\n", pConn->recv.data);
    propogateCSeq(pConn);
  }
  addToShairBuffer(&(pConn->resp), "\r\n");
  return tReturn;
}

// Copies CSeq value from request, and adds standard header values in.
static void propogateCSeq(struct connection *pConn) //char *pRecvBuffer, struct shairbuffer *pConn->recp.data)
{
  int tSize=0;
  char *tRecPtr = getFromHeader(pConn->recv.data, "CSeq", &tSize);
  addToShairBuffer(&(pConn->resp), "Audio-Jack-Status: connected; type=analog\r\n");
  addToShairBuffer(&(pConn->resp), "CSeq: ");
  addNToShairBuffer(&(pConn->resp), tRecPtr, tSize);
  addToShairBuffer(&(pConn->resp), "\r\n");
}

static void cleanupBuffers(struct connection *pConn)
{
  if(pConn->recv.data != NULL)
  {
    free(pConn->recv.data);
    pConn->recv.data = NULL;
  }
  if(pConn->resp.data != NULL)
  {
    free(pConn->resp.data);
    pConn->resp.data = NULL;
  }
}

static void cleanup(struct connection *pConn)
{
  cleanupBuffers(pConn);
  // TBD CLEANUP
#ifndef XBMC
  if(pConn->hairtunes != NULL)
  {

    closePipe(&(pConn->hairtunes->in[0]));
    closePipe(&(pConn->hairtunes->in[1]));
    closePipe(&(pConn->hairtunes->out[0]));
    closePipe(&(pConn->hairtunes->out[1]));
  }
#endif
  if(pConn->keys != NULL)
  {
    if(pConn->keys->aesiv != NULL)
    {
      free(pConn->keys->aesiv);
    }
    if(pConn->keys->aeskey != NULL)
    {
      free(pConn->keys->aeskey);
    }
    if(pConn->keys->fmt != NULL)
    {
      free(pConn->keys->fmt);
    }
    pConn->keys = NULL;
  }
  if(pConn->clientSocket != -1)
  {
    close(pConn->clientSocket);
    pConn->clientSocket = -1;
  }
}

#ifndef XBMC
static int startAvahi(const char *pHWStr, const char *pServerName, int pPort)
{
  int tMaxServerName = 25; // Something reasonable?  iPad showed 21, iphone 25
  int tPid = fork();
  if(tPid == 0)
  {
    char tName[100 + HWID_SIZE + 3];
    if(strlen(pServerName) > tMaxServerName)
    {
      __shairport_xprintf("Hey dog, we see you like long server names, "
              "so we put a strncat in our command so we don't buffer overflow, while you listen to your flow.\n"
              "We just used the first %d characters.  Pick something shorter if you want\n", tMaxServerName);
    }
    
    tName[0] = '\0';
    char tPort[SERVLEN];
    sprintf(tPort, "%d", pPort);
    strcat(tName, pHWStr);
    strcat(tName, "@");
    strncat(tName, pServerName, tMaxServerName);
    __shairport_xprintf("Avahi/DNS-SD Name: %s\n", tName);
    
    execlp("avahi-publish-service", "avahi-publish-service", tName,
         "_raop._tcp", tPort, "tp=UDP","sm=false","sv=false","ek=1","et=0,1",
         "cn=0,1","ch=2","ss=16","sr=44100","pw=false","vn=3","txtvers=1", NULL);
    execlp("dns-sd", "dns-sd", "-R", tName,
         "_raop._tcp", ".", tPort, "tp=UDP","sm=false","sv=false","ek=1","et=0,1",
         "cn=0,1","ch=2","ss=16","sr=44100","pw=false","vn=3","txtvers=1", NULL);
    if(errno == -1) {
            perror("error");
    }

    __shairport_xprintf("Bad error... couldn't find or failed to run: avahi-publish-service OR dns-sd\n");
    //exit(1);
  }
  else
  {
    __shairport_xprintf("Avahi/DNS-SD started on PID: %d\n", tPid);
  }
  return tPid;
}
#endif

// static void printBufferInfo(struct shairbuffer *pBuf, int pLevel)
// {
//   __shairport_xprintf("Buffer: [%s]  size: %d  maxchars:%d\n", pBuf->data, pBuf->current, pBuf->maxsize/sizeof(char));
// }

static int getAvailChars(struct shairbuffer *pBuf)
{
  return (pBuf->maxsize / sizeof(char)) - pBuf->current;
}

static void addToShairBuffer(struct shairbuffer *pBuf, char *pNewBuf)
{
  addNToShairBuffer(pBuf, pNewBuf, strlen(pNewBuf));
}

static void addNToShairBuffer(struct shairbuffer *pBuf, char *pNewBuf, int pNofNewBuf)
{
  int tAvailChars = getAvailChars(pBuf);
  if(pNofNewBuf > tAvailChars)
  {
    int tNewSize = pBuf->maxsize * 2 + MAX_SIZE + sizeof(char);
    char *tTmpBuf = malloc(tNewSize);

    tTmpBuf[0] = '\0';
    memset(tTmpBuf, 0, tNewSize/sizeof(char));
    memcpy(tTmpBuf, pBuf->data, pBuf->current);
    free(pBuf->data);

    pBuf->maxsize = tNewSize;
    pBuf->data = tTmpBuf;
  }
  memcpy(pBuf->data + pBuf->current, pNewBuf, pNofNewBuf);
  pBuf->current += pNofNewBuf;
  if(getAvailChars(pBuf) > 1)
  {
    pBuf->data[pBuf->current] = '\0';
  }
}

static char *getTrimmedMalloc(char *pChar, int pSize, int pEndStr, int pAddNL)
{
  int tAdditionalSize = 0;
  if(pEndStr)
    tAdditionalSize++;
  if(pAddNL)
    tAdditionalSize++;
  char *tTrimDest = malloc(sizeof(char) * (pSize + tAdditionalSize));
  return getTrimmed(pChar, pSize, pEndStr, pAddNL, tTrimDest);
}

// Must free returned ptr
static char *getTrimmed(char *pChar, int pSize, int pEndStr, int pAddNL, char *pTrimDest)
{
  int tSize = pSize;
  if(pEndStr)
  {
    tSize++;
  }
  if(pAddNL)
  {
    tSize++;
  }
  
  memset(pTrimDest, 0, tSize);
  memcpy(pTrimDest, pChar, pSize);
  if(pAddNL)
  {
    pTrimDest[pSize] = '\n';
  }
  if(pEndStr)
  {
    pTrimDest[tSize-1] = '\0';
  }
  return pTrimDest;
}

// static void slog(int pLevel, char *pFormat, ...)
// {
//   //#ifdef SHAIRPORT_LOG
//   //if(isLogEnabledFor(pLevel))
//   {
//     va_list argp;
//     va_start(argp, pFormat);
//     __shairport_xprintf(pFormat, argp);
//     //vprintf(pFormat, argp);
//     va_end(argp);
//   }
//   //#endif
// }

static int isLogEnabledFor(int pLevel)
{
  if(pLevel <= kCurrentLogLevel)
  {
    return TRUE;
  }
  return FALSE;
}

static void initConnection(struct connection *pConn, struct keyring *pKeys, 
                    struct comms *pComms, int pSocket, char *pPassword)
{
#ifndef XBMC
  pConn->hairtunes = pComms;
#else
  (void)pComms;
#endif
  if(pKeys != NULL)
  {
    pConn->keys = pKeys;
    pConn->keys->aesiv = NULL;
    pConn->keys->aeskey = NULL;
    pConn->keys->fmt = NULL;
  }
  pConn->recv.data = NULL;  // Pre-init buffer expected to be NULL
  pConn->resp.data = NULL;  // Pre-init buffer expected to be NULL
  pConn->clientSocket = pSocket;
  if(strlen(pPassword) >0)
  {
    pConn->password = pPassword;
  }
  else
  {
    pConn->password = NULL;
  }
}

// static void closePipe(int *pPipe)
// {
//   if(*pPipe != -1)
//   {
//     close(*pPipe);
//     *pPipe = -1;
//   }
// }

static void initBuffer(struct shairbuffer *pBuf, int pNumChars)
{
  if(pBuf->data != NULL)
  {
    __shairport_xprintf("Hrm, buffer wasn't cleaned up....trying to free\n");
    free(pBuf->data);
    __shairport_xprintf("Free didn't seem to seg fault....huzzah\n");
  }
  pBuf->current = 0;
  pBuf->marker = 0;
  pBuf->maxsize = sizeof(char) * pNumChars;
  pBuf->data = malloc(pBuf->maxsize);
  memset(pBuf->data, 0, pBuf->maxsize);
}

static void setKeys(struct keyring *pKeys, char *pIV, char* pAESKey, char *pFmtp)
{
  if(pKeys->aesiv != NULL)
  {
    free(pKeys->aesiv);
  }
  if(pKeys->aeskey != NULL)
  {
    free(pKeys->aeskey);
  }
  if(pKeys->fmt != NULL)
  {
    free(pKeys->fmt);
  }
  pKeys->aesiv = pIV;
  pKeys->aeskey = pAESKey;
  pKeys->fmt = pFmtp;
}

#define AIRPORT_PRIVATE_KEY \
"-----BEGIN RSA PRIVATE KEY-----\n" \
"MIIEpQIBAAKCAQEA59dE8qLieItsH1WgjrcFRKj6eUWqi+bGLOX1HL3U3GhC/j0Qg90u3sG/1CUt\n" \
"wC5vOYvfDmFI6oSFXi5ELabWJmT2dKHzBJKa3k9ok+8t9ucRqMd6DZHJ2YCCLlDRKSKv6kDqnw4U\n" \
"wPdpOMXziC/AMj3Z/lUVX1G7WSHCAWKf1zNS1eLvqr+boEjXuBOitnZ/bDzPHrTOZz0Dew0uowxf\n" \
"/+sG+NCK3eQJVxqcaJ/vEHKIVd2M+5qL71yJQ+87X6oV3eaYvt3zWZYD6z5vYTcrtij2VZ9Zmni/\n" \
"UAaHqn9JdsBWLUEpVviYnhimNVvYFZeCXg/IdTQ+x4IRdiXNv5hEewIDAQABAoIBAQDl8Axy9XfW\n" \
"BLmkzkEiqoSwF0PsmVrPzH9KsnwLGH+QZlvjWd8SWYGN7u1507HvhF5N3drJoVU3O14nDY4TFQAa\n" \
"LlJ9VM35AApXaLyY1ERrN7u9ALKd2LUwYhM7Km539O4yUFYikE2nIPscEsA5ltpxOgUGCY7b7ez5\n" \
"NtD6nL1ZKauw7aNXmVAvmJTcuPxWmoktF3gDJKK2wxZuNGcJE0uFQEG4Z3BrWP7yoNuSK3dii2jm\n" \
"lpPHr0O/KnPQtzI3eguhe0TwUem/eYSdyzMyVx/YpwkzwtYL3sR5k0o9rKQLtvLzfAqdBxBurciz\n" \
"aaA/L0HIgAmOit1GJA2saMxTVPNhAoGBAPfgv1oeZxgxmotiCcMXFEQEWflzhWYTsXrhUIuz5jFu\n" \
"a39GLS99ZEErhLdrwj8rDDViRVJ5skOp9zFvlYAHs0xh92ji1E7V/ysnKBfsMrPkk5KSKPrnjndM\n" \
"oPdevWnVkgJ5jxFuNgxkOLMuG9i53B4yMvDTCRiIPMQ++N2iLDaRAoGBAO9v//mU8eVkQaoANf0Z\n" \
"oMjW8CN4xwWA2cSEIHkd9AfFkftuv8oyLDCG3ZAf0vrhrrtkrfa7ef+AUb69DNggq4mHQAYBp7L+\n" \
"k5DKzJrKuO0r+R0YbY9pZD1+/g9dVt91d6LQNepUE/yY2PP5CNoFmjedpLHMOPFdVgqDzDFxU8hL\n" \
"AoGBANDrr7xAJbqBjHVwIzQ4To9pb4BNeqDndk5Qe7fT3+/H1njGaC0/rXE0Qb7q5ySgnsCb3DvA\n" \
"cJyRM9SJ7OKlGt0FMSdJD5KG0XPIpAVNwgpXXH5MDJg09KHeh0kXo+QA6viFBi21y340NonnEfdf\n" \
"54PX4ZGS/Xac1UK+pLkBB+zRAoGAf0AY3H3qKS2lMEI4bzEFoHeK3G895pDaK3TFBVmD7fV0Zhov\n" \
"17fegFPMwOII8MisYm9ZfT2Z0s5Ro3s5rkt+nvLAdfC/PYPKzTLalpGSwomSNYJcB9HNMlmhkGzc\n" \
"1JnLYT4iyUyx6pcZBmCd8bD0iwY/FzcgNDaUmbX9+XDvRA0CgYEAkE7pIPlE71qvfJQgoA9em0gI\n" \
"LAuE4Pu13aKiJnfft7hIjbK+5kyb3TysZvoyDnb3HOKvInK7vXbKuU4ISgxB2bB3HcYzQMGsz1qJ\n" \
"2gG0N5hvJpzwwhbhXqFKA4zaaSrw622wDniAK5MlIE0tIAKKP4yxNGjoD2QYjhBGuhvkWKaXTyY=\n" \
"-----END RSA PRIVATE KEY-----"

static RSA *loadKey()
{
  BIO *tBio = BIO_new_mem_buf(AIRPORT_PRIVATE_KEY, -1);
  RSA *rsa = PEM_read_bio_RSAPrivateKey(tBio, NULL, NULL, NULL); //NULL, NULL, NULL);
  BIO_free(tBio);
  __shairport_xprintf("RSA Key: %d\n", RSA_check_key(rsa));
  return rsa;
}
