/**
* vim: set ts=4 :
* =============================================================================
* SourceMod Sample Extension
* Copyright (C) 2004-2008 AlliedModders LLC.  All rights reserved.
* =============================================================================
*
* This program is free software; you can redistribute it and/or modify it under
* the terms of the GNU General Public License, version 3.0, as published by the
* Free Software Foundation.
* 
* This program is distributed in the hope that it will be useful, but WITHOUT
* ANY WARRANTY; without even the implied warranty of MERCHANTABILITY or FITNESS
* FOR A PARTICULAR PURPOSE.  See the GNU General Public License for more
* details.
*
* You should have received a copy of the GNU General Public License along with
* this program.  If not, see <http://www.gnu.org/licenses/>.
*
* As a special exception, AlliedModders LLC gives you permission to link the
* code of this program (as well as its derivative works) to "Half-Life 2," the
* "Source Engine," the "SourcePawn JIT," and any Game MODs that run on software
* by the Valve Corporation.  You must obey the GNU General Public License in
* all respects for all other code used.  Additionally, AlliedModders LLC grants
* this exception to all derivative works.  AlliedModders LLC defines further
* exceptions, found in LICENSE.txt (as of this writing, version JULY-31-2007),
* or <http://www.sourcemod.net/license.php>.
*
* Version: $Id$
*/

#ifndef _INCLUDE_SOURCEMOD_EXTENSION_PROPER_H_
#define _INCLUDE_SOURCEMOD_EXTENSION_PROPER_H_

#ifdef _WIN32
#include <winsock2.h>
#include <ws2tcpip.h>
#else
#include <poll.h>
#include <sys/socket.h>
#include <sys/ioctl.h>
#include <netinet/in.h>
#include <arpa/inet.h>
#include <fcntl.h>
#endif

#include "smsdk_ext.h"
#include <ITimerSystem.h>
#include <iclient.h>

#ifdef EXPORT
#undef EXPORT
#include "opus.h"
#endif
#include "ringbuffer.h"

/**
* @file extension.h
* @brief Voice extension header
*/

#define MAX_CLIENTS 16

#ifdef _WIN32
typedef __int64		int64;
#else
typedef long long	int64;
#endif

// Forward declarations
class CDetour;
class IClient;
class SpeakingEndTimer;

// Global variable declarations
extern ConVar *g_SvLogging;
extern ConVar *g_SmVoiceAddr;
extern ConVar *g_SmVoicePort;
extern ITimer *g_pTimerSpeaking[SM_MAXPLAYERS + 1];

// Global functions
extern double getTime();
extern SpeakingEndTimer s_SpeakingEndTimer;

/**
* @brief Voice extension implementation
*/
class CVoice :
  public SDKExtension,
  public IConCommandBaseAccessor
{
public:
  // SDKExtension overrides
  virtual bool SDK_OnLoad(char *error, size_t maxlength, bool late);
  virtual void SDK_OnUnload();
  virtual void SDK_OnAllLoaded();
  
#if defined SMEXT_CONF_METAMOD
  virtual bool SDK_OnMetamodLoad(ISmmAPI *ismm, char *error, size_t maxlength, bool late);
#endif

  // IConCommandBaseAccessor
  virtual bool RegisterConCommandBase(ConCommandBase *pVar);

public:
  // Constructor
  CVoice();
  
  // Public methods
  void OnGameFrame(bool simulating);
  bool OnBroadcastVoiceData(IClient *pClient, int nBytes, char *data);
  void ListenSocket();
  void RestartListener();
  bool IsRunning();

private:
  // Socket handling
  int m_ListenSocket;
  
  // Client structure
  struct CClient
  {
    int m_Socket;
    size_t m_BufferWriteIndex;
    size_t m_LastLength;
    double m_LastValidData;
    bool m_New;
    bool m_UnEven;
    unsigned char m_Remainder;
  } m_aClients[MAX_CLIENTS];

  // Poll handling
  struct pollfd m_aPollFds[1 + MAX_CLIENTS];
  int m_PollFds;

  // Audio buffer
  CRingBuffer m_Buffer;

  // Timing
  double m_AvailableTime;

  // Opus encoder
  OpusEncoder *m_OpusEncoder;

  // Detour
  CDetour *m_VoiceDetour;

  // Private methods
  void HandleNetwork();
  void OnDataReceived(CClient *pClient, int16_t *pData, size_t Samples);
  void HandleVoiceData();
  void BroadcastVoiceData(IClient *pClient, int nBytes, unsigned char *pData);
};

#endif // _INCLUDE_SOURCEMOD_EXTENSION_PROPER_H_