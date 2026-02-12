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
//#define _GNU_SOURCE
#include <stdlib.h>
#include <string.h>
#include <sys/types.h>
#include <sys/socket.h>
#include <sys/ioctl.h>
#include <netinet/in.h>
#include <arpa/inet.h>
#include <fcntl.h>
#include <poll.h>
#include <opus.h>

#include <iclient.h>
#include <iserver.h>
#include <ISDKTools.h>

#include "CDetour/detours.h"
#include "extension.h"

// voice packets are sent over unreliable netchannel
//#define NET_MAX_DATAGRAM_PAYLOAD	4000	// = maximum unreliable payload size
// voice packetsize = 64 | netchannel overflows at >4000 bytes
// with 22050 samplerate and 512 frames per packet -> 23.22ms per packet
// SVC_VoiceData overhead = 5 bytes
// sensible limit of 8 packets per frame = 552 bytes -> 185.76ms of voice data per frame
#define NET_MAX_VOICE_BYTES_FRAME (10 * (5 + 64))

ConVar g_SmVoiceAddr("sm_voice_addr", "127.0.0.1", FCVAR_PROTECTED, "Voice server listen ip address.");
ConVar g_SmVoicePort("sm_voice_port", "27020", FCVAR_PROTECTED, "Voice server listen port.", true, 1025.0, true, 65535.0);

/**
 * @file extension.cpp
 * @brief Implement extension code here.
 */

template <typename T> inline T min_ext(T a, T b) { return a<b?a:b; }

const unsigned int CRCTable[256] = {
  0x00000000, 0x77073096, 0xee0e612c, 0x990951ba, 0x076dc419, 0x706af48f,
  0xe963a535, 0x9e6495a3, 0x0edb8832, 0x79dcb8a4, 0xe0d5e91e, 0x97d2d988,
  0x09b64c2b, 0x7eb17cbd, 0xe7b82d07, 0x90bf1d91, 0x1db71064, 0x6ab020f2,
  0xf3b97148, 0x84be41de, 0x1adad47d, 0x6ddde4eb, 0xf4d4b551, 0x83d385c7,
  0x136c9856, 0x646ba8c0, 0xfd62f97a, 0x8a65c9ec, 0x14015c4f, 0x63066cd9,
  0xfa0f3d63, 0x8d080df5, 0x3b6e20c8, 0x4c69105e, 0xd56041e4, 0xa2677172,
  0x3c03e4d1, 0x4b04d447, 0xd20d85fd, 0xa50ab56b, 0x35b5a8fa, 0x42b2986c,
  0xdbbbc9d6, 0xb8bda940, 0x32d86ce3, 0x45df5c75, 0xdcd60dcf, 0xabd13d59,
  0x26d930ac, 0x51de003a, 0xc8d75180, 0xbfd06116, 0x21b4f4b5, 0x56b3c423,
  0xcfba9599, 0xb8bda50f, 0x2802b89e, 0x5f058808, 0xc60cd9b2, 0xb10be924,
  0x2f6f7c87, 0x58684c11, 0xc1611dab, 0xb6662d3d, 0x76dc4190, 0x01db7106,
  0x98d220bc, 0xefd5102a, 0x71b18589, 0x06b6b51f, 0x9fbfe4a5, 0xe8b8d433,
  0x7807c9a2, 0x0f00f934, 0x9609a88e, 0xe10e9818, 0x7f6a0dbb, 0x086d3d2d,
  0x91646c97, 0xe6635c01, 0x6b6b51f4, 0x1c6c6162, 0x856530d8, 0xf262004e,
  0x6c0695ed, 0x1b01a57b, 0x8208f4c1, 0xf50fc457, 0x65b0d9c6, 0x12b7e950,
  0x8bbeb8ea, 0xfcb9887c, 0x62dd1ddf, 0x15da2d49, 0x8cd37cf3, 0xfbd44c65,
  0x4db26158, 0x3ab551ce, 0xa3bc0074, 0xd4bb30e2, 0x4adfa541, 0x3dd895d7,
  0xa4d1c46d, 0xd3d6f4fb, 0x4369e96a, 0x346ed9fc, 0xad678846, 0xda60b8d0,
  0x44042d73, 0x33031de5, 0xaa0a4c5f, 0xdd0d7cc9, 0x5005713c, 0x270241aa,
  0xbe0b1010, 0xc90c2086, 0x5768b525, 0x206f85b3, 0xb966d409, 0xce61e49f,
  0x5edef90e, 0x29d9c998, 0xb0d09822, 0xc7d7a8b4, 0x59b33d17, 0x2eb40d81,
  0xb7bd5c3b, 0xc0ba6cad, 0xedb88320, 0x9abfb3b6, 0x03b6e20c, 0x74b1d29a,
  0xead54739, 0x9dd277af, 0x04db2615, 0x73dc1683, 0xe3630b12, 0x94643b84,
  0x0d6d6a3e, 0x7a6a5aa8, 0xe40ecf0b, 0x9309ff9d, 0x0a00ae27, 0x7d079eb1,
  0xf00f9344, 0x8708a3d2, 0x1e01f268, 0x6906c2fe, 0xf762575d, 0x806567cb,
  0x196c3671, 0x6e6b06e7, 0xfed41b76, 0x89d32be0, 0x10da7a5a, 0x67dd4acc,
  0xf9b9df6f, 0x8ebeeff9, 0x17b7be43, 0x60b08ed5, 0xd6d6a3e8, 0xa1d1937e,
  0x38d8c2c4, 0x4fdff252, 0xd1bb67f1, 0xa6bc5767, 0x3fb506dd, 0x48b2364b,
  0xd80d2bda, 0xaf0a1b4c, 0x36034af6, 0x41047a60, 0xdf60efc3, 0xa867df55,
  0x316e8eef, 0x4669be79, 0xcb61b38c, 0xbc66831a, 0x256fd2a0, 0x5268e236,
  0xcc0c7795, 0xbb0b4703, 0x220216b9, 0x5505262f, 0xc5ba3bbe, 0xb2bd0b28,
  0x2bb45a92, 0x5cb36a04, 0xc2d7ffa7, 0xb5d0cf31, 0x2cd99e8b, 0x5bdeae1d,
  0x9b64c2b0, 0xec63f226, 0x756aa39c, 0x026d930a, 0x9c0906a9, 0xeb0e363f,
  0x72076785, 0x05005713, 0x95bf4a82, 0xe2b87a14, 0x7bb12bae, 0x0cb61b38,
  0x92d28e9b, 0xe5d5be0d, 0x7cdcefb7, 0x0bdbdf21, 0x86d3d2d4, 0xf1d4e242,
  0x68ddb3f8, 0x1fda836e, 0x81be16cd, 0xf6b9265b, 0x6fb077e1, 0x18b74777,
  0x88085ae6, 0xff0f6a70, 0x66063bca, 0x11010b5c, 0x8f659eff, 0xf862ae69,
  0x616bffd3, 0x166ccf45, 0xa00ae278, 0xd70dd2ee, 0x4e048354, 0x3903b3c2,
  0xa7672661, 0xd06016f7, 0x4969474d, 0x3e6e77db, 0xaed16a4a, 0xd9d65adc,
  0x40df0b66, 0x37d83bf0, 0xa9bcae53, 0xdebb9ec5, 0x47b2cf7f, 0x30b5ffe9,
  0xbdbdf21c, 0xcabac28a, 0x53b39330, 0x24b4a3a6, 0xbad03605, 0xcdd70693,
  0x54de5729, 0x23d967bf, 0xb3667a2e, 0xc4614ab8, 0x5d681b02, 0x2a6f2b94,
  0xb40bbe37, 0xc30c8ea1, 0x5a05df1b, 0x2d02ef8d};


unsigned int UTIL_CRC32(const void *pdata, size_t data_length)
{
    unsigned char *data = (unsigned char *)pdata;
    unsigned int crc = 0xFFFFFFFF;
    unsigned char c;

    for(size_t i = 0; i < data_length; i++, data++)
    {
        c = (unsigned char)((crc ^ *data) & 0xFF);
        crc = CRCTable[c] ^ (crc >> 8);
    }

    return ~crc;
}

CVoice g_Interface;
SMEXT_LINK(&g_Interface);

CGlobalVars *gpGlobals = NULL;
ISDKTools *g_pSDKTools = NULL;
IServer *iserver = NULL;

double g_fLastVoiceData[SM_MAXPLAYERS + 1];
int g_aFrameVoiceBytes[SM_MAXPLAYERS + 1];

DETOUR_DECL_STATIC4(SV_BroadcastVoiceData, void, IClient *, pClient, int, nBytes, char *, data, int64, xuid)
{
	if(g_Interface.OnBroadcastVoiceData(pClient, nBytes, data))
		DETOUR_STATIC_CALL(SV_BroadcastVoiceData)(pClient, nBytes, data, xuid);
}

#ifdef _WIN32
DETOUR_DECL_STATIC2(SV_BroadcastVoiceData_LTCG, void, char *, data, int64, xuid)
{
	IClient *pClient = NULL;
	int nBytes = 0;

	__asm mov pClient, ecx;
	__asm mov nBytes, edx;

	bool ret = g_Interface.OnBroadcastVoiceData(pClient, nBytes, data);

	__asm mov ecx, pClient;
	__asm mov edx, nBytes;

	if(ret)
		DETOUR_STATIC_CALL(SV_BroadcastVoiceData_LTCG)(data, xuid);
}
#endif

double getTime()
{
    struct timespec tv;
    if(clock_gettime(CLOCK_REALTIME, &tv) != 0)
    	return 0;

    return (tv.tv_sec + (tv.tv_nsec / 1000000000.0));
}

void OnGameFrame(bool simulating)
{
	g_Interface.OnGameFrame(simulating);
}

CVoice::CVoice()
{
	m_ListenSocket = -1;

	m_PollFds = 0;
	for(int i = 1; i < 1 + MAX_CLIENTS; i++)
		m_aPollFds[i].fd = -1;

	for(int i = 0; i < MAX_CLIENTS; i++)
		m_aClients[i].m_Socket = -1;

    m_OpusEncoder = NULL;
    m_AvailableTime = 0.0;

	m_VoiceDetour = NULL;
	m_SV_BroadcastVoiceData = NULL;
}

bool CVoice::SDK_OnLoad(char *error, size_t maxlength, bool late)
{
	// Setup engine-specific data.
	Dl_info info;
	void *engineFactory = (void *)g_SMAPI->GetEngineFactory(false);
	if(dladdr(engineFactory, &info) == 0)
	{
		g_SMAPI->Format(error, maxlength, "dladdr(engineFactory) failed.");
		return false;
	}

	void *pEngineSo = dlopen(info.dli_fname, RTLD_NOW);
	if(pEngineSo == NULL)
	{
		g_SMAPI->Format(error, maxlength, "dlopen(%s) failed.", info.dli_fname);
		return false;
	}

	int engineVersion = g_SMAPI->GetSourceEngineBuild();
	void *adrVoiceData = NULL;

	switch (engineVersion)
	{
		case SOURCE_ENGINE_CSGO:
#ifdef _WIN32
			adrVoiceData = memutils->FindPattern(pEngineSo, "\x55\x8B\xEC\x81\xEC\xD0\x00\x00\x00\x53\x56\x57", 12);
#else
			adrVoiceData = memutils->ResolveSymbol(pEngineSo, "_Z21SV_BroadcastVoiceDataP7IClientiPcx");
#endif
			break;

		case SOURCE_ENGINE_LEFT4DEAD2:
#ifdef _WIN32
			adrVoiceData = memutils->FindPattern(pEngineSo, "\x55\x8B\xEC\x83\xEC\x70\xA1\x2A\x2A\x2A\x2A\x33\xC5\x89\x45\xFC\xA1\x2A\x2A\x2A\x2A\x53\x56", 23);
#else
			adrVoiceData = memutils->ResolveSymbol(pEngineSo, "_Z21SV_BroadcastVoiceDataP7IClientiPcx");
#endif
			break;

		case SOURCE_ENGINE_NUCLEARDAWN:
#ifdef _WIN32
			adrVoiceData = memutils->FindPattern(pEngineSo, "\x55\x8B\xEC\xA1\x2A\x2A\x2A\x2A\x83\xEC\x58\x57\x33\xFF", 14);
#else
			adrVoiceData = memutils->ResolveSymbol(pEngineSo, "_Z21SV_BroadcastVoiceDataP7IClientiPcx");
#endif
			break;

		case SOURCE_ENGINE_INSURGENCY:
#ifdef _WIN32
			adrVoiceData = memutils->FindPattern(pEngineSo, "\x55\x8B\xEC\x83\xEC\x74\x68\x2A\x2A\x2A\x2A\x8D\x4D\xE4\xE8", 15);
#else
			adrVoiceData = memutils->ResolveSymbol(pEngineSo, "_Z21SV_BroadcastVoiceDataP7IClientiPcx");
#endif
			break;

		case SOURCE_ENGINE_TF2:
		case SOURCE_ENGINE_CSS:
		case SOURCE_ENGINE_HL2DM:
		case SOURCE_ENGINE_DODS:
		case SOURCE_ENGINE_SDK2013:
#ifdef _WIN32
			adrVoiceData = memutils->FindPattern(pEngineSo, "\x55\x8B\xEC\xA1\x2A\x2A\x2A\x2A\x83\xEC\x50\x83\x78\x30", 14);
#else
			adrVoiceData = memutils->ResolveSymbol(pEngineSo, "_Z21SV_BroadcastVoiceDataP7IClientiPcx");
#endif
			break;

		default:
			g_SMAPI->Format(error, maxlength, "Unsupported game.");
			dlclose(pEngineSo);
			return false;
	}
	dlclose(pEngineSo);

	m_SV_BroadcastVoiceData = (t_SV_BroadcastVoiceData)adrVoiceData;
	if(!m_SV_BroadcastVoiceData)
	{
		g_SMAPI->Format(error, maxlength, "SV_BroadcastVoiceData sigscan failed.");
		return false;
	}

	// Setup voice detour.
	CDetourManager::Init(g_pSM->GetScriptingEngine(), NULL);

#ifdef _WIN32
	if (engineVersion == SOURCE_ENGINE_CSGO || engineVersion == SOURCE_ENGINE_INSURGENCY)
	{
		m_VoiceDetour = DETOUR_CREATE_STATIC(SV_BroadcastVoiceData_LTCG, adrVoiceData);
	}
	else
	{
		m_VoiceDetour = DETOUR_CREATE_STATIC(SV_BroadcastVoiceData, adrVoiceData);
	}
#else
	m_VoiceDetour = DETOUR_CREATE_STATIC(SV_BroadcastVoiceData, adrVoiceData);
#endif

	if (!m_VoiceDetour)
	{
		g_SMAPI->Format(error, maxlength, "SV_BroadcastVoiceData detour failed.");
		return false;
	}

	m_VoiceDetour->EnableDetour();

    //opus edit
    int err;
    //m_OpusEncoder = opus_encoder_create(24000, 2, OPUS_APPLICATION_AUDIO, &err);
    m_OpusEncoder = opus_encoder_create(48000, 2, OPUS_APPLICATION_AUDIO, &err);
    if (err<0)
    {
        smutils->LogError(myself, "failed to create encode: %s", opus_strerror(err));
        return false;
    }

    opus_encoder_ctl(m_OpusEncoder, OPUS_SET_BITRATE(128000)); 
    opus_encoder_ctl(m_OpusEncoder, OPUS_SET_BANDWIDTH(OPUS_BANDWIDTH_FULLBAND));
    opus_encoder_ctl(m_OpusEncoder, OPUS_SET_SIGNAL(OPUS_SIGNAL_MUSIC)); //MDCT mode
    opus_encoder_ctl(m_OpusEncoder, OPUS_SET_LSB_DEPTH(16)); 
    opus_encoder_ctl(m_OpusEncoder, OPUS_SET_PACKET_LOSS_PERC(0));
    opus_encoder_ctl(m_OpusEncoder, OPUS_SET_FORCE_CHANNELS(2));

    if (err<0)
    {
        smutils->LogError(myself, "failed to set bitrate: %s\n", opus_strerror(err));
        return false;
    }

	return true;
}

bool CVoice::SDK_OnMetamodLoad(ISmmAPI *ismm, char *error, size_t maxlen, bool late)
{
	GET_V_IFACE_CURRENT(GetEngineFactory, g_pCVar, ICvar, CVAR_INTERFACE_VERSION);
	gpGlobals = ismm->GetCGlobals();
	ConVar_Register(0, this);

	return true;
}

bool CVoice::RegisterConCommandBase(ConCommandBase *pVar)
{
	/* Always call META_REGCVAR instead of going through the engine. */
	return META_REGCVAR(pVar);
}

cell_t IsClientTalking(IPluginContext *pContext, const cell_t *params)
{
	int client = params[1];

	if(client < 1 || client > SM_MAXPLAYERS)
	{
		return pContext->ThrowNativeError("Client index %d is invalid", client);
	}

	double d = gpGlobals->curtime - g_fLastVoiceData[client];

	if(d < 0) // mapchange
		return false;

	if(d > 0.33)
		return false;

	return true;
}

const sp_nativeinfo_t MyNatives[] =
{
	{ "IsClientTalking", IsClientTalking },
	{ NULL, NULL }
};

static void ListenSocketAction(void *pData)
{
	CVoice *pThis = (CVoice *)pData;
	pThis->ListenSocket();
}

void CVoice::SDK_OnAllLoaded()
{
	sharesys->AddNatives(myself, MyNatives);
	sharesys->RegisterLibrary(myself, "Voice");

	SM_GET_LATE_IFACE(SDKTOOLS, g_pSDKTools);
	if(g_pSDKTools == NULL)
	{
		smutils->LogError(myself, "SDKTools interface not found");
		SDK_OnUnload();
		return;
	}

	iserver = g_pSDKTools->GetIServer();
	if(iserver == NULL)
	{
		smutils->LogError(myself, "Failed to get IServer interface from SDKTools!");
		SDK_OnUnload();
		return;
	}

	// Init tcp server
	m_ListenSocket = socket(AF_INET, SOCK_STREAM, 0);
	if(m_ListenSocket < 0)
	{
		smutils->LogError(myself, "Failed creating socket.");
		SDK_OnUnload();
		return;
	}

	int yes = 1;
	if(setsockopt(m_ListenSocket, SOL_SOCKET, SO_REUSEADDR, &yes, sizeof(int)) < 0)
	{
		smutils->LogError(myself, "Failed setting SO_REUSEADDR on socket.");
		SDK_OnUnload();
		return;
	}

	// This doesn't seem to work right away ...
	engine->ServerCommand("exec sourcemod/extension.Voice.cfg\n");
	engine->ServerExecute();

	// ... delay starting listen server to next frame
	smutils->AddFrameAction(ListenSocketAction, this);
}

void CVoice::ListenSocket()
{
	if(m_PollFds > 0)
		return;

	sockaddr_in bindAddr;
	memset(&bindAddr, 0, sizeof(bindAddr));
	bindAddr.sin_family = AF_INET;
	inet_aton(g_SmVoiceAddr.GetString(), &bindAddr.sin_addr);
	bindAddr.sin_port = htons(g_SmVoicePort.GetInt());

	smutils->LogMessage(myself, "Binding to %s:%d!\n", g_SmVoiceAddr.GetString(), g_SmVoicePort.GetInt());

	if(bind(m_ListenSocket, (sockaddr *)&bindAddr, sizeof(sockaddr_in)) < 0)
	{
		smutils->LogError(myself, "Failed binding to socket (%d '%s').", errno, strerror(errno));
		SDK_OnUnload();
		return;
	}

	if(listen(m_ListenSocket, MAX_CLIENTS) < 0)
	{
		smutils->LogError(myself, "Failed listening on socket.");
		SDK_OnUnload();
		return;
	}

	m_aPollFds[0].fd = m_ListenSocket;
	m_aPollFds[0].events = POLLIN;
	m_PollFds++;

	smutils->AddGameFrameHook(::OnGameFrame);
}

void CVoice::SDK_OnUnload()
{
	smutils->RemoveGameFrameHook(::OnGameFrame);

	if(m_VoiceDetour)
	{
		m_VoiceDetour->Destroy();
		m_VoiceDetour = NULL;
	}

	if(m_ListenSocket != -1)
	{
		close(m_ListenSocket);
		m_ListenSocket = -1;
	}

	for(int Client = 0; Client < MAX_CLIENTS; Client++)
	{
		if(m_aClients[Client].m_Socket != -1)
		{
			close(m_aClients[Client].m_Socket);
			m_aClients[Client].m_Socket = -1;
		}
	}

    opus_encoder_destroy(m_OpusEncoder);
}

void CVoice::OnGameFrame(bool simulating)
{
	HandleNetwork();
	HandleVoiceData();

	// Reset per-client voice byte counter to 0 every frame.
	memset(g_aFrameVoiceBytes, 0, sizeof(g_aFrameVoiceBytes));
}

bool CVoice::OnBroadcastVoiceData(IClient *pClient, int nBytes, char *data)
{
	// Reject empty packets
	if(nBytes < 1)
		return false;

	int client = pClient->GetPlayerSlot() + 1;

	// Reject voice packet if we'd send more than NET_MAX_VOICE_BYTES_FRAME voice bytes from this client in the current frame.
	// 5 = SVC_VoiceData header/overhead
	g_aFrameVoiceBytes[client] += 5 + nBytes;

	if(g_aFrameVoiceBytes[client] > NET_MAX_VOICE_BYTES_FRAME)
		return false;

	g_fLastVoiceData[client] = gpGlobals->curtime;

	return true;
}

void CVoice::HandleNetwork()
{
	if(m_ListenSocket == -1)
		return;

	int PollRes = poll(m_aPollFds, m_PollFds, 0);
	if(PollRes <= 0)
		return;

	// Accept new clients
	if(m_aPollFds[0].revents & POLLIN)
	{
		// Find slot
		int Client;
		for(Client = 0; Client < MAX_CLIENTS; Client++)
		{
			if(m_aClients[Client].m_Socket == -1)
				break;
		}

		// no free slot
		if(Client != MAX_CLIENTS)
		{
			sockaddr_in addr;
			socklen_t size = sizeof(sockaddr_in);
			int Socket = accept(m_ListenSocket, (sockaddr *)&addr, &size);

			m_aClients[Client].m_Socket = Socket;
			m_aClients[Client].m_BufferWriteIndex = 0;
			m_aClients[Client].m_LastLength = 0;
			m_aClients[Client].m_LastValidData = 0.0;
			m_aClients[Client].m_New = true;
			m_aClients[Client].m_UnEven = false;

			m_aPollFds[m_PollFds].fd = Socket;
			m_aPollFds[m_PollFds].events = POLLIN | POLLHUP;
			m_aPollFds[m_PollFds].revents = 0;
			m_PollFds++;

			//smutils->LogMessage(myself, "Client %d connected!\n", Client);
		}
	}

	bool CompressPollFds = false;
	for(int PollFds = 1; PollFds < m_PollFds; PollFds++)
	{
		int Client = -1;
		for(Client = 0; Client < MAX_CLIENTS; Client++)
		{
			if(m_aClients[Client].m_Socket == m_aPollFds[PollFds].fd)
				break;
		}
		if(Client == -1)
			continue;

		CClient *pClient = &m_aClients[Client];

		// Connection shutdown prematurely ^C
		// Make sure to set SO_LINGER l_onoff = 1, l_linger = 0
		if(m_aPollFds[PollFds].revents & POLLHUP)
		{
			close(pClient->m_Socket);
			pClient->m_Socket = -1;
			m_aPollFds[PollFds].fd = -1;
			CompressPollFds = true;
			//smutils->LogMessage(myself, "Client %d disconnected!(2)\n", Client);
			continue;
		}

		// Data available?
		if(!(m_aPollFds[PollFds].revents & POLLIN))
			continue;

		size_t BytesAvailable;
		if(ioctl(pClient->m_Socket, FIONREAD, &BytesAvailable) == -1)
			continue;

		if(pClient->m_New)
		{
			pClient->m_BufferWriteIndex = m_Buffer.GetReadIndex();
			pClient->m_New = false;
		}

		m_Buffer.SetWriteIndex(pClient->m_BufferWriteIndex);

		// Don't recv() when we can't fit data into the ringbuffer
		unsigned char aBuf[32768];
		if(min_ext(BytesAvailable, sizeof(aBuf)) > m_Buffer.CurrentFree() * sizeof(int16_t))
			continue;

		// Edge case: previously received data is uneven and last recv'd byte has to be prepended
		int Shift = 0;
		if(pClient->m_UnEven)
		{
			Shift = 1;
			aBuf[0] = pClient->m_Remainder;
			pClient->m_UnEven = false;
		}

		ssize_t Bytes = recv(pClient->m_Socket, &aBuf[Shift], sizeof(aBuf) - Shift, 0);

		if(Bytes <= 0)
		{
			close(pClient->m_Socket);
			pClient->m_Socket = -1;
			m_aPollFds[PollFds].fd = -1;
			CompressPollFds = true;
			//smutils->LogMessage(myself, "Client %d disconnected!(1)\n", Client);
			continue;
		}

		Bytes += Shift;

		// Edge case: data received is uneven (can't be divided by two)
		// store last byte, drop it here and prepend it right before the next recv
		if(Bytes & 1)
		{
			pClient->m_UnEven = true;
			pClient->m_Remainder = aBuf[Bytes - 1];
			Bytes -= 1;
		}

		// Got data!
		OnDataReceived(pClient, (int16_t *)aBuf, Bytes / sizeof(int16_t));

		pClient->m_LastLength = m_Buffer.CurrentLength();
		pClient->m_BufferWriteIndex = m_Buffer.GetWriteIndex();
	}

	if(CompressPollFds)
	{
		for(int PollFds = 1; PollFds < m_PollFds; PollFds++)
		{
			if(m_aPollFds[PollFds].fd != -1)
				continue;

			for(int PollFds_ = PollFds; PollFds_ < 1 + MAX_CLIENTS; PollFds_++)
				m_aPollFds[PollFds_].fd = m_aPollFds[PollFds_ + 1].fd;

			PollFds--;
			m_PollFds--;
		}
	}
}

void CVoice::OnDataReceived(CClient *pClient, int16_t *pData, size_t Samples)
{
	// Check for empty input
	ssize_t DataStartsAt = -1;
	for(size_t i = 0; i < Samples; i++)
	{
		if(pData[i] == 0)
			continue;

		DataStartsAt = i;
		break;
	}

	// Discard empty data if last vaild data was more than a second ago.
	if(pClient->m_LastValidData + 1.0 < getTime())
	{
		// All empty
		if(DataStartsAt == -1)
			return;

		// Data starts here
		pData += DataStartsAt;
		Samples -= DataStartsAt;
	}

	if(!m_Buffer.Push(pData, Samples))
	{
		smutils->LogError(myself, "Buffer push failed!!! Samples: %u, Free: %u\n", Samples, m_Buffer.CurrentFree());
		return;
	}

	pClient->m_LastValidData = getTime();
}

struct SteamVoiceHeader
{
	uint32_t iSteamAccountID : 32;
	uint32_t iSteamCommunity : 32;
	uint32_t nPayload1 : 8;
	uint32_t iSampleRate : 16;
	uint32_t nPayload2 : 8;
	uint32_t iDataLength : 16;
};

void CVoice::HandleVoiceData()
{
    uint32_t sampleRate = 48000;
    const int SamplesPerChannel = 480;
    const int Channels = 2;
    int TotalSamplesPerFrame = SamplesPerChannel * Channels;

    int FramesAvailable = m_Buffer.TotalLength() / TotalSamplesPerFrame;
    if(!FramesAvailable)
        return;

    int FramesMax = 2; //used to be 5
    bool reset_state = false;
    if (FramesAvailable <= FramesMax)
    {
        reset_state = true;
    }
    FramesAvailable = min_ext(FramesAvailable, FramesMax);

    // Allow less buffering after audio has started playing
    if (m_Buffer.TotalLength() < TotalSamplesPerFrame)
        return;

    float TimeAvailable = (float)m_Buffer.TotalLength() / sampleRate;
    if (m_AvailableTime < getTime() && TimeAvailable < 0.2)
        return;

    double maxBuffer = (m_AvailableTime < getTime()) ? 0.2 : 0.04;
    if (m_AvailableTime > getTime() + maxBuffer)
        return;
    

    IClient *pClient = iserver->GetClient(0);
    if(!pClient)
        return;

    unsigned char aFinal[8192];
    size_t FinalSize = 0;

    // 1. Steam Account ID (4 bytes)
    uint32_t steamID = 1;
    memcpy(&aFinal[FinalSize], &steamID, sizeof(uint32_t));
    FinalSize += sizeof(uint32_t);

    // 2. Steam Community (4 bytes)
    uint32_t steamCommunity = 0x01100001;
    memcpy(&aFinal[FinalSize], &steamCommunity, sizeof(uint32_t));
    FinalSize += sizeof(uint32_t);

    // 3. Payload Type 11 (1 byte)
    aFinal[FinalSize++] = 0x0B;

    // 4. Sample Rate (2 bytes little-endian)
    memcpy(&aFinal[FinalSize], &sampleRate, sizeof(uint16_t));
    FinalSize += sizeof(uint16_t);

    // 5. Payload Type 5 for Opus. 6 for opus plc (1 byte)
    aFinal[FinalSize++] = 0x05;

    // 6. Reserve space for total data length (2 bytes little-endian)
    uint16_t *pTotalDataLength = (uint16_t*)&aFinal[FinalSize];
    FinalSize += sizeof(uint16_t);
    *pTotalDataLength = 0;

    // 7. Encode frames
    for(int Frame = 0; Frame < FramesAvailable; Frame++)
    {
        int16_t aBuffer[TotalSamplesPerFrame];

        size_t OldReadIdx = m_Buffer.m_ReadIndex;
		size_t OldCurLength = m_Buffer.CurrentLength();
		size_t OldTotalLength = m_Buffer.TotalLength();

        if(!m_Buffer.Pop(aBuffer, TotalSamplesPerFrame))
        {
            smutils->LogError(myself, "Buffer pop failed!");
            return;
        }

        uint16_t *pFrameSize = (uint16_t*)&aFinal[FinalSize];
        FinalSize += sizeof(uint16_t);
        *pFrameSize = sizeof(aFinal) - sizeof(uint32_t) - FinalSize;

        // Encode with Opus
        //pcm <tt>opus_int16*</tt>: Input signal (interleaved if 2 channels). length is frame_size*channels*sizeof(opus_int16)
        int nbBytes = opus_encode(m_OpusEncoder, (const opus_int16*)aBuffer, SamplesPerChannel,
                                  &aFinal[FinalSize], *pFrameSize);
        if (nbBytes <= 1)
        {
            smutils->LogError(myself, "Opus encode failed: %s", opus_strerror(nbBytes));
            return;
        }

        // Write frame size
        *pFrameSize = (uint16_t)nbBytes;
        *pTotalDataLength += sizeof(uint16_t) + nbBytes;
        FinalSize += nbBytes;

        // Check for buffer underruns
        for(int Client = 0; Client < MAX_CLIENTS; Client++)
        {
            CClient *pClient = &m_aClients[Client];
            if(pClient->m_Socket == -1 || pClient->m_New == true)
                continue;

            m_Buffer.SetWriteIndex(pClient->m_BufferWriteIndex);

            if(m_Buffer.CurrentLength() > pClient->m_LastLength)
            {
                pClient->m_BufferWriteIndex = m_Buffer.GetReadIndex();
                m_Buffer.SetWriteIndex(pClient->m_BufferWriteIndex);
                pClient->m_LastLength = m_Buffer.CurrentLength();
            }
        }
    }

    // 8. Add CRC32
    uint32_t crc32_value = UTIL_CRC32(aFinal, FinalSize);
    memcpy(&aFinal[FinalSize], &crc32_value, sizeof(uint32_t));
    FinalSize += sizeof(uint32_t);
    
    BroadcastVoiceData(pClient, FinalSize, aFinal);

    if (m_AvailableTime < getTime())
        m_AvailableTime = getTime();
    m_AvailableTime += (double)FramesAvailable * 0.01;
    
    if (reset_state)
    {
        opus_encoder_ctl(m_OpusEncoder, OPUS_RESET_STATE);
    }
}

void CVoice::BroadcastVoiceData(IClient *pClient, int nBytes, unsigned char *pData)
{
	#ifdef _WIN32
	__asm mov ecx, pClient;
	__asm mov edx, nBytes;

	DETOUR_STATIC_CALL(SV_BroadcastVoiceData_LTCG)((char *)pData, 0);
	#else
	DETOUR_STATIC_CALL(SV_BroadcastVoiceData)(pClient, nBytes, (char *)pData, 0);
	#endif
}
