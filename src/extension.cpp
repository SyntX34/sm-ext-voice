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

#ifdef _WIN32
  #include <winsock2.h>
  #include <ws2tcpip.h>
  typedef SOCKET socket_t;
#else
  typedef int socket_t;
#endif

#include <iclient.h>
#include <iserver.h>
#include <ISDKTools.h>

#include <ITimerSystem.h>

#include <ihltvdirector.h>
#include <ihltv.h>

#include "CDetour/detours.h"
#include "extension.h"
#include "convarhelper.h"

// voice packets are sent over unreliable netchannel
#define NET_MAX_VOICE_BYTES_FRAME (10 * (5 + 64))

ConVar g_SmVoiceAddr("sm_voice_addr", "127.0.0.1", FCVAR_PROTECTED, "Voice server listen ip address.");
ConVar g_SmVoicePort("sm_voice_port", "27020", FCVAR_PROTECTED, "Voice server listen port.", true, 1025.0, true, 65535.0);

/**
 * @file extension.cpp
 * @brief Implement extension code here.
 */

#ifdef _WIN32
#include <basetsd.h>
typedef SSIZE_T ssize_t;
#endif

template <typename T> inline T min_ext(T a, T b) { return a<b?a:b; }

CVoice g_Interface;
SMEXT_LINK(&g_Interface);



CGlobalVars *gpGlobals = NULL;
ISDKTools *g_pSDKTools = NULL;
IServer *iserver = NULL;

IHLTVDirector *hltvdirector = NULL;
IHLTVServer *hltv = NULL;

size_t g_aFrameVoiceBytes[SM_MAXPLAYERS + 1];
double g_fLastVoiceData[SM_MAXPLAYERS + 1];

IGameConfig *g_pGameConf = NULL;

std::string string_to_hex(const std::string& input)
{
    static const char hex_digits[] = "0123456789ABCDEF";

    std::string output;
    output.reserve(input.length() * 2);
    for (unsigned char c : input)
    {
        output.push_back(hex_digits[c >> 4]);
        output.push_back(hex_digits[c & 15]);
    }
    return output;
}

int hex_value(unsigned char hex_digit)
{
    static const signed char hex_values[256] = {
        -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1,
        -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1,
        -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1,
         0,  1,  2,  3,  4,  5,  6,  7,  8,  9, -1, -1, -1, -1, -1, -1,
        -1, 10, 11, 12, 13, 14, 15, -1, -1, -1, -1, -1, -1, -1, -1, -1,
        -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1,
        -1, 10, 11, 12, 13, 14, 15, -1, -1, -1, -1, -1, -1, -1, -1, -1,
        -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1,
        -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1,
        -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1,
        -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1,
        -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1,
        -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1,
        -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1,
        -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1,
        -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1,
    };
    int value = hex_values[hex_digit];
    if (value == -1) throw std::invalid_argument("invalid hex digit");
    return value;
}

std::string hex_to_string(const std::string& input)
{
    const auto len = input.length();
    if (len & 1) throw std::invalid_argument("odd length");

    std::string output;
    output.reserve(len / 2);
    for (auto it = input.begin(); it != input.end(); )
    {
        int hi = hex_value(*it++);
        int lo = hex_value(*it++);
        output.push_back(hi << 4 | lo);
    }
    return output;
}

const unsigned int CRCTable[256] = {
  0x00000000, 0x77073096, 0xee0e612c, 0x990951ba, 0x076dc419, 0x706af48f,
  0xe963a535, 0x9e6495a3, 0x0edb8832, 0x79dcb8a4, 0xe0d5e91e, 0x97d2d988,
  0x09b64c2b, 0x7eb17cbd, 0xe7b82d07, 0x90bf1d91, 0x1db71064, 0x6ab020f2,
  0xf3b97148, 0x84be41de, 0x1adad47d, 0x6ddde4eb, 0xf4d4b551, 0x83d385c7,
  0x136c9856, 0x646ba8c0, 0xfd62f97a, 0x8a65c9ec, 0x14015c4f, 0x63066cd9,
  0xfa0f3d63, 0x8d080df5, 0x3b6e20c8, 0x4c69105e, 0xd56041e4, 0xa2677172,
  0x3c03e4d1, 0x4b04d447, 0xd20d85fd, 0xa50ab56b, 0x35b5a8fa, 0x42b2986c,
  0xdbbbc9d6, 0xacbcf940, 0x32d86ce3, 0x45df5c75, 0xdcd60dcf, 0xabd13d59,
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

#if SOURCE_ENGINE == SE_CSGO || SOURCE_ENGINE == SE_INSURGENCY
void PrintCCLCMsg_VoiceData(const char *funcName, int client, const CCLCMsg_VoiceData &msg, bool drop)
{
    if (!g_SvLogging->GetInt()) return;
    
    g_pSM->LogMessage(myself, "===START=======%s=============", funcName);
    g_pSM->LogMessage(myself, "client %d", client);
    g_pSM->LogMessage(myself, "drop %d", drop);

    if (msg.xuid())
        g_pSM->LogMessage(myself, "Msg XUID: %" PRId64, msg.xuid());

    g_pSM->LogMessage(myself, "Msg Format: %d", msg.format());
    g_pSM->LogMessage(myself, "Msg sequence_bytes %d", msg.sequence_bytes());
    if (msg.has_data())
    {
        g_pSM->LogMessage(myself, "Msg Data Size: %d", msg.data().size());
        g_pSM->LogMessage(myself, "Msg Data: %s", string_to_hex(msg.data().c_str()).c_str());
    }
    g_pSM->LogMessage(myself, "Msg section_number %d", msg.section_number());
    g_pSM->LogMessage(myself, "Msg uncompressed_sample_offset %d", msg.uncompressed_sample_offset());
    g_pSM->LogMessage(myself, "===END=======%s================", funcName);
}

DETOUR_DECL_STATIC3(SV_BroadcastVoiceData_CSGO, int, IClient *, pClient, const CCLCMsg_VoiceData &, msg, bool, drop)
{
    if (g_SvLogging->GetInt())
        PrintCCLCMsg_VoiceData("SV_BroadcastVoiceData_CSGO", pClient->GetPlayerSlot() + 1, msg, drop);

    if (pClient && g_Interface.OnBroadcastVoiceData(pClient, msg.data().size(), (char*)msg.data().c_str()))
        return DETOUR_STATIC_CALL(SV_BroadcastVoiceData_CSGO)(pClient, msg, drop);

    return 1;
}
#endif

DETOUR_DECL_STATIC4(SV_BroadcastVoiceData, void, IClient *, pClient, int, nBytes, char *, data, int64, xuid)
{
    if (pClient && g_Interface.OnBroadcastVoiceData(pClient, nBytes, data))
        DETOUR_STATIC_CALL(SV_BroadcastVoiceData)(pClient, nBytes, data, xuid);
}

#ifdef _WIN32
DETOUR_DECL_STATIC2(SV_BroadcastVoiceData_LTCG, void, char *, data, int64, xuid)
{
    IClient *pClient = NULL;
    int nBytes = 0;

#ifndef WIN64
    __asm mov pClient, ecx;
    __asm mov nBytes, edx;
#endif

    bool ret = g_Interface.OnBroadcastVoiceData(pClient, nBytes, data);

#ifndef WIN64
    __asm mov ecx, pClient;
    __asm mov edx, nBytes;
#endif

    if (ret)
        DETOUR_STATIC_CALL(SV_BroadcastVoiceData_LTCG)(data, xuid);
}
#endif

#ifdef _WIN32
double getTime() {
    LARGE_INTEGER freq, count;
    if (!QueryPerformanceFrequency(&freq) || !QueryPerformanceCounter(&count)) {
        return 0.0;
    }
    return static_cast<double>(count.QuadPart) / static_cast<double>(freq.QuadPart);
}
#else
double getTime() {
    struct timespec tv;
    if(clock_gettime(CLOCK_REALTIME, &tv) != 0)
        return 0;

    return (tv.tv_sec + (tv.tv_nsec / 1000000000.0));
}
#endif

void OnGameFrame(bool simulating)
{
    g_Interface.OnGameFrame(simulating);
}

CVoice::CVoice()
{
    m_ListenSocket = -1;
    m_PollFds = 0;
    for(int i = 0; i < 1 + MAX_CLIENTS; i++)
        m_aPollFds[i].fd = -1;

    for(int i = 0; i < MAX_CLIENTS; i++)
    {
        m_aClients[i].m_Socket = -1;
        m_aClients[i].m_New = true;
    }

    m_AvailableTime = 0.0;
    m_OpusEncoder = NULL;
    m_VoiceDetour = NULL;
}

class SpeakingEndTimer : public ITimedEvent
{
public:
    ResultType OnTimer(ITimer *pTimer, void *pData)
    {
        int client = (int)(intptr_t)pData;
        if ((gpGlobals->curtime - g_fLastVoiceData[client]) > 0.1)
        {
            if (g_SvLogging->GetInt())
                g_pSM->LogMessage(myself, "Player Speaking End (client=%d)", client);
            return Pl_Stop;
        }
        return Pl_Continue;
    }
    void OnTimerEnd(ITimer *pTimer, void *pData)
    {
        g_pTimerSpeaking[(int)(intptr_t)pData] = NULL;
    }
} s_SpeakingEndTimer;

bool CVoice::SDK_OnLoad(char *error, size_t maxlength, bool late)
{
    char conf_error[255] = "";
    if(!gameconfs->LoadGameConfigFile("voice.games", &g_pGameConf, conf_error, sizeof(conf_error)))
    {
        if(conf_error[0])
        {
            snprintf(error, maxlength, "Could not read voice.games.txt: %s\n", conf_error);
        }
        return false;
    }

    // Setup voice detour.
    CDetourManager::Init(g_pSM->GetScriptingEngine(), g_pGameConf);

#if SOURCE_ENGINE == SE_CSGO || SOURCE_ENGINE == SE_INSURGENCY
    #ifdef _WIN32
        m_VoiceDetour = DETOUR_CREATE_STATIC(SV_BroadcastVoiceData_LTCG, "SV_BroadcastVoiceData");
    #else
        m_VoiceDetour = DETOUR_CREATE_STATIC(SV_BroadcastVoiceData_CSGO, "SV_BroadcastVoiceData");
    #endif
#else
    #ifdef _WIN32
        m_VoiceDetour = DETOUR_CREATE_STATIC(SV_BroadcastVoiceData_LTCG, "SV_BroadcastVoiceData");
    #else
        m_VoiceDetour = DETOUR_CREATE_STATIC(SV_BroadcastVoiceData, "SV_BroadcastVoiceData");
    #endif
#endif

    if (!m_VoiceDetour)
    {
        g_SMAPI->Format(error, maxlength, "SV_BroadcastVoiceData detour failed.");
        return false;
    }

    m_VoiceDetour->EnableDetour();

    AutoExecConfig(g_pCVar, true);

    int err;
    // Create Opus encoder
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
    GET_V_IFACE_CURRENT(GetServerFactory, hltvdirector, IHLTVDirector, INTERFACEVERSION_HLTVDIRECTOR);
    gpGlobals = ismm->GetCGlobals();
    ConVar_Register(0, this);

    return true;
}

bool CVoice::RegisterConCommandBase(ConCommandBase *pVar)
{
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
    if(setsockopt(m_ListenSocket, SOL_SOCKET, SO_REUSEADDR, (const char*)&yes, sizeof(yes)) < 0)
    {
        smutils->LogError(myself, "Failed setting SO_REUSEADDR on socket.");
        SDK_OnUnload();
        return;
    }

    #ifdef _WIN32
        unsigned long nonblock = 1;
        ioctlsocket(m_ListenSocket, FIONBIO, &nonblock);
    #else
        int flags = fcntl(m_ListenSocket, F_GETFL, 0);
        fcntl(m_ListenSocket, F_SETFL, flags | O_NONBLOCK);
    #endif

    smutils->AddFrameAction(ListenSocketAction, this);
}

bool convert_ip(const char *ip, struct in_addr *addr)
{
#ifdef _WIN32
    return InetPton(AF_INET, ip, addr) == 1;
#else
    return inet_aton(ip, addr) != 0;
#endif
}

void close_socket(socket_t sock)
{
#ifdef _WIN32
    closesocket(sock);
#else
    close(sock);
#endif
}

int my_poll(struct pollfd *fds, int nfds, int timeout)
{
#ifdef _WIN32
    typedef int nfds_t;
    return WSAPoll(fds, nfds, timeout);
#else
    return poll(fds, nfds, timeout);
#endif
}

int my_ioctl(socket_t sockfd, long cmd, size_t *argp)
{
#ifdef _WIN32
    return ioctlsocket(sockfd, cmd, reinterpret_cast<u_long*>(argp));
#else
    return ioctl(sockfd, cmd, argp);
#endif
}

void CVoice::ListenSocket()
{
    if(m_PollFds > 0)
        return;

    sockaddr_in bindAddr;
    memset(&bindAddr, 0, sizeof(bindAddr));
    bindAddr.sin_family = AF_INET;
    if (!convert_ip(g_SmVoiceAddr->GetString(), &bindAddr.sin_addr))
    {
        smutils->LogError(myself, "Failed to convert ip.");
        SDK_OnUnload();
        return;
    }
    bindAddr.sin_port = htons(g_SmVoicePort->GetInt());

    smutils->LogMessage(myself, "Binding to %s:%d!", g_SmVoiceAddr->GetString(), g_SmVoicePort->GetInt());

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

    if (m_VoiceDetour)
    {
        m_VoiceDetour->Destroy();
        m_VoiceDetour = NULL;
    }

    if(m_ListenSocket != -1)
    {
        close_socket(m_ListenSocket);
        m_ListenSocket = -1;
    }

    for (int Client = 0; Client < MAX_CLIENTS; Client++)
    {
        if(m_aClients[Client].m_Socket != -1)
        {
            close_socket(m_aClients[Client].m_Socket);
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
    
    if (g_aFrameVoiceBytes[client] > NET_MAX_VOICE_BYTES_FRAME)
    {
        return false;
    }

    g_fLastVoiceData[client] = gpGlobals->curtime;

    return true;
}

void CVoice::HandleNetwork()
{
    if(m_ListenSocket == -1 || m_PollFds == 0)
        return;

    int PollRes = my_poll(m_aPollFds, m_PollFds, 0);
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

        // Found free slot
        if(Client < MAX_CLIENTS)
        {
            sockaddr_in addr;
            socklen_t size = sizeof(sockaddr_in);
            socket_t Socket = accept(m_ListenSocket, (sockaddr *)&addr, &size);

            if (Socket != -1)
            {
                #ifdef _WIN32
                    unsigned long nonblock = 1;
                    ioctlsocket(Socket, FIONBIO, &nonblock);
                #else
                    int flags = fcntl(Socket, F_GETFL, 0);
                    fcntl(Socket, F_SETFL, flags | O_NONBLOCK);
                #endif

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

                if (g_SvLogging->GetInt())
                    smutils->LogMessage(myself, "Client %d connected!", Client);
            }
        }
    }

    bool CompressPollFds = false;
    for(int PollFds = 1; PollFds < m_PollFds; PollFds++)
    {
        if (m_aPollFds[PollFds].fd == -1)
            continue;

        int Client = -1;
        for(Client = 0; Client < MAX_CLIENTS; Client++)
        {
            if(m_aClients[Client].m_Socket == m_aPollFds[PollFds].fd)
                break;
        }
        if(Client == -1 || Client >= MAX_CLIENTS)
            continue;

        CClient *pClient = &m_aClients[Client];

        // Connection shutdown
        if(m_aPollFds[PollFds].revents & (POLLHUP | POLLERR))
        {
            if (pClient->m_Socket != -1)
                close_socket(pClient->m_Socket);

            pClient->m_Socket = -1;
            m_aPollFds[PollFds].fd = -1;
            CompressPollFds = true;
            if (g_SvLogging->GetInt())
                smutils->LogMessage(myself, "Client %d disconnected!", Client);
            continue;
        }

        // Data available?
        if(!(m_aPollFds[PollFds].revents & POLLIN))
            continue;

        size_t BytesAvailable;
        if(my_ioctl(pClient->m_Socket, FIONREAD, &BytesAvailable) == -1)
            continue;

        if(pClient->m_New)
        {
            pClient->m_BufferWriteIndex = m_Buffer.GetReadIndex();
            pClient->m_New = false;
        }

        m_Buffer.SetWriteIndex(pClient->m_BufferWriteIndex);

        char aBuf[32768];
        size_t max_recv = min_ext(BytesAvailable, sizeof(aBuf));
        
        // Don't recv() when we can't fit data into the ringbuffer
        if(max_recv > m_Buffer.CurrentFree() * sizeof(int16_t))
            continue;

        // Edge case: previously received data is uneven
        int Shift = 0;
        if(pClient->m_UnEven)
        {
            Shift = 1;
            aBuf[0] = pClient->m_Remainder;
            pClient->m_UnEven = false;
        }

        ssize_t Bytes = recv(pClient->m_Socket, &aBuf[Shift], max_recv - Shift, 0);

        if(Bytes <= 0)
        {
            if (pClient->m_Socket != -1)
                close_socket(pClient->m_Socket);

            pClient->m_Socket = -1;
            m_aPollFds[PollFds].fd = -1;
            CompressPollFds = true;
            if (g_SvLogging->GetInt())
                smutils->LogMessage(myself, "Client %d disconnected!", Client);
            continue;
        }

        Bytes += Shift;

        // Edge case: data received is uneven
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
        int write_idx = 1;
        for(int read_idx = 1; read_idx < m_PollFds; read_idx++)
        {
            if(m_aPollFds[read_idx].fd != -1)
            {
                if (write_idx != read_idx)
                {
                    m_aPollFds[write_idx] = m_aPollFds[read_idx];
                }
                write_idx++;
            }
        }
        m_PollFds = write_idx;
    }
}

void CVoice::OnDataReceived(CClient *pClient, int16_t *pData, size_t Samples)
{
    if (Samples == 0)
        return;

    // Check for empty input
    ssize_t DataStartsAt = -1;
    for(size_t i = 0; i < Samples; i++)
    {
        if(pData[i] == 0)
            continue;

        DataStartsAt = i;
        break;
    }

    // Discard empty data if last valid data was more than a second ago.
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
        smutils->LogError(myself, "Buffer push failed! Samples: %zu, Free: %zu", Samples, m_Buffer.CurrentFree());
        return;
    }

    pClient->m_LastValidData = getTime();
}

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