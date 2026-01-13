#if defined _Voice_included
 #endinput
#endif
#define _Voice_included

enum OS_Type {
    OS_Unknown = -1,
    OS_Windows = 0,
    OS_Linux = 1,
    OS_Mac = 2
};

/**
 * Checks whether a client is speaking or not.
 *
 * @param client 	The client index to check against.
 *
 * @error 			Client is not valid, ingame, or client is a bot.
 *
 * @return 			True if client is speaking, false otherwise.
 */
native bool IsClientTalking(int client);

/**
 * Gets the operating system of a client.
 *
 * @param client 	The client index to check.
 *
 * @error 			Client is not valid.
 *
 * @return 			OS_Type enum value.
 */
native OS_Type GetClientOS(int client);

/**
 * Gets the total number of voice packets sent by a client.
 *
 * @param client 	The client index to check.
 *
 * @error 			Client is not valid.
 *
 * @return 			Total voice packets.
 */
native int GetClientVoicePackets(int client);

/**
 * Gets the total bytes of voice data sent by a client.
 *
 * @param client 	The client index to check.
 *
 * @error 			Client is not valid.
 *
 * @return 			Total voice bytes.
 */
native int GetClientVoiceBytes(int client);

/**
 * Checks if a client is currently talking (within last 0.33 seconds).
 *
 * @param client 	The client index to check.
 *
 * @error 			Client is not valid.
 *
 * @return 			True if client is currently talking.
 */
native bool IsClientCurrentlyTalking(int client);

public Extension __ext_Voice =
{
	name = "Voice",
	file = "Voice.ext",
#if defined AUTOLOAD_EXTENSIONS
	autoload = 1,
#else
	autoload = 0,
#endif
#if defined REQUIRE_EXTENSIONS
	required = 1,
#else
	required = 0,
#endif
};

#if !defined REQUIRE_EXTENSIONS
public void __ext_Voice_SetNTVOptional()
{
    MarkNativeAsOptional("IsClientTalking");
    MarkNativeAsOptional("GetClientOS");
    MarkNativeAsOptional("GetClientVoicePackets");
    MarkNativeAsOptional("GetClientVoiceBytes");
    MarkNativeAsOptional("IsClientCurrentlyTalking");
}
#endif