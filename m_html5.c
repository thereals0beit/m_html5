/* 
 * m_html5 (C) 2013 s0beit
 * http://s0beit.me 
*/
 
#include "config.h"
#include "struct.h"
#include "common.h"
#include "sys.h"
#include "numeric.h"
#include "msg.h"
#include "proto.h"
#include "channel.h"
#include <time.h>
#include <sys/stat.h>
#include <inttypes.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#ifdef _WIN32
#include <io.h>
#endif
#include <fcntl.h>
#include "h.h"
#ifdef STRIPBADWORDS
#include "badwords.h"
#endif
#ifdef _WIN32
#include "version.h"
#endif

// Used for SHA1
#include <openssl/sha.h>

/* Module Header */
ModuleHeader MOD_HEADER(m_html5) = {
	"m_html5",
	"v0.1",
	"HTML5 WebSocket support module (by s0beit)",
	"3.2-b8-1",
	NULL
};

DLLFUNC int m_html5_in_hook(aClient* from, char* buf, int *len);
DLLFUNC int m_html5_out_hook(aClient *from, aClient *to, char **msg, int *len);

DLLFUNC CMD_FUNC(m_html5reject);
DLLFUNC CMD_FUNC(m_html5headerNull);

static long UMODE_HTMLFIVE = 0;
static Umode* UmodeHtmlFive = NULL;
static Hook* inHook = NULL;
static Hook* outHook = NULL;

int make_handshake_reply(aClient* to, char* key) {
	char finalKey[256];
	sprintf(finalKey, "%s258EAFA5-E914-47DA-95CA-C5AB0DC85B11", key); // Magic key!
	
	unsigned char sha1_hash[20];
	
	SHA_CTX hash;
	SHA1_Init(&hash);
	SHA1_Update(&hash, finalKey, strlen(finalKey));
	SHA1_Final(sha1_hash, &hash);
	
	b64_encode(sha1_hash, 20, finalKey, 256);
	
	ircd_log(LOG_DEBUG, "HANDSHAKE: Accept [%s]", finalKey);
	
	char handshakeReply[1024];

	sprintf(handshakeReply,
		"HTTP/1.1 101 Switching Protocols\r\n"
		"Upgrade: websocket\r\n"
		"Connection: Upgrade\r\n"
		"Sec-WebSocket-Accept: %s\r\n"
		"Sec-WebSocket-Protocol: unrealircd\r\n"
		"\r\n", finalKey);
	
	ircd_log(LOG_DEBUG, "HANDSHAKE: %s", handshakeReply);
	
	return send(to->fd, handshakeReply, strlen(handshakeReply), 0);
}

int readRfc6455( unsigned char* buffer, int* len ) {
	uint16_t opcode = (uint16_t) (buffer[0] & 0x0F);
	uint8_t basicLength = (buffer[1] & 0x7F);
	uint8_t masked = ((buffer[1] & 0x80) == 0x80);
	uint8_t fin = ((buffer[0] & 0x80) == 0x80);
	
	if(opcode != 0x1) { //kText is the only accepted type.
		return 0;
	}
	
	if(fin != 1) {
		return 0; // Continuation packets not allowed
	}
	
	if(basicLength == 127) {
		return 0; // IRC only supports up to 512 anyway, no need to handle it.
	}
	
	uint16_t packetIndex = sizeof(uint16_t);
	uint16_t payload_length = 0;
	
	if(basicLength == 126) {
		uint16_t v;
		memcpy(&v, buffer + packetIndex, sizeof(uint16_t));
		packetIndex += sizeof(uint16_t);
		
		payload_length = ntohs(v);
	} else {
		payload_length = (uint16_t) basicLength;
	}
	
	uint8_t mask[4];
	
	if(masked != 0) {
		memcpy(mask, buffer + packetIndex, sizeof(uint8_t) * 4);
		packetIndex += sizeof(uint8_t) * 4;
	} else {
		ircd_log(LOG_DEBUG, "No mask...");
	}
	
	uint16_t i;
	for(i = 0; i < payload_length; i++, packetIndex++) {
		uint8_t raw = (uint8_t) buffer[packetIndex];
		
		if(masked != 0) {
			uint8_t masked = mask[i % 4];
			uint8_t umaskd = raw ^ masked;
			buffer[i] = umaskd;
		} else {
			buffer[i] = raw;
		}
	}
	
	buffer[i++] = '\0'; //k lol
	
	ircd_log(LOG_DEBUG, "[%i][%i][%i]", i, packetIndex, payload_length);
	
	*len = payload_length;
	
	return 1;
}

int writeRfc6455(char** buffer, int *len) {
	if(*len == 0 || *len > 512) return 0; // We shouldn't even have packets over 512! Go away!
	
	char sendBufferBackup[2048]; // Matches the size of the unrealircd buffer
	
	memset(sendBufferBackup, 0, 2048 * sizeof(char));
	memcpy(sendBufferBackup, (*buffer), 2048 * sizeof(char));
	
	uint16_t opcode = 0x01; //text
	
	(*buffer)[0] = (0x80 | (opcode & 0x0F)); // Generic header
	
	uint16_t packetIndex = sizeof(uint16_t); // Header is included
	
	if(*len < 126) {
		(*buffer)[1] = (uint8_t) *len;
	} else {
		(*buffer)[1] = 126;
		uint16_t u = htons(*len);
		memcpy((*buffer) + packetIndex, &u, sizeof(uint16_t));
		packetIndex += sizeof(uint16_t); // 16-bit size
	}
		
	memcpy((*buffer) + packetIndex, sendBufferBackup, *len);
	
	*len += packetIndex;
	
	return 1;
}

int parseHandshakeParameters(aClient* from, char* buf, char* protocol, char* key, char* version) {
	if(from->user != NULL) return 0;
	
	char* token;
	if((token = strtok(buf, "\n")) != NULL) {
		do {
			token[strlen(token) - 1] = '\0'; //remove \r
						
			if(memcmp(token, "Sec-WebSocket-Protocol: ", 24) == 0) {
				strcpy(protocol, token + 24);
			} else if(memcmp(token, "Sec-WebSocket-Key: ", 19) == 0) {
				strcpy(key, token + 19);
			} else if(memcmp(token, "Sec-WebSocket-Version: ", 23) == 0) {
				strcpy(version, token + 23);
			}
		} while ((token = strtok(NULL, "\n")) != NULL);
	}
	
	return (strlen(protocol) && strlen(key) && strlen(version)) ? 1 : 0;
}

int packetParser(aClient* from, char* buf, int* len) {
	if(from->umodes & UMODE_HTMLFIVE) {
		ircd_log(LOG_DEBUG, "HTML5 packet [%i]", *len);
		
		int r = readRfc6455((uint8_t*)buf, len);
		
		ircd_log(LOG_DEBUG, "GOT [%s][%i][%i]", buf, r, *len);
		
		return 1; // So, we can't actually modify the length, so we just need to kill the packet right here and now...
	}
	
	if(memcmp(buf, "GET / HTTP/1.1", 14)) {
		ircd_log(LOG_DEBUG, "Standard packet");
		return 1; // Not a GET packet, not an HTML5 packet, so we can just go ahead
	}
	
	char protocol[256] = {0}, key[256] = {0}, version[256] = {0};
	
	if(parseHandshakeParameters(from, buf, protocol, key, version) == 0) {
		ircd_log(LOG_DEBUG, "Unable to parse HTML5 Handshake parameters!");
		return 0;
	} else {
		ircd_log(LOG_DEBUG, "Parsed handshake properly!");
	}
	
	if(atoi(version) < 13 || strcmp(protocol, "unrealircd")) {
		ircd_log(LOG_DEBUG, "Invalid handshake parameters!");
		return 0; // Invalid parameters
	}
	
	ircd_log(LOG_DEBUG, "[%s][%s][%s]", protocol, version, key);
	
	int r = (make_handshake_reply(from, key) > 0) ? 1 : 0;
	
	if(r == 1) {
		if(!(from->umodes & UMODE_HTMLFIVE)) {
			from->umodes |= UMODE_HTMLFIVE; // We HTML5 now
			
			ircd_log(LOG_DEBUG, "HTML5 umode applied");
		}
	} else {
		ircd_log(LOG_DEBUG, "Failed to make handshake reply...");
	}
	
	return r;
}

DLLFUNC int MOD_INIT(m_html5)(ModuleInfo *modinfo) {
	// add the '5' usermode which is reserved for clients connecting with HTML5
	UmodeHtmlFive = UmodeAdd(modinfo->handle, '5', UMODE_GLOBAL, NULL, &UMODE_HTMLFIVE);
	
	if(!UmodeHtmlFive) {
		config_error("m_html5: Could not add usermode '5': %s", ModuleGetErrorStr(modinfo->handle));
		return MOD_FAILED;
	}
	
	// We really should block POST and other stuff, though.
	CommandAdd(modinfo->handle, "POST", NULL, m_html5reject, MAXPARA, M_UNREGISTERED);
	CommandAdd(modinfo->handle, "PUT", NULL, m_html5reject, MAXPARA, M_UNREGISTERED);
	
	// If I add this, I can override the anti-HTTP POST protection.
	CommandAdd(modinfo->handle, "GET", NULL, m_html5headerNull, MAXPARA, M_UNREGISTERED);

	inHook = HookAddEx(modinfo->handle, HOOKTYPE_RAWPACKET_IN, m_html5_in_hook);
	outHook = HookAddEx(modinfo->handle, HOOKTYPE_PACKET, m_html5_out_hook);
	
	ModuleSetOptions(modinfo->handle, MOD_OPT_PERM);
	
	return MOD_SUCCESS;
}

DLLFUNC int MOD_LOAD(m_html5)(int module_load) {
	return MOD_SUCCESS;
}

DLLFUNC int MOD_UNLOAD(m_html5)(int module_unload) {
	return MOD_SUCCESS;
}

int m_html5_in_hook(aClient* from, char* buf, int* len) {
	ircd_log(LOG_DEBUG, "m_html5_in_hook");

	return packetParser(from, buf, len);
}

int m_html5_out_hook(aClient *from, aClient *to, char **msg, int *len) {
	ircd_log(LOG_DEBUG, "m_html5_out_hook");
	ircd_log(LOG_DEBUG, "[from: 0x%lX][to: 0x%lX][%s][%i]", from->umodes, to->umodes, *msg, *len);
	
	if(to->receiveM == 0) {
		ircd_log(LOG_DEBUG, "[OUT] BLOCKED [%s]", *msg);
		*msg = NULL;
		return 0;
	}
	
	if(IsMe(to)) {
		ircd_log(LOG_DEBUG, "[OUT] Allowed packet to 'me'");
		return 1; // Nope!
	}

	if(memcmp(*msg, "GET / HTTP/1.1", 14) == 0) {
		ircd_log(LOG_DEBUG, "[OUT] BLOCKED [%s]", *msg);
		*msg = NULL;
		return 0;
	}

	ircd_log(LOG_DEBUG, "[from: 0x%lX][to: 0x%lX]", from->umodes, to->umodes);
	ircd_log(LOG_DEBUG, "[to->receiveM: %li]", to->receiveM);
	
	if(to->umodes & UMODE_HTMLFIVE) {
		ircd_log(LOG_DEBUG, "[OUT] HTML5 OUT [%s]", *msg);
			
		if(writeRfc6455(msg, len) == 0) {
			ircd_log(LOG_DEBUG, "[OUT] ERROR: Failed writeRfc6455 to client...");
		}
	} else {
		ircd_log(LOG_DEBUG, "[OUT] Allowed Packet without UMODE [%s]", *msg);
	}

	return 1;
}

DLLFUNC int m_html5reject(aClient* cptr, aClient* sptr, int parc, char *parv[]) {
	return place_host_ban(sptr, BAN_ACT_KILL, "Invalid HTML5 HTTP header (ATTACK?)", 60 * 60 * 4);
}

DLLFUNC int m_html5headerNull(aClient *cptr, aClient *sptr, int parc, char *parv[]) {
	return 1;
}
