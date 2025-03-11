/**
 * libpacket.h - Interface for high-performance packet operations
 */

#ifndef LIBPACKET_H
#define LIBPACKET_H

#ifdef __cplusplus
extern "C" {
#endif

// Error codes
#define ERR_SUCCESS          0
#define ERR_INVALID_PARAM    1
#define ERR_PCAP_OPEN        2
#define ERR_MEMORY_ALLOC     3
#define ERR_PACKET_SEND      4
#define ERR_CHANNEL_SWITCH   5

/**
 * Initialize the library and set up required resources
 * 
 * @return 0 on success, error code otherwise
 */
int initialize();

/**
 * Clean up resources used by the library
 * 
 * @return 0 on success, error code otherwise
 */
int cleanup();

/**
 * Send deauthentication packets at wire speed
 *
 * @param interface The wireless interface to use
 * @param bssid The BSSID of the access point
 * @param client The MAC address of the target client
 * @param count Number of packets to send
 * @param reason Reason code for deauthentication
 * @return 0 on success, error code otherwise
 */
int send_deauth(const char* interface, const char* bssid, const char* client, int count, int reason);

/**
 * Send disassociation packets at wire speed
 *
 * @param interface The wireless interface to use
 * @param bssid The BSSID of the access point
 * @param client The MAC address of the target client
 * @param count Number of packets to send
 * @param reason Reason code for disassociation
 * @return 0 on success, error code otherwise
 */
int send_disassoc(const char* interface, const char* bssid, const char* client, int count, int reason);

/**
 * Send null function packets at wire speed
 *
 * @param interface The wireless interface to use
 * @param bssid The BSSID of the access point
 * @param client The MAC address of the target client
 * @param count Number of packets to send
 * @return 0 on success, error code otherwise
 */
int send_null_func(const char* interface, const char* bssid, const char* client, int count);

/**
 * Send authentication flood packets at wire speed
 *
 * @param interface The wireless interface to use
 * @param bssid The BSSID of the access point
 * @param client The MAC address of the target client
 * @param count Number of packets to send
 * @return 0 on success, error code otherwise
 */
int send_auth_flood(const char* interface, const char* bssid, const char* client, int count);

/**
 * Set wireless interface to a specific channel
 *
 * @param interface The wireless interface to use
 * @param channel The channel number to set
 * @return 0 on success, error code otherwise
 */
int set_channel(const char* interface, int channel);

/**
 * Scan multiple channels in sequence
 *
 * @param interface The wireless interface to use
 * @param channels Array of channel numbers to scan
 * @param count Number of channels in the array
 * @return 0 on success, error code otherwise
 */
int scan_channels(const char* interface, int* channels, int count);

/**
 * Start a background channel hopper thread
 *
 * @param interface The wireless interface to use
 * @param channels Array of channel numbers to hop between
 * @param count Number of channels in the array
 * @param interval_ms Time to spend on each channel in milliseconds
 * @return 0 on success, error code otherwise
 */
int start_channel_hopper(const char* interface, int* channels, int count, int interval_ms);

/**
 * Stop the background channel hopper thread
 *
 * @return 0 on success, error code otherwise
 */
int stop_channel_hopper();

#ifdef __cplusplus
}
#endif

#endif /* LIBPACKET_H */