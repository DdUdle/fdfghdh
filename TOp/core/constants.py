"""
Wireless Network Analysis Framework - Constants Module

This module defines constants used throughout the framework, including
attack parameters, MAC address mappings, protocol identifiers, and timing values.
"""

# General timing constants
DEFAULT_TIMEOUT = 30.0
DEFAULT_INTERVAL = 0.5
CLIENT_TIMEOUT = 300  # 5 minutes in seconds
MIN_ATTACK_INTERVAL = 5.0  # Minimum time between attacks on same client
MAX_RETRIES = 10  # Maximum attack attempts before giving up

# Packet counts and rates
DEFAULT_DEAUTH_RATE = 0.1  # 10 packets per second
DEFAULT_PACKET_COUNT = 5
MAX_PACKET_COUNT = 20

# MAC address patterns
BROADCAST_MAC = "ff:ff:ff:ff:ff:ff"

# Common OUI mappings for device identification
COMMON_OUIS = {
    "APPLE": [
        "00:03:93", "00:05:02", "00:0A:27", "00:0A:95", "00:0D:93", 
        "00:11:24", "00:14:51", "00:16:CB", "00:17:F2", "00:19:E3", 
        "00:1B:63", "00:1D:4F", "00:1E:52", "00:1E:C2", "00:1F:5B",
        "00:1F:F3", "00:21:E9", "00:22:41", "00:23:12", "00:23:32",
        "00:23:6C", "00:23:DF", "00:24:36", "00:25:00", "00:25:4B",
        "00:25:BC", "00:26:08", "00:26:4A", "00:26:B0", "00:26:BB",
        "00:30:65", "00:3E:E1", "00:50:E4", "00:56:CD", "00:61:71",
        "00:C6:10", "00:DB:70", "00:F4:B9", "04:0C:CE", "04:15:52",
        "04:1E:64", "04:26:65", "04:54:53", "04:69:F8", "04:D3:CF",
        "04:DB:56", "04:E5:36", "04:F1:3E", "04:F7:E4", "08:66:98"
    ],
    "SAMSUNG": [
        "00:07:AB", "00:0D:AE", "00:12:47", "00:12:FB", "00:13:77",
        "00:15:99", "00:15:B9", "00:16:32", "00:16:6B", "00:16:6C",
        "00:17:C9", "00:17:D5", "00:18:AF", "00:1A:8A", "00:1B:98",
        "00:1C:43", "00:1D:25", "00:1D:F6", "00:1E:7D", "00:1F:CC",
        "00:1F:CD", "00:21:19", "00:21:4C", "00:21:D1", "00:21:D2",
        "00:23:39", "00:23:3A", "00:23:99", "00:23:C2", "00:23:D6",
        "00:23:D7", "00:24:54", "00:24:90", "00:24:91", "00:24:E9",
        "00:25:38", "00:25:66", "00:25:67", "00:26:37", "00:26:5D",
        "00:26:5F", "00:E0:64", "04:18:0F", "04:1B:BA", "04:FE:31",
        "08:08:C2", "08:37:3D", "08:3D:88", "08:78:08", "08:C6:B3"
    ],
    "MICROSOFT": [
        "00:03:FF", "00:0D:3A", "00:12:5A", "00:15:5D", "00:17:FA",
        "00:18:8B", "00:1D:D8", "00:22:48", "00:25:AE", "00:50:F2",
        "28:16:A8", "28:18:78", "30:59:B7", "48:51:B7", "50:1A:C5",
        "58:82:A8", "60:45:BD", "7C:1E:52", "7C:ED:8D", "98:5F:D3"
    ],
    "GOOGLE": [
        "00:1A:11", "08:9E:08", "3C:5A:B4", "54:60:09", "70:3A:CB",
        "94:95:A0", "94:EB:2C", "98:D2:93", "A4:77:33", "D8:6C:63"
    ],
    "INTEL": [
        "00:02:B3", "00:03:47", "00:04:23", "00:07:E9", "00:0C:F1",
        "00:0E:0C", "00:0E:35", "00:11:11", "00:12:F0", "00:13:02",
        "00:13:20", "00:13:CE", "00:13:E8", "00:15:00", "00:15:17",
        "00:16:6F", "00:16:76", "00:16:EA", "00:16:EB", "00:18:DE"
    ],
    "CISCO": [
        "00:00:0C", "00:01:42", "00:01:43", "00:01:63", "00:01:64",
        "00:01:96", "00:01:97", "00:01:C7", "00:01:C9", "00:02:16",
        "00:02:17", "00:02:3D", "00:02:4A", "00:02:4B", "00:02:7D",
        "00:02:7E", "00:02:B9", "00:02:BA", "00:02:FC", "00:02:FD"
    ],
    "HUAWEI": [
        "00:18:82", "00:1E:10", "00:25:68", "00:25:9E", "00:34:FE",
        "00:46:4B", "00:5A:13", "00:66:4B", "00:9A:CD", "00:E0:FC",
        "04:25:C5", "04:27:58", "04:33:89", "04:4F:AA", "04:75:03"
    ],
    "DEFAULT": []
}

# 802.11 management frame type and subtype values
DOT11_MGMT_TYPE = 0
DOT11_MGMT_SUBTYPES = {
    "ASSOC_REQ": 0,
    "ASSOC_RESP": 1,
    "REASSOC_REQ": 2,
    "REASSOC_RESP": 3,
    "PROBE_REQ": 4,
    "PROBE_RESP": 5,
    "BEACON": 8,
    "ATIM": 9,
    "DISASSOC": 10,
    "AUTH": 11,
    "DEAUTH": 12,
    "ACTION": 13
}

# 802.11 control frame type and subtype values
DOT11_CTRL_TYPE = 1
DOT11_CTRL_SUBTYPES = {
    "BLOCK_ACK_REQ": 8,
    "BLOCK_ACK": 9,
    "PS_POLL": 10,
    "RTS": 11,
    "CTS": 12,
    "ACK": 13,
    "CF_END": 14,
    "CF_END_ACK": 15
}

# 802.11 data frame type and subtype values
DOT11_DATA_TYPE = 2
DOT11_DATA_SUBTYPES = {
    "DATA": 0,
    "DATA_CF_ACK": 1,
    "DATA_CF_POLL": 2,
    "DATA_CF_ACK_POLL": 3,
    "NULL": 4,
    "CF_ACK": 5,
    "CF_POLL": 6,
    "CF_ACK_POLL": 7,
    "QOS_DATA": 8,
    "QOS_DATA_CF_ACK": 9,
    "QOS_DATA_CF_POLL": 10,
    "QOS_DATA_CF_ACK_POLL": 11,
    "QOS_NULL": 12,
    "QOS_CF_POLL": 14,
    "QOS_CF_ACK_POLL": 15
}

# Common deauthentication reason codes
DEAUTH_REASON_CODES = {
    1: "Unspecified",
    2: "Previous authentication no longer valid",
    3: "Deauthenticated because sending STA is leaving (or has left) IBSS or ESS",
    4: "Disassociated due to inactivity",
    5: "Disassociated because AP is unable to handle all currently associated STAs",
    6: "Class 2 frame received from nonauthenticated STA",
    7: "Class 3 frame received from nonassociated STA",
    8: "Disassociated because sending STA is leaving (or has left) BSS",
    9: "STA requesting (re)association is not authenticated with responding STA"
}

# Attack vectors
ATTACK_VECTORS = {
    "DEAUTH": 0,
    "DISASSOC": 1,
    "NULL_FUNC": 2,
    "AUTH_FLOOD": 3,
    "PROBE_FLOOD": 4,
    "ACTION_FLOOD": 5,
    "PMF_BYPASS": 6,
    "MIXED": 7
}

# Channel definitions and regions
CHANNELS_2GHZ = {
    "US": [1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11],
    "EU": [1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11, 12, 13],
    "JP": [1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11, 12, 13, 14]
}

CHANNELS_5GHZ = {
    "US": [36, 40, 44, 48, 52, 56, 60, 64, 100, 104, 108, 112, 116, 120, 124, 128, 132, 136, 140, 149, 153, 157, 161, 165],
    "EU": [36, 40, 44, 48, 52, 56, 60, 64, 100, 104, 108, 112, 116, 120, 124, 128, 132, 136, 140],
    "JP": [36, 40, 44, 48, 52, 56, 60, 64, 100, 104, 108, 112, 116, 120, 124, 128, 132, 136, 140]
}

# Common device categories and their attack strategies
DEVICE_CATEGORIES = {
    "APPLE": {
        "attack_vector": [ATTACK_VECTORS["DEAUTH"], ATTACK_VECTORS["DISASSOC"]],
        "reason_codes": [1, 2, 7],
        "burst": 6,
        "interval": 0.15,
        "description": "Apple devices (iPhone, iPad, MacBook, etc.)"
    },
    "SAMSUNG": {
        "attack_vector": [ATTACK_VECTORS["DISASSOC"], ATTACK_VECTORS["DEAUTH"]],
        "reason_codes": [2, 3, 4],
        "burst": 4,
        "interval": 0.12,
        "description": "Samsung devices (Galaxy phones, tablets, etc.)"
    },
    "MICROSOFT": {
        "attack_vector": [ATTACK_VECTORS["DEAUTH"], ATTACK_VECTORS["ACTION_FLOOD"]],
        "reason_codes": [1, 7],
        "burst": 5,
        "interval": 0.18,
        "description": "Microsoft devices (Surface, Windows laptops, etc.)"
    },
    "GOOGLE": {
        "attack_vector": [ATTACK_VECTORS["DEAUTH"], ATTACK_VECTORS["NULL_FUNC"]],
        "reason_codes": [2, 7],
        "burst": 4,
        "interval": 0.15,
        "description": "Google devices (Pixel, Chromebook, etc.)"
    },
    "INTEL": {
        "attack_vector": [ATTACK_VECTORS["DEAUTH"]],
        "reason_codes": [7],
        "burst": 6,
        "interval": 0.1,
        "description": "Devices with Intel wireless chipsets"
    },
    "IOT": {
        "attack_vector": [ATTACK_VECTORS["DEAUTH"], ATTACK_VECTORS["AUTH_FLOOD"]],
        "reason_codes": [1, 2],
        "burst": 8,
        "interval": 0.1,
        "description": "IoT devices (smart home devices, etc.)"
    },
    "NETWORK": {
        "attack_vector": [ATTACK_VECTORS["MIXED"], ATTACK_VECTORS["PMF_BYPASS"]],
        "reason_codes": [9, 7, 3],
        "burst": 3,
        "interval": 0.2,
        "description": "Network equipment (routers, access points, etc.)"
    },
    "DEFAULT": {
        "attack_vector": [ATTACK_VECTORS["DEAUTH"]],
        "reason_codes": [7],
        "burst": 5,
        "interval": 0.15,
        "description": "Default category for unknown devices"
    }
}

# WiFi element IDs of interest
WIFI_ELEMENT_IDS = {
    0: "SSID",
    1: "Supported Rates",
    3: "DSSS Parameter Set",
    5: "Traffic Indication Map",
    7: "Country",
    16: "Challenge Text",
    32: "Power Constraint",
    42: "ERP Information",
    45: "HT Capabilities",
    48: "RSN",
    50: "Extended Supported Rates",
    61: "HT Operation",
    127: "Extended Capabilities",
    191: "VHT Capabilities",
    192: "VHT Operation",
    255: "Vendor Specific"
}

# File paths and directories
DEFAULT_CONFIG_PATH = "config/default.cfg"
DEFAULT_LOG_DIR = "logs"
DEFAULT_DATA_DIR = "data"
DEFAULT_MODEL_DIR = "models"

# Machine learning model parameters
ML_MODEL_PARAMS = {
    "learning_rate": 0.001,
    "discount_factor": 0.95,
    "exploration_rate": 0.2,
    "max_history": 1000,
    "batch_size": 32,
    "target_update_freq": 100
}

# Evasion parameters
EVASION_LEVELS = {
    0: "None",
    1: "Basic",
    2: "Moderate",
    3: "Advanced",
    4: "Maximum"
}

# AI behavior modes
AI_MODES = {
    "balanced": "Balanced approach",
    "stealth": "Prioritize staying undetected",
    "speed": "Prioritize quick results",
    "efficiency": "Prioritize minimum packet usage"
}