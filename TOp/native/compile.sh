#!/bin/bash
# Compilation script for the packet operations module

set -e  # Exit on error

# Check for required tools
for cmd in gcc pkg-config; do
    if ! command -v $cmd &> /dev/null; then
        echo "Error: $cmd is required but not installed"
        exit 1
    fi
done

# Check for libpcap
if ! pkg-config --exists libpcap; then
    echo "Error: libpcap development package is required"
    echo "Install with: sudo apt-get install libpcap-dev"
    exit 1
fi

# Get compiler flags for libpcap
PCAP_CFLAGS=$(pkg-config --cflags libpcap)
PCAP_LIBS=$(pkg-config --libs libpcap)

# Compile the shared library
echo "Compiling libpacket.c to libpacket.so..."
gcc -Wall -Wextra -fPIC -shared -o libpacket.so libpacket.c \
    $PCAP_CFLAGS -lpthread $PCAP_LIBS -O2

# Create test program if requested
if [ "$1" == "--with-test" ]; then
    echo "Compiling test program..."
    gcc -Wall -Wextra -o packet_test test.c -L. -lpacket \
        $PCAP_CFLAGS $PCAP_LIBS -Wl,-rpath,.
fi

echo "Compilation completed successfully"