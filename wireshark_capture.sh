
# Wireshark capture script for PE recording
# Captures network traffic during generation process

# Start capture on all interfaces
tshark -i any -w pe_generation_capture.pcapng -f "tcp or udp" &
CAPTURE_PID=$!

# Monitor for 60 seconds
sleep 60

# Stop capture
kill $CAPTURE_PID

echo "Wireshark capture completed: pe_generation_capture.pcapng"
        