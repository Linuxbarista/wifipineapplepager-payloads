#!/bin/sh
# Title: Blue Clues
# Author: Brandon Starkweather

# --- 1. LOG SETUP ---
CURRENT_DIR=$(pwd)
TIMESTAMP=$(date +%Y%m%d_%H%M%S)
LOG_FILE="${CURRENT_DIR}/blueclues_${TIMESTAMP}.txt"
touch "$LOG_FILE"

# --- 2. HARDWARE CONTROL ---
set_global_color() {
    # $1=R, $2=G, $3=B
    for dir in up down left right; do
        if [ -f "/sys/class/leds/${dir}-led-red/brightness" ]; then
            echo "$1" > "/sys/class/leds/${dir}-led-red/brightness"
            echo "$2" > "/sys/class/leds/${dir}-led-green/brightness"
            echo "$3" > "/sys/class/leds/${dir}-led-blue/brightness"
        fi
    done
}

set_led() {
    # $1: 0=OFF, 1=RED(Found), 2=GREEN(Idle), 3=BLUE(Working)
    STATE=$1
    if [ "$STATE" -eq 1 ]; then
        if [ "$FB_MODE" -eq 2 ] || [ "$FB_MODE" -eq 4 ]; then
            set_global_color 255 0 0
        fi
    elif [ "$STATE" -eq 2 ]; then
        set_global_color 0 255 0
    else
        set_global_color 0 0 0
    fi
}

do_vibe() {
    if [ "$FB_MODE" -eq 3 ] || [ "$FB_MODE" -eq 4 ]; then
        # Use GPIO Vibrator
        if [ -f "/sys/class/gpio/vibrator/value" ]; then
            echo "1" > /sys/class/gpio/vibrator/value
            sleep 0.2
            echo "0" > /sys/class/gpio/vibrator/value
        fi
    fi
}

cleanup() {
    set_global_color 0 0 0
    rm /tmp/bt_scan.txt 2>/dev/null
    
    if [ -s "$LOG_FILE" ]; then
        # Count Unique MACs (Field 2) since Field 1 is now Timestamp
        UNIQUE=$(awk '{print $2}' "$LOG_FILE" | sort -u | grep -c ":")
        FILENAME=$(basename "$LOG_FILE")
        PROMPT "SESSION COMPLETED
        
Unique Devices: $UNIQUE
Saved: $FILENAME"
    else
        PROMPT "SESSION ENDED
        
No data captured."
        rm "$LOG_FILE" 2>/dev/null
    fi
    exit 0
}
trap cleanup EXIT INT TERM

# --- 3. INIT ---
for led in /sys/class/leds/*; do
    if [ -f "$led/trigger" ]; then echo "none" > "$led/trigger"; fi
done
set_global_color 0 0 0

if ! command -v hcitool >/dev/null; then
    PROMPT "ERROR: hcitool missing."
    exit 1
fi

hciconfig hci0 up >/dev/null 2>&1

# --- 4. INTRO SEQUENCE ---

# A. App Description
PROMPT "BLUE CLUES

This tool scans for visible Bluetooth devices and logs them to a file.

It runs silently in the background for a set duration.

Press OK to Continue."

# B. Workflow
PROMPT "WORKFLOW

1. Select Feedback Mode.
2. Set Scan Duration.
3. Device runs silently.

Cancel anytime to Exit.
Press OK to Continue."

# C. Feedback Details
PROMPT "FEEDBACK OPTIONS

What happens when a device is found?

1. Silent (Log Only)
2. LED (Red Flash)
3. Vibe (Short Buzz)
4. Both (Flash + Buzz)

Press OK to Select."

# D. Feedback Picker
# Label: "Choose Feedback Selection"
FB_MODE=$(NUMBER_PICKER "Choose Feedback Selection" 1)
if [ -z "$FB_MODE" ]; then cleanup; fi

# --- 5. MAIN LOOP ---
while true; do
    set_led 2 # Green (Idle)
    
    # A. Get Time Input (Number Picker)
    # Label: "Duration of Scan in Minutes"
    MINS=$(NUMBER_PICKER "Duration of Scan in Minutes" 1)
    
    if [ -z "$MINS" ]; then cleanup; fi
    
    # B. Start
    PROMPT "STARTING RUN
    
Duration: ${MINS}m
Feedback: Mode $FB_MODE

Screen will be silent.
Press OK to Start."

    START_TIME=$(date +%s)
    DURATION_SEC=$((MINS * 60))
    END_TIME=$((START_TIME + DURATION_SEC))
    
    set_global_color 0 0 0
    
    # C. SILENT SCAN LOOP
    while [ $(date +%s) -lt $END_TIME ]; do
        
        hcitool scan > /tmp/bt_scan.txt
        
        RAW_DATA=$(tail -n +2 /tmp/bt_scan.txt)
        COUNT=$(echo "$RAW_DATA" | grep -c ":")
        
        # Log with Timestamp First
        if [ -n "$RAW_DATA" ]; then
            CURRENT_TIME=$(date '+%H:%M:%S')
            # Prepend timestamp to start of every line
            # Result: HH:MM:SS  MAC  Name
            echo "$RAW_DATA" | sed "s/^/$CURRENT_TIME\t/" >> "$LOG_FILE"
        fi
        
        if [ "$COUNT" -gt 0 ]; then
            # Feedback Trigger
            set_led 1 # Red
            do_vibe
            sleep 1
            set_global_color 0 0 0
        else
            set_global_color 0 0 0
        fi
        
        sleep 1
    done
    
    # D. FINISH
    set_led 2 # Green
    if [ "$FB_MODE" -eq 3 ] || [ "$FB_MODE" -eq 4 ]; then
        do_vibe; sleep 0.2; do_vibe
    fi
    
    PROMPT "TIMER FINISHED
    
${MINS} minutes complete.
Data Saved.

Press OK to continue."
    
done