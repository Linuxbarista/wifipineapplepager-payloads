#!/usr/bin

# Title:  GPS Real-Time Tracker
# Author: spywill
# Description: Real-Time GPS Tracker Shows location name Updates continuously using curl
# Version: 1.0

trap 'exit 0' INT TERM
INTERVAL=10
LAST_LAT=""
LAST_LON=""
LAST_LOCATION="(no location yet)"

# Reset the GPS hardware
GPS_RESET=$(START_SPINNER "Reset the GPS hardware")
gpsctl -n
STOP_SPINNER ${GPS_RESET}

# Check internet connectivity
is_online() {
	ping -c 1 -W 1 8.8.8.8 >/dev/null 2>&1
}

while true; do
	LOG ""
	LOG green "GPS Real-Time Tracker"
	LOG blue "================================================="
	LOG ""

	DATA=$(gpspipe -w -n 10 | grep -m 1 TPV)

	LAT=$(echo "$DATA" | jq -r '.lat')
	LON=$(echo "$DATA" | jq -r '.lon')
	ALT=$(echo "$DATA" | jq -r '.alt')
	SPD=$(echo "$DATA" | jq -r '.speed')

	if [[ "$LAT" == "null" || -z "$LAT" ]]; then
		LOG "Waiting for GPS fix..."
		sleep $INTERVAL
		continue
	fi

	LOG green "Coordinates:"
	LOG "  Latitude : $LAT"
	LOG "  Longitude: $LON"
	LOG ""

	# Speed
	if [[ "$SPD" != "null" ]]; then
		SPEED_KMH=$(awk "BEGIN {printf \"%.2f\", $SPD * 3.6}")
		LOG "  Speed    : $SPEED_KMH km/h"
	else
		LOG "  Speed    : N/A"
	fi

	# Altitude
    if [[ "$ALT" != "null" ]]; then
        LOG "  Altitude : $ALT m"
    else
        LOG "  Altitude : N/A"
	fi
    
	# Only reverse-geocode if moved AND online
	if [[ "$LAT" != "$LAST_LAT" || "$LON" != "$LAST_LON" ]]; then
		if is_online; then
			LOCATION=$(curl -s \
			"https://nominatim.openstreetmap.org/reverse?format=json&lat=$LAT&lon=$LON" \
			-H "User-Agent: gps-terminal-tracker" |
			jq -r '.display_name' | tr ',' '\n' | sed 's/^/  /')

			[[ -n "$LOCATION" && "$LOCATION" != "null" ]] && LAST_LOCATION="$LOCATION"
		else
			LAST_LOCATION="(offline – no map lookup)"
		fi
		LAST_LAT="$LAT"
		LAST_LON="$LON"
	fi
	LOG ""
	LOG green "Location:"
	LOG "$LAST_LOCATION"
	LOG ""
	LOG yellow "Updated: $(date)"
	sleep $INTERVAL
done
