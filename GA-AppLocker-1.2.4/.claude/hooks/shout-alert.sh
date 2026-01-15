#!/bin/bash
# Alert hook - Makes noise when Claude needs keyboard input
# Used by the test loop to get your attention

TITLE="${1:-Attention Needed}"
MESSAGE="${2:-Claude needs your input}"
URGENT="${3:-false}"

# Console output
echo ""
echo "============================================================"
echo "  ${URGENT:+🚨 URGENT } ALERT: $TITLE"
echo "  $MESSAGE"
echo "============================================================"
echo ""

# Desktop notification (Linux)
if command -v notify-send &>/dev/null; then
    if [ "$URGENT" = "true" ]; then
        notify-send -u critical "$TITLE" "$MESSAGE"
    else
        notify-send "$TITLE" "$MESSAGE"
    fi
fi

# Play sound (Linux)
if [ "$URGENT" = "true" ]; then
    if command -v paplay &>/dev/null; then
        paplay /usr/share/sounds/freedesktop/stereo/bell.oga 2>/dev/null &
    elif command -v aplay &>/dev/null; then
        aplay /usr/share/sounds/alsa/Front_Center.wav 2>/dev/null &
    fi
fi

# Log to file
LOG_DIR="$(dirname "$0")"
echo "[$(date '+%Y-%m-%d %H:%M:%S')] $TITLE - $MESSAGE" >> "$LOG_DIR/alert-log.txt"
