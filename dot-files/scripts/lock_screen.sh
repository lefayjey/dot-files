#!/bin/bash

# Modern lock screen — pixelated blur with Nord overlay
# Dependencies: scrot, imagemagick, i3lock

TMPIMG="/tmp/screen_locked.png"

# Take screenshot
scrot "$TMPIMG"

# Apply a gaussian blur + pixelation for a frosted-glass effect
convert "$TMPIMG" \
    -scale 10% \
    -scale 1000% \
    -fill '#1a1b2680' -draw 'rectangle 0,0,9999,9999' \
    "$TMPIMG"

# Lock with the processed image
i3lock -e -i "$TMPIMG" \
    --nofork \
    --color=1a1b26 \
    --insidecolor=24283b00 \
    --ringcolor=7aa2f7ff \
    --ringvercolor=73dacaff \
    --ringwrongcolor=f7768eff \
    --keyhlcolor=7dcfffff \
    --bshlcolor=ff9e64ff \
    --separatorcolor=00000000 \
    --verifcolor=c0caf5ff \
    --wrongcolor=f7768eff \
    --layoutcolor=a9b1d6ff

# Turn screen off after 60s if still locked
sleep 60
pgrep i3lock && xset dpms force off