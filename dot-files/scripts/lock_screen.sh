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
    -fill '#2e344080' -draw 'rectangle 0,0,9999,9999' \
    "$TMPIMG"

# Lock with the processed image
i3lock -e -i "$TMPIMG" \
    --nofork \
    --color=2e3440 \
    --insidecolor=3b425200 \
    --ringcolor=5e81acff \
    --ringvercolor=a3be8cff \
    --ringwrongcolor=bf616aff \
    --keyhlcolor=88c0d0ff \
    --bshlcolor=d08770ff \
    --separatorcolor=00000000 \
    --verifcolor=eceff4ff \
    --wrongcolor=bf616aff \
    --layoutcolor=d8dee9ff

# Turn screen off after 60s if still locked
sleep 60
pgrep i3lock && xset dpms force off