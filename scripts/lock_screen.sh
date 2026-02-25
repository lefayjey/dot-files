#!/bin/bash

# Modern lock screen using i3lock-color
# Frosted blur with Catppuccin Macchiato-themed ring indicator
# Dependencies: i3lock-color, scrot, imagemagick

TMPIMG="/tmp/screen_locked.png"

# Capture & blur — fast pixelation + gaussian for frosted-glass look
scrot -o "$TMPIMG"
convert "$TMPIMG" \
    -scale 10% \
    -scale 1000% \
    -fill '#18192680' -draw 'rectangle 0,0,9999,9999' \
    "$TMPIMG"

# i3lock-color with styled ring indicator
i3lock \
    --nofork \
    --image="$TMPIMG" \
    \
    --indicator \
    --radius=105 \
    --ring-width=8 \
    \
    --inside-color=1e203000 \
    --ring-color=363a4fff \
    --line-color=00000000 \
    --separator-color=00000000 \
    \
    --keyhl-color=8aadf4ff \
    --bshl-color=f5a97fff \
    \
    --ringver-color=8bd5caff \
    --insidever-color=1e203080 \
    --verif-color=cad3f5ff \
    --verif-text="verifying..." \
    --verif-font="JetBrains Mono" \
    --verif-size=14 \
    \
    --ringwrong-color=ed8796ff \
    --insidewrong-color=1e203080 \
    --wrong-color=ed8796ff \
    --wrong-text="access denied" \
    --wrong-font="JetBrains Mono" \
    --wrong-size=14 \
    \
    --layout-color=a5adcbff \
    --time-color=cad3f5ff \
    --date-color=a5adcbff \
    --greeter-color=8aadf4ff \
    \
    --clock \
    --time-font="JetBrains Mono" \
    --time-size=42 \
    --time-str="%H:%M" \
    \
    --date-font="JetBrains Mono" \
    --date-size=14 \
    --date-str="%A, %d %B" \
    \
    --greeter-font="JetBrains Mono" \
    --greeter-size=12 \
    --greeter-text="" \
    \
    --pass-media-keys \
    --pass-screen-keys \
    --ignore-empty-password

# Turn screen off after 60s if still locked
sleep 60
pgrep i3lock && xset dpms force off