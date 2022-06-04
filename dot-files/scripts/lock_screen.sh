#!/bin/bash

# Take a screenshot
scrot /tmp/screen_locked.png

# Pixellate it 4x
mogrify -scale 25% -scale 400% /tmp/screen_locked.png
# Lock screen displaying this image.
i3lock -i /tmp/screen_locked.png

# Turn the screen off after a delay.
sleep 60; pgrep i3lock && xset dpms force off