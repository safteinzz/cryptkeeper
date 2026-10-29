# The still of `ck check`. Its own tape, since a still is sized to its three
# lines and the TUI's frame would leave it mostly empty. The render container
# has no udisks, which is why its LUKS line shows the missing case.
#
#   cd demo && ./render.sh check

Output "/tmp/ck-check.mp4"

Set Shell bash
Set FontFamily "JetBrainsMono NF"
Set Theme "Catppuccin Mocha"
Set FontSize 15
Set Width 1240
Set Height 160
Set Padding 20
Set Framerate 24
Set TypingSpeed 60ms

Hide
Type "./stage.sh up >/dev/null 2>&1"
Enter
Sleep 1s
# `exec`, so a stage that refuses to open takes the terminal with it: without it
# the script exits, the outer shell survives, and every keystroke after this
# lands in the real home.
Type "exec ./stage.sh shell"
Enter
Sleep 1.5s
Show

Type "ck check"
Enter
Sleep 2.5s
Screenshot ../readme-assets/check.png
Sleep 500ms
