# The whole tool in one story: make a vault, open it, put a file in, lock it,
# and see the file gone from view and only ciphertext left in `.photos`.
#
#   cd demo && ./render.sh egc
#
# The vault is real and really mounted inside the stage; its password `demo`
# and its master key die with the stage.

Output "../readme-assets/egc.gif"

Set Shell bash
Set FontFamily "JetBrainsMono NF"
Set Theme "Catppuccin Mocha"
Set FontSize 15
# 1000 wide, not 1240: the widest line, gocryptfs's own note under the master
# key, is under 80 columns, so 1240 would leave a quarter of the frame empty.
Set Width 1000
Set Height 420
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

# ---- make it ---------------------------------------------------------------
Type "egc init photos"
Enter
Sleep 800ms
Type "demo"
Enter
Sleep 400ms
Type "demo"
Enter
Sleep 3s
Type "clear"
Enter
Sleep 300ms

# ---- open it, use it -------------------------------------------------------
Type "egc unlock photos"
Enter
Sleep 800ms
Type "demo"
Enter
Sleep 1.5s
Type "touch photos/beach.jpg && ls photos"
Enter
Sleep 1.5s
Type "egc"
Enter
Sleep 2s

# ---- lock it, and it is gone from view --------------------------------------
Type "egc lock photos"
Enter
Sleep 1.5s
Type "ls -A photos .photos"
Enter
Sleep 4s
