# Making a vault from the TUI: `c` and what it offers, a new encrypted folder
# typed in with the command it runs shown live, gocryptfs asking for the
# password and printing the master key, and the new vault in the list.
#
#   cd demo && ./render.sh create
#
# The vault is real inside the stage; the password `demo` and its master key
# die with the stage.

Output "../readme-assets/create.gif"

Set Shell bash
Set FontFamily "JetBrainsMono NF"
Set Theme "Catppuccin Mocha"
Set FontSize 15
Set Width 1240
Set Height 480
Set Padding 20
Set Framerate 24
Set TypingSpeed 80ms

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
Type "clear && ck"
Enter
Sleep 2.5s
Show
Sleep 1.5s

# ---- what `c` offers, then the folder ----------------------------------------
Type "c"
Sleep 2.5s
Down
Sleep 1s
Enter
Sleep 1s
Type "~/private"
Sleep 2s
Enter
Sleep 1.5s

# ---- gocryptfs's own prompts, then its master key ----------------------------
Type "demo"
Enter
Sleep 800ms
Type "demo"
Enter
Sleep 4s
Type " "
Sleep 3s

Hide
Type "q"
Sleep 500ms
