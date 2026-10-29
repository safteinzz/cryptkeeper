# Every vault at once: bare `ck` on a folder vault and an encrypted file,
# Enter locking the folder, Enter unlocking it at gocryptfs's own password
# prompt, then Enter opening the file at age's passphrase prompt, the way most
# people lock a file.
#
#   cd demo && ./render.sh vaults
#
# The vaults are real and really mounted inside the stage; the password `demo`,
# the master key and the file's passphrase `demo` die with the stage.

Output "../readme-assets/vaults.gif"

Set Shell bash
Set FontFamily "JetBrainsMono NF"
Set Theme "Catppuccin Mocha"
Set FontSize 15
Set Width 1240
Set Height 480
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
# A piped stdin carries the password for gocryptfs, so nothing here prompts.
Type "echo demo | ck init photos >/dev/null 2>&1 && echo demo | ck unlock photos >/dev/null && touch photos/beach.jpg"
Enter
Sleep 3s
# age asks for a passphrase on the terminal itself, twice and then once more
# for ck to check the new file opens with it.
Type "echo 1040 > taxes.txt && ck init taxes.txt"
Enter
Sleep 1.5s
Type "demo"
Enter
Sleep 800ms
Type "demo"
Enter
Sleep 1.5s
Type "demo"
Enter
Sleep 2s
# The first frame is what the README shows before the GIF plays, so it opens on
# the list, not on a shell prompt.
Type "clear && ck"
Enter
Sleep 2.5s
Show
Sleep 2s

# ---- lock the folder, open it again ------------------------------------------
Enter
Sleep 2.5s
# Unlocking hands the plain terminal to gocryptfs's own password prompt.
Enter
Sleep 1s
Type "demo"
Enter
Sleep 2.5s

# ---- open the encrypted file at age's own passphrase prompt -------------------
Down
Sleep 800ms
Enter
Sleep 1.2s
Type "demo"
Enter
Sleep 3s

Hide
Type "q"
Sleep 500ms
