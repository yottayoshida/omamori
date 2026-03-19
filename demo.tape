# omamori demo — terminal recording
# Run: vhs demo.tape

Output demo.gif

Set Shell "bash"
Set FontSize 15
Set Width 880
Set Height 480
Set Theme "Catppuccin Mocha"
Set Padding 16
Set TypingSpeed 40ms

# Setup sandbox
Hide
Type `export PS1='$ '`
Enter
Sleep 300ms
Type `/bin/rm -rf /tmp/omamori-demo && mkdir -p /tmp/omamori-demo/src /tmp/omamori-demo/node_modules /tmp/omamori-demo/data`
Enter
Sleep 300ms
Type `touch /tmp/omamori-demo/src/main.rs /tmp/omamori-demo/node_modules/.keep /tmp/omamori-demo/data/report.csv`
Enter
Sleep 300ms
Type `cd /tmp/omamori-demo && git init -q`
Enter
Sleep 300ms
Type `export PATH="$HOME/.omamori/shim:$PATH"`
Enter
Sleep 300ms
Type "clear"
Enter
Sleep 500ms
Show

# Scene 1: Protected path → BLOCKED
Type "# AI agent tries to delete source code..."
Enter
Sleep 800ms
Type "CLAUDECODE=1 rm -rf src/"
Sleep 300ms
Enter
Sleep 2s

# Scene 2: Regenerable path → allowed
Type "# Regenerable path? No problem."
Enter
Sleep 600ms
Type "CLAUDECODE=1 rm -rf node_modules/"
Sleep 300ms
Enter
Sleep 2s

# Scene 3: Normal path → Trash
Type "# Unknown path → moved to Trash (recoverable)"
Enter
Sleep 600ms
Type "CLAUDECODE=1 rm -rf data/"
Sleep 300ms
Enter
Sleep 2s

# Scene 4: Terminal direct → no interference
Type "# Your terminal? Unaffected."
Enter
Sleep 600ms
Type `echo "rm works normally without AI env var"`
Sleep 300ms
Enter
Sleep 2s
