# Use FIDO2 KEY to generate Passphrase

## Usage :

- Create a passphrase for a website or whatever
./gofido2pass -u websitename -c
(enter PIN and touch key)

- Print passphrase to standard output
./gofido2pass -u websitename
(default output in base58, use -hex to output with an hex string)

## Context menu with key shortcut

- To show a dialog in graphical desktop, gofido2pass uses Zenity tool (debian : apt install zenity)
- To auto-type passphrase to the window under mouse cursor, gofido2pass uses xdotool

### Example with XFCE4

- Copy gofido2pass application and gofido2pass.sh to a directory (example $HOME/gofido2pass)

- Go to Keyboard configuration and add application shortcut for gofido2pass.sh script
 (verify path for gofido2pass application in gofido2script : default to ~/gofido2pass)
 
- Type your keyboard shortcut to test



