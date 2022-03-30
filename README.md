# Use FIDO2 KEY to generate Passphrase

Tested with HyperFIDO Pro Mini, Yubikey 5 but should work with all compatible FIDO2 keys 

## Usage :

- Create a passphrase for a website or whatever
```
./gofido2pass -u websitename -c
```
(enter PIN and touch key)

- Print passphrase to standard output
```
./gofido2pass -u websitename
```
(default output in base58, use -hex to output with an hex string)

## Context menu with key shortcut

- To show a dialog in graphical desktop, gofido2pass uses Zenity tool (debian : apt install zenity)
- To auto-type passphrase to the window under mouse cursor, gofido2pass.sh uses xdotool
- To show notifications gofido2pass.sh uses notify-send

### Example with XFCE4

- Copy gofido2pass application and gofido2pass.sh to a directory (example $HOME/scripts)

- Go to Keyboard configuration and add application shortcut for gofido2pass.sh script
 (verify path for gofido2pass application in gofido2script : default to ~/scripts/gofido2pass)
 
- Type your keyboard shortcut to test



