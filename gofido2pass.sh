#! /bin/sh

WID=`xdotool getmouselocation --shell | grep WINDOW | cut -d '=' -f2`
WNAME=`xdotool getwindowname $WID`

notify-send -t 20 "$WNAME" "$WNAME $WID" --icon=dialog-information
sleep 0.2

OPTIONS=`~/scripts/gofido2pass -l | tr '\n' ' '`

TEXT=`zenity --hide-header --column=name --list $OPTIONS --height=400`

if [ "$TEXT" = "" ]; then
	notify-send -t 20 "Cancel" "Cancel !" --icon=dialog-error
else
	notify-send -t 20 "Selected" "$TEXT" --icon=dialog-information
	xdotool windowactivate $WID 

	PASSPHRASE=`~/scripts/gofido2pass -u $TEXT`
	setxkbmap fr && xdotool type --delay 2 $PASSPHRASE
fi

