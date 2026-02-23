# meshcore_bot
another anoying meshcore ping-bot

## what it will do
This bot is used to react on single keyword in one or more channels setup on your companion-radion connected by serial or tcp-connection.

It supports
- channels and direct messages
- hop-limit on receiving trigger message
- blocktime on re-triggering the bot by same user
- setting scope to outgoing messages (highly recommended to use)

Another thing this script can do is to forward messages to an telegram-bot. I use this feature to check bot is working properly and forward private messages to the bot.

## what you will need
- raspberry, linux-pc or linux-vm (tested with Debian Trixie)
- companion-radio with serial-(usb)- or wifi-firmware (v1.11 or newer)
- current version of meshcore_py (tested with 2.2.14)

## what you should be able to do
- download code from github
- running python script
- install python scripts as a service

## what is really important !!!
- do not use a bot if you don't really know what happens with flood traffic in the meshcore
- do not use a bot if your neigbour uses a bot
- do not connect yout bot to many channels
- allways use scopes on bot and regions on your repeaters
- limit traffic by setting small a hop-limit for trigger an setting a small scope
- if you see your bot is causing a lot of traffic: stop it, set smaller scope and reduce hop-limit

## using from CLI

python3 meshcore_bot.py   with one of the following options ...
 
 -c | --config	path to config-file  e.g. meshcore_bot.conf
 -t | --tcp		use tcp-connection to companion  e.g. 10.0.0.1:5000
 -s | --serial	use serial-connection to companion  e.g. /dev/ttyUSB0

 -q | --quiet	minimal logging to CLI & journal
 -v | --verbose	maximum logging to CLI & journal
 -ver | --version	print version and exit

## using with config-file
you can start with my example under meshcore_bot.conf - it has a lot of comments to understand usage

### connecting to telegrambot
you can connect this bot to a telegram-bot to forward messages. You have to programm an host this bot on yourself! This script uses the following url-scheme ...

channel-messages: {bot_url}?apikey={apikey_channel}&message=[...]&title=[...]&sender={sender}

direct-messages: {bot_url}?apikey={apikey_private}&message=[...]&title=[...]&sender={sender}

## what you should know before you start
This software comes as it is without any guarantee to work stable and secure. There can be a lot of bugs in it.