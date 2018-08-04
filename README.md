# jelbrekTime
A developer jailbreak for Apple watch S3 watchOS 4.1  
Running this on an apple watch series 3 on watchOS 4.1 will:

## Features
  * Exploits kernel using v0rtex
  * Gets tfp0 and stores it to hsp4
  * Applies h3lix kernelpacthes
  * Remounts / as rw
  * Extracts bootstrap.tar

## Kernelpatches
  * Sets i_can_has_debugger = 1
  * Patches remount to allow remounting / as rw
  * Patches mount to allow mounting without _nosuid_
  * Sets proc_enforce = 0
  * Disables amfi code signature checks
  * Allows rwx mappings (for cool watch tweaks?)
  * Disables a bunch of sanbox stuff (likely incomplete)

## How to run
  * Clone git repo
  * Open in Xcode
  * Select certificate for main app/watch app/watch extension
  * Build and run iOS app on Phone
    * On the phone go to Settings->General->Profiles and trust your certificate
    * Run iOS app on the phone through Xcode again
  * ~Open jailbreak.m and set a breakpoint at the bottom where it says 'SET A BREAKPOINT HERE'~
  * Build and run Watchkit App on the watch
    * Wait for the app to install (this takes ages!!!)
    * Wait for Xcode to tell you launching failed
    * Launch the app manually on the watch
    * Accept the trust certificate on the watch
    * ~~DO NOT CLICK jelbrekTime YET!~~
  * ~~Run the Watchkit App through Xcode again!~~
    * ~~Again wait for the app to install (this takes ages!!!)~~
  * ~~Click on jelbrekTime button in Watchkit App~~
  * ~~Wait for the breakpoint to hit in Xcode~~
  * ~~Now you can execute shell commands through the debugger by typing:~~
    * ~~'p mysystem("ls /")'~~
    * ~~'p mysystem("id")'~~
    * ~~'p mysystem("ps aux")'~~

Update: SSH is now working :D  
To connect to the watch you want to use [companion_proxy](https://ghostbin.com/paste/vvxkk) by [qwertyoruiop](https://twitter.com/qwertyoruiopz/status/707638464523739136)

## Support more devices
If you want to run this on anything other than Apple Watch S3 on 4.1
You need to modify this project

### watchOS 4.0-4.1
Simply add more offsets to _offsetfinder.c_ and you should be good to go.  
For finding offsets you can download watch OTA updates from [ipsw.me](https://ipsw.me) and run [offsetfinder](https://github.com/tihmstar/offsetfinder).

### watchOS 3.x
While watchOS 3.x (iOS 10.x) is vulnerable to v0rtex, structs like *kport_t* is different to watchOS 4.
To port jelbrekTime to 3.x you need to modify *kport_t* (and possibly other things) to get v0rtex running. You also very likely need to make some changes to the kernelpatches.  
Some resources to get started are [doubleH3lix](https://github.com/tihmstar/doubleH3lix) and [liboffsetfinder64](https://github.com/tihmstar/liboffsetfinder64/) (obviously those projects are 64bit, but you need to do similar stuff to a 32bit kernel).


## Credits
* Siguza
* qwertyoruiop
* jk9357

Special thanks to @coolstarorg for compiling the bootstrap.tar for armv7k!
