A tool to dump original Xbox games to [redump](http://redump.org/) standards (and better).
Based on FreeCell.

**DO NOT USE THIS TOOL FOR PRESERVING YOUR DISCS YET**


## Supported drives / firmwares

Currently only Kreon 1.00 has been tested and confirmed working.
For a list of drives supporting this firmware, [check this article on XboxDevWiki](http://xboxdevwiki.net/Xbox_Game_Disc).


## Building

* Install [zlib](https://www.zlib.net/)
  * MSYS2: `pacman -S zlib`
  * For other platforms check your platforms documentation
* Clone this repository: `git clone https://github.com/JayFoxRox/dump-xbox-dvd.git`
* Change into the repository folder: `cd dump-xbox-dvd`
* Create a build folder and move into it: `mkdir build; cd build`
* Run CMake to generate build files `cmake ..`

You can now use your platforms build system to compile.
For most platforms this can be done by running `make`.


## Running

Insert the game disc you want to dump into your drive which is connected to your system.
Then run:

`xbox-dump-dvd <drive name>`

Typical drive names:

* Linux: `/dev/sr0`, `/dev/sr1`, ..
* MacOS: `IODVDServices[/0]`, `IODVDServices[/1]`, ..
* Windows: `D:`, `E:`, ..

Note that you need administrative / super-user permissions on most platforms.


## License

Licensed under GPLv3 or any later version.
Refer to the LICENSE.txt file included.

Also, this software makes use of the MD5 implementation of Alexander Peslyak.
This is found at http://openwall.info/wiki/people/solar/software/public-domain-source-code/md5
Changes were made for OpenSSL compatibility and a small casting patch for g++ support.
These changes are released under the same license as the original md5.c file.

Finally, this software makes use of the SHA1 implementation of Steve Reid, Ralph Giles et al.
Changes were made for OpenSSL compatibility and using standard c types in the header.
Also, SHA1HANDSOFF is defined to protect input data.
These changes are also released under the same license as the original sha1.c file.
