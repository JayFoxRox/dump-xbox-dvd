
Usage: FreeCell <DRIVE> [-n|-o OUTPUTFILE] [SECTORFILE]

Dumps an XGD from a compatible drive, padding sectors in SECTORFILE.
The resulting OUTPUTFILE will include all video layers data.
Outputs the crc, md5 and sha1 of the resulting dump.

  -n             don't save to OUTPUTFILE, only calculate and show hashes
                 can not be used together with -o
  -o OUTPUTFILE  use OUTPUTFILE as file to extract to
                 if no -o option is given, it will default to "Track 01.iso"
                 can not be used together with -n

