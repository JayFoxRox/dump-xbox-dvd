/*
  This is free software: you can redistribute it and/or modify
  it under the terms of the GNU General Public License as published by
  the Free Software Foundation, either version 3 of the License, or
  (at your option) any later version.

  This is distributed in the hope that it will be useful,
  but WITHOUT ANY WARRANTY; without even the implied warranty of
  MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
  GNU General Public License for more details.

  You should have received a copy of the GNU General Public License
  along with this software.  If not, see <http://www.gnu.org/licenses/>.
*/

#ifndef FREECELL_LINUX_H
#define FREECELL_LINUX_H

#define PROGRAMNAME "freecell"
#define EXECUTABLE "freecell"
#define DRIVEUSAGE "IODVDServices[/?]"

#define O_BINARY 0
#define SIZE_T_FORMAT "%lu"

int getdrive(char *);
int opendrive();
void closedrive();
unsigned long long millisecondstime();
int sendcdb(const unsigned char *, unsigned char, unsigned char *, size_t, int, unsigned int *);

#endif
