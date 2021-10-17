/*
** Copyright (C) 1998-2002 Martin Roesch <roesch@sourcefire.com>
**
** This program is free software; you can redistribute it and/or modify
** it under the terms of the GNU General Public License as published by
** the Free Software Foundation; either version 2 of the License, or
** (at your option) any later version.
**
** This program is distributed in the hope that it will be useful,
** but WITHOUT ANY WARRANTY; without even the implied warranty of
** MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
** GNU General Public License for more details.
**
** You should have received a copy of the GNU General Public License
** along with this program; if not, write to the Free Software
** Foundation, Inc., 59 Temple Place - Suite 330, Boston, MA 02111-1307, USA.
*/
/* $Id: codes.c,v 1.7 2003/10/20 15:03:16 chrisgreen Exp $ */
#ifdef HAVE_CONFIG_H
#include "config.h"
#endif

#include "codes.h"

typedef struct {
    unsigned int index;
    unsigned int val;
} unicode_entry;


unicode_entry unicode_data[]={
/*   char   �         char   �         char   �         char   �         char   � */
{ 0x0081, 0x81 }, { 0x0081, 0x81 }, { 0x008d, 0x8d }, { 0x008d, 0x8d }, { 0x008f, 0x8f },
/*   char   �         char   �         char   �         char   �         char   � */
{ 0x008f, 0x8f }, { 0x0090, 0x90 }, { 0x0090, 0x90 }, { 0x009d, 0x9d }, { 0x009d, 0x9d },
/*   char   �         char   �         char   �         char   �         char   � */
{ 0x00a0, 0xa0 }, { 0x00a0, 0xa0 }, { 0x00a1, 0xa1 }, { 0x00a1, 0xa1 }, { 0x00a2, 0xa2 },
/*   char   �         char   �         char   �         char   �         char   � */
{ 0x00a2, 0xa2 }, { 0x00a3, 0xa3 }, { 0x00a3, 0xa3 }, { 0x00a4, 0xa4 }, { 0x00a4, 0xa4 },
/*   char   �         char   �         char   �         char   �         char   � */
{ 0x00a5, 0xa5 }, { 0x00a5, 0xa5 }, { 0x00a6, 0xa6 }, { 0x00a6, 0xa6 }, { 0x00a7, 0xa7 },
/*   char   �         char   �         char   �         char   �         char   � */
{ 0x00a7, 0xa7 }, { 0x00a8, 0xa8 }, { 0x00a8, 0xa8 }, { 0x00a9, 0xa9 }, { 0x00a9, 0xa9 },
/*   char   �         char   �         char   �         char   �         char   � */
{ 0x00aa, 0xaa }, { 0x00aa, 0xaa }, { 0x00ab, 0xab }, { 0x00ab, 0xab }, { 0x00ac, 0xac },
/*   char   �         char   �         char   �         char   �         char   � */
{ 0x00ac, 0xac }, { 0x00ad, 0xad }, { 0x00ad, 0xad }, { 0x00ae, 0xae }, { 0x00ae, 0xae },
/*   char   �         char   �         char   �         char   �         char   � */
{ 0x00af, 0xaf }, { 0x00af, 0xaf }, { 0x00b0, 0xb0 }, { 0x00b0, 0xb0 }, { 0x00b1, 0xb1 },
/*   char   �         char   �         char   �         char   �         char   � */
{ 0x00b1, 0xb1 }, { 0x00b2, 0xb2 }, { 0x00b2, 0xb2 }, { 0x00b3, 0xb3 }, { 0x00b3, 0xb3 },
/*   char   �         char   �         char   �         char   �         char   � */
{ 0x00b4, 0xb4 }, { 0x00b4, 0xb4 }, { 0x00b5, 0xb5 }, { 0x00b5, 0xb5 }, { 0x00b6, 0xb6 },
/*   char   �         char   �         char   �         char   �         char   � */
{ 0x00b6, 0xb6 }, { 0x00b7, 0xb7 }, { 0x00b7, 0xb7 }, { 0x00b8, 0xb8 }, { 0x00b8, 0xb8 },
/*   char   �         char   �         char   �         char   �         char   � */
{ 0x00b9, 0xb9 }, { 0x00b9, 0xb9 }, { 0x00ba, 0xba }, { 0x00ba, 0xba }, { 0x00bb, 0xbb },
/*   char   �         char   �         char   �         char   �         char   � */
{ 0x00bb, 0xbb }, { 0x00bc, 0xbc }, { 0x00bc, 0xbc }, { 0x00bd, 0xbd }, { 0x00bd, 0xbd },
/*   char   �         char   �         char   �         char   �         char   � */
{ 0x00be, 0xbe }, { 0x00be, 0xbe }, { 0x00bf, 0xbf }, { 0x00bf, 0xbf }, { 0x00c0, 0xc0 },
/*   char   �         char   �         char   �         char   �         char   � */
{ 0x00c0, 0xc0 }, { 0x00c1, 0xc1 }, { 0x00c1, 0xc1 }, { 0x00c2, 0xc2 }, { 0x00c2, 0xc2 },
/*   char   �         char   �         char   �         char   �         char   � */
{ 0x00c3, 0xc3 }, { 0x00c3, 0xc3 }, { 0x00c4, 0xc4 }, { 0x00c4, 0xc4 }, { 0x00c5, 0xc5 },
/*   char   �         char   �         char   �         char   �         char   � */
{ 0x00c5, 0xc5 }, { 0x00c6, 0xc6 }, { 0x00c6, 0xc6 }, { 0x00c7, 0xc7 }, { 0x00c7, 0xc7 },
/*   char   �         char   �         char   �         char   �         char   � */
{ 0x00c8, 0xc8 }, { 0x00c8, 0xc8 }, { 0x00c9, 0xc9 }, { 0x00c9, 0xc9 }, { 0x00ca, 0xca },
/*   char   �         char   �         char   �         char   �         char   � */
{ 0x00ca, 0xca }, { 0x00cb, 0xcb }, { 0x00cb, 0xcb }, { 0x00cc, 0xcc }, { 0x00cc, 0xcc },
/*   char   �         char   �         char   �         char   �         char   � */
{ 0x00cd, 0xcd }, { 0x00cd, 0xcd }, { 0x00ce, 0xce }, { 0x00ce, 0xce }, { 0x00cf, 0xcf },
/*   char   �         char   �         char   �         char   �         char   � */
{ 0x00cf, 0xcf }, { 0x00d0, 0xd0 }, { 0x00d0, 0xd0 }, { 0x00d1, 0xd1 }, { 0x00d1, 0xd1 },
/*   char   �         char   �         char   �         char   �         char   � */
{ 0x00d2, 0xd2 }, { 0x00d2, 0xd2 }, { 0x00d3, 0xd3 }, { 0x00d3, 0xd3 }, { 0x00d4, 0xd4 },
/*   char   �         char   �         char   �         char   �         char   � */
{ 0x00d4, 0xd4 }, { 0x00d5, 0xd5 }, { 0x00d5, 0xd5 }, { 0x00d6, 0xd6 }, { 0x00d6, 0xd6 },
/*   char   �         char   �         char   �         char   �         char   � */
{ 0x00d7, 0xd7 }, { 0x00d7, 0xd7 }, { 0x00d8, 0xd8 }, { 0x00d8, 0xd8 }, { 0x00d9, 0xd9 },
/*   char   �         char   �         char   �         char   �         char   � */
{ 0x00d9, 0xd9 }, { 0x00da, 0xda }, { 0x00da, 0xda }, { 0x00db, 0xdb }, { 0x00db, 0xdb },
/*   char   �         char   �         char   �         char   �         char   � */
{ 0x00dc, 0xdc }, { 0x00dc, 0xdc }, { 0x00dd, 0xdd }, { 0x00dd, 0xdd }, { 0x00de, 0xde },
/*   char   �         char   �         char   �         char   �         char   � */
{ 0x00de, 0xde }, { 0x00df, 0xdf }, { 0x00df, 0xdf }, { 0x00e0, 0xe0 }, { 0x00e0, 0xe0 },
/*   char   �         char   �         char   �         char   �         char   � */
{ 0x00e1, 0xe1 }, { 0x00e1, 0xe1 }, { 0x00e2, 0xe2 }, { 0x00e2, 0xe2 }, { 0x00e3, 0xe3 },
/*   char   �         char   �         char   �         char   �         char   � */
{ 0x00e3, 0xe3 }, { 0x00e4, 0xe4 }, { 0x00e4, 0xe4 }, { 0x00e5, 0xe5 }, { 0x00e5, 0xe5 },
/*   char   �         char   �         char   �         char   �         char   � */
{ 0x00e6, 0xe6 }, { 0x00e6, 0xe6 }, { 0x00e7, 0xe7 }, { 0x00e7, 0xe7 }, { 0x00e8, 0xe8 },
/*   char   �         char   �         char   �         char   �         char   � */
{ 0x00e8, 0xe8 }, { 0x00e9, 0xe9 }, { 0x00e9, 0xe9 }, { 0x00ea, 0xea }, { 0x00ea, 0xea },
/*   char   �         char   �         char   �         char   �         char   � */
{ 0x00eb, 0xeb }, { 0x00eb, 0xeb }, { 0x00ec, 0xec }, { 0x00ec, 0xec }, { 0x00ed, 0xed },
/*   char   �         char   �         char   �         char   �         char   � */
{ 0x00ed, 0xed }, { 0x00ee, 0xee }, { 0x00ee, 0xee }, { 0x00ef, 0xef }, { 0x00ef, 0xef },
/*   char   �         char   �         char   �         char   �         char   � */
{ 0x00f0, 0xf0 }, { 0x00f0, 0xf0 }, { 0x00f1, 0xf1 }, { 0x00f1, 0xf1 }, { 0x00f2, 0xf2 },
/*   char   �         char   �         char   �         char   �         char   � */
{ 0x00f2, 0xf2 }, { 0x00f3, 0xf3 }, { 0x00f3, 0xf3 }, { 0x00f4, 0xf4 }, { 0x00f4, 0xf4 },
/*   char   �         char   �         char   �         char   �         char   � */
{ 0x00f5, 0xf5 }, { 0x00f5, 0xf5 }, { 0x00f6, 0xf6 }, { 0x00f6, 0xf6 }, { 0x00f7, 0xf7 },
/*   char   �         char   �         char   �         char   �         char   � */
{ 0x00f7, 0xf7 }, { 0x00f8, 0xf8 }, { 0x00f8, 0xf8 }, { 0x00f9, 0xf9 }, { 0x00f9, 0xf9 },
/*   char   �         char   �         char   �         char   �         char   � */
{ 0x00fa, 0xfa }, { 0x00fa, 0xfa }, { 0x00fb, 0xfb }, { 0x00fb, 0xfb }, { 0x00fc, 0xfc },
/*   char   �         char   �         char   �         char   �         char   � */
{ 0x00fc, 0xfc }, { 0x00fd, 0xfd }, { 0x00fd, 0xfd }, { 0x00fe, 0xfe }, { 0x00fe, 0xfe },
/*   char   �         char   �         char   A         char   A         char   a */
{ 0x00ff, 0xff }, { 0x00ff, 0xff }, { 0x0100, 0x41 }, { 0x0100, 0x41 }, { 0x0101, 0x61 },
/*   char   a         char   A         char   A         char   a         char   a */
{ 0x0101, 0x61 }, { 0x0102, 0x41 }, { 0x0102, 0x41 }, { 0x0103, 0x61 }, { 0x0103, 0x61 },
/*   char   A         char   A         char   a         char   a         char   C */
{ 0x0104, 0x41 }, { 0x0104, 0x41 }, { 0x0105, 0x61 }, { 0x0105, 0x61 }, { 0x0106, 0x43 },
/*   char   C         char   c         char   c         char   C         char   C */
{ 0x0106, 0x43 }, { 0x0107, 0x63 }, { 0x0107, 0x63 }, { 0x0108, 0x43 }, { 0x0108, 0x43 },
/*   char   c         char   c         char   C         char   C         char   c */
{ 0x0109, 0x63 }, { 0x0109, 0x63 }, { 0x010a, 0x43 }, { 0x010a, 0x43 }, { 0x010b, 0x63 },
/*   char   c         char   C         char   C         char   c         char   c */
{ 0x010b, 0x63 }, { 0x010c, 0x43 }, { 0x010c, 0x43 }, { 0x010d, 0x63 }, { 0x010d, 0x63 },
/*   char   D         char   D         char   d         char   d         char   � */
{ 0x010e, 0x44 }, { 0x010e, 0x44 }, { 0x010f, 0x64 }, { 0x010f, 0x64 }, { 0x0110, 0xd0 },
/*   char   �         char   d         char   d         char   E         char   E */
{ 0x0110, 0xd0 }, { 0x0111, 0x64 }, { 0x0111, 0x64 }, { 0x0112, 0x45 }, { 0x0112, 0x45 },
/*   char   e         char   e         char   E         char   E         char   e */
{ 0x0113, 0x65 }, { 0x0113, 0x65 }, { 0x0114, 0x45 }, { 0x0114, 0x45 }, { 0x0115, 0x65 },
/*   char   e         char   E         char   E         char   e         char   e */
{ 0x0115, 0x65 }, { 0x0116, 0x45 }, { 0x0116, 0x45 }, { 0x0117, 0x65 }, { 0x0117, 0x65 },
/*   char   E         char   E         char   e         char   e         char   E */
{ 0x0118, 0x45 }, { 0x0118, 0x45 }, { 0x0119, 0x65 }, { 0x0119, 0x65 }, { 0x011a, 0x45 },
/*   char   E         char   e         char   e         char   G         char   G */
{ 0x011a, 0x45 }, { 0x011b, 0x65 }, { 0x011b, 0x65 }, { 0x011c, 0x47 }, { 0x011c, 0x47 },
/*   char   g         char   g         char   G         char   G         char   g */
{ 0x011d, 0x67 }, { 0x011d, 0x67 }, { 0x011e, 0x47 }, { 0x011e, 0x47 }, { 0x011f, 0x67 },
/*   char   g         char   G         char   G         char   g         char   g */
{ 0x011f, 0x67 }, { 0x0120, 0x47 }, { 0x0120, 0x47 }, { 0x0121, 0x67 }, { 0x0121, 0x67 },
/*   char   G         char   G         char   g         char   g         char   H */
{ 0x0122, 0x47 }, { 0x0122, 0x47 }, { 0x0123, 0x67 }, { 0x0123, 0x67 }, { 0x0124, 0x48 },
/*   char   H         char   h         char   h         char   H         char   H */
{ 0x0124, 0x48 }, { 0x0125, 0x68 }, { 0x0125, 0x68 }, { 0x0126, 0x48 }, { 0x0126, 0x48 },
/*   char   h         char   h         char   I         char   I         char   i */
{ 0x0127, 0x68 }, { 0x0127, 0x68 }, { 0x0128, 0x49 }, { 0x0128, 0x49 }, { 0x0129, 0x69 },
/*   char   i         char   I         char   I         char   i         char   i */
{ 0x0129, 0x69 }, { 0x012a, 0x49 }, { 0x012a, 0x49 }, { 0x012b, 0x69 }, { 0x012b, 0x69 },
/*   char   I         char   I         char   i         char   i         char   I */
{ 0x012c, 0x49 }, { 0x012c, 0x49 }, { 0x012d, 0x69 }, { 0x012d, 0x69 }, { 0x012e, 0x49 },
/*   char   I         char   i         char   i         char   I         char   I */
{ 0x012e, 0x49 }, { 0x012f, 0x69 }, { 0x012f, 0x69 }, { 0x0130, 0x49 }, { 0x0130, 0x49 },
/*   char   i         char   i         char   J         char   J         char   j */
{ 0x0131, 0x69 }, { 0x0131, 0x69 }, { 0x0134, 0x4a }, { 0x0134, 0x4a }, { 0x0135, 0x6a },
/*   char   j         char   K         char   K         char   k         char   k */
{ 0x0135, 0x6a }, { 0x0136, 0x4b }, { 0x0136, 0x4b }, { 0x0137, 0x6b }, { 0x0137, 0x6b },
/*   char   L         char   L         char   l         char   l         char   L */
{ 0x0139, 0x4c }, { 0x0139, 0x4c }, { 0x013a, 0x6c }, { 0x013a, 0x6c }, { 0x013b, 0x4c },
/*   char   L         char   l         char   l         char   L         char   L */
{ 0x013b, 0x4c }, { 0x013c, 0x6c }, { 0x013c, 0x6c }, { 0x013d, 0x4c }, { 0x013d, 0x4c },
/*   char   l         char   l         char   L         char   L         char   l */
{ 0x013e, 0x6c }, { 0x013e, 0x6c }, { 0x0141, 0x4c }, { 0x0141, 0x4c }, { 0x0142, 0x6c },
/*   char   l         char   N         char   N         char   n         char   n */
{ 0x0142, 0x6c }, { 0x0143, 0x4e }, { 0x0143, 0x4e }, { 0x0144, 0x6e }, { 0x0144, 0x6e },
/*   char   N         char   N         char   n         char   n         char   N */
{ 0x0145, 0x4e }, { 0x0145, 0x4e }, { 0x0146, 0x6e }, { 0x0146, 0x6e }, { 0x0147, 0x4e },
/*   char   N         char   n         char   n         char   O         char   O */
{ 0x0147, 0x4e }, { 0x0148, 0x6e }, { 0x0148, 0x6e }, { 0x014c, 0x4f }, { 0x014c, 0x4f },
/*   char   o         char   o         char   O         char   O         char   o */
{ 0x014d, 0x6f }, { 0x014d, 0x6f }, { 0x014e, 0x4f }, { 0x014e, 0x4f }, { 0x014f, 0x6f },
/*   char   o         char   O         char   O         char   o         char   o */
{ 0x014f, 0x6f }, { 0x0150, 0x4f }, { 0x0150, 0x4f }, { 0x0151, 0x6f }, { 0x0151, 0x6f },
/*   char   �         char   �         char   �         char   �         char   R */
{ 0x0152, 0x8c }, { 0x0152, 0x8c }, { 0x0153, 0x9c }, { 0x0153, 0x9c }, { 0x0154, 0x52 },
/*   char   R         char   r         char   r         char   R         char   R */
{ 0x0154, 0x52 }, { 0x0155, 0x72 }, { 0x0155, 0x72 }, { 0x0156, 0x52 }, { 0x0156, 0x52 },
/*   char   r         char   r         char   R         char   R         char   r */
{ 0x0157, 0x72 }, { 0x0157, 0x72 }, { 0x0158, 0x52 }, { 0x0158, 0x52 }, { 0x0159, 0x72 },
/*   char   r         char   S         char   S         char   s         char   s */
{ 0x0159, 0x72 }, { 0x015a, 0x53 }, { 0x015a, 0x53 }, { 0x015b, 0x73 }, { 0x015b, 0x73 },
/*   char   S         char   S         char   s         char   s         char   S */
{ 0x015c, 0x53 }, { 0x015c, 0x53 }, { 0x015d, 0x73 }, { 0x015d, 0x73 }, { 0x015e, 0x53 },
/*   char   S         char   s         char   s         char   �         char   � */
{ 0x015e, 0x53 }, { 0x015f, 0x73 }, { 0x015f, 0x73 }, { 0x0160, 0x8a }, { 0x0160, 0x8a },
/*   char   �         char   �         char   T         char   T         char   t */
{ 0x0161, 0x9a }, { 0x0161, 0x9a }, { 0x0162, 0x54 }, { 0x0162, 0x54 }, { 0x0163, 0x74 },
/*   char   t         char   T         char   T         char   t         char   t */
{ 0x0163, 0x74 }, { 0x0164, 0x54 }, { 0x0164, 0x54 }, { 0x0165, 0x74 }, { 0x0165, 0x74 },
/*   char   T         char   T         char   t         char   t         char   U */
{ 0x0166, 0x54 }, { 0x0166, 0x54 }, { 0x0167, 0x74 }, { 0x0167, 0x74 }, { 0x0168, 0x55 },
/*   char   U         char   u         char   u         char   U         char   U */
{ 0x0168, 0x55 }, { 0x0169, 0x75 }, { 0x0169, 0x75 }, { 0x016a, 0x55 }, { 0x016a, 0x55 },
/*   char   u         char   u         char   U         char   U         char   u */
{ 0x016b, 0x75 }, { 0x016b, 0x75 }, { 0x016c, 0x55 }, { 0x016c, 0x55 }, { 0x016d, 0x75 },
/*   char   u         char   U         char   U         char   u         char   u */
{ 0x016d, 0x75 }, { 0x016e, 0x55 }, { 0x016e, 0x55 }, { 0x016f, 0x75 }, { 0x016f, 0x75 },
/*   char   U         char   U         char   u         char   u         char   U */
{ 0x0170, 0x55 }, { 0x0170, 0x55 }, { 0x0171, 0x75 }, { 0x0171, 0x75 }, { 0x0172, 0x55 },
/*   char   U         char   u         char   u         char   W         char   W */
{ 0x0172, 0x55 }, { 0x0173, 0x75 }, { 0x0173, 0x75 }, { 0x0174, 0x57 }, { 0x0174, 0x57 },
/*   char   w         char   w         char   Y         char   Y         char   y */
{ 0x0175, 0x77 }, { 0x0175, 0x77 }, { 0x0176, 0x59 }, { 0x0176, 0x59 }, { 0x0177, 0x79 },
/*   char   y         char   �         char   �         char   Z         char   Z */
{ 0x0177, 0x79 }, { 0x0178, 0x9f }, { 0x0178, 0x9f }, { 0x0179, 0x5a }, { 0x0179, 0x5a },
/*   char   z         char   z         char   Z         char   Z         char   z */
{ 0x017a, 0x7a }, { 0x017a, 0x7a }, { 0x017b, 0x5a }, { 0x017b, 0x5a }, { 0x017c, 0x7a },
/*   char   z         char   �         char   �         char   �         char   � */
{ 0x017c, 0x7a }, { 0x017d, 0x8e }, { 0x017d, 0x8e }, { 0x017e, 0x9e }, { 0x017e, 0x9e },
/*   char   b         char   b         char   �         char   �         char   � */
{ 0x0180, 0x62 }, { 0x0180, 0x62 }, { 0x0189, 0xd0 }, { 0x0189, 0xd0 }, { 0x0191, 0x83 },
/*   char   �         char   �         char   �         char   I         char   I */
{ 0x0191, 0x83 }, { 0x0192, 0x83 }, { 0x0192, 0x83 }, { 0x0197, 0x49 }, { 0x0197, 0x49 },
/*   char   l         char   l         char   O         char   O         char   O */
{ 0x019a, 0x6c }, { 0x019a, 0x6c }, { 0x019f, 0x4f }, { 0x019f, 0x4f }, { 0x01a0, 0x4f },
/*   char   O         char   o         char   o         char   t         char   t */
{ 0x01a0, 0x4f }, { 0x01a1, 0x6f }, { 0x01a1, 0x6f }, { 0x01ab, 0x74 }, { 0x01ab, 0x74 },
/*   char   T         char   T         char   U         char   U         char   u */
{ 0x01ae, 0x54 }, { 0x01ae, 0x54 }, { 0x01af, 0x55 }, { 0x01af, 0x55 }, { 0x01b0, 0x75 },
/*   char   u         char   z         char   z         char   |         char   | */
{ 0x01b0, 0x75 }, { 0x01b6, 0x7a }, { 0x01b6, 0x7a }, { 0x01c0, 0x7c }, { 0x01c0, 0x7c },
/*   char   !         char   !         char   A         char   A         char   a */
{ 0x01c3, 0x21 }, { 0x01c3, 0x21 }, { 0x01cd, 0x41 }, { 0x01cd, 0x41 }, { 0x01ce, 0x61 },
/*   char   a         char   I         char   I         char   i         char   i */
{ 0x01ce, 0x61 }, { 0x01cf, 0x49 }, { 0x01cf, 0x49 }, { 0x01d0, 0x69 }, { 0x01d0, 0x69 },
/*   char   O         char   O         char   o         char   o         char   U */
{ 0x01d1, 0x4f }, { 0x01d1, 0x4f }, { 0x01d2, 0x6f }, { 0x01d2, 0x6f }, { 0x01d3, 0x55 },
/*   char   U         char   u         char   u         char   U         char   U */
{ 0x01d3, 0x55 }, { 0x01d4, 0x75 }, { 0x01d4, 0x75 }, { 0x01d5, 0x55 }, { 0x01d5, 0x55 },
/*   char   u         char   u         char   U         char   U         char   u */
{ 0x01d6, 0x75 }, { 0x01d6, 0x75 }, { 0x01d7, 0x55 }, { 0x01d7, 0x55 }, { 0x01d8, 0x75 },
/*   char   u         char   U         char   U         char   u         char   u */
{ 0x01d8, 0x75 }, { 0x01d9, 0x55 }, { 0x01d9, 0x55 }, { 0x01da, 0x75 }, { 0x01da, 0x75 },
/*   char   U         char   U         char   u         char   u         char   A */
{ 0x01db, 0x55 }, { 0x01db, 0x55 }, { 0x01dc, 0x75 }, { 0x01dc, 0x75 }, { 0x01de, 0x41 },
/*   char   A         char   a         char   a         char   G         char   G */
{ 0x01de, 0x41 }, { 0x01df, 0x61 }, { 0x01df, 0x61 }, { 0x01e4, 0x47 }, { 0x01e4, 0x47 },
/*   char   g         char   g         char   G         char   G         char   g */
{ 0x01e5, 0x67 }, { 0x01e5, 0x67 }, { 0x01e6, 0x47 }, { 0x01e6, 0x47 }, { 0x01e7, 0x67 },
/*   char   g         char   K         char   K         char   k         char   k */
{ 0x01e7, 0x67 }, { 0x01e8, 0x4b }, { 0x01e8, 0x4b }, { 0x01e9, 0x6b }, { 0x01e9, 0x6b },
/*   char   O         char   O         char   o         char   o         char   O */
{ 0x01ea, 0x4f }, { 0x01ea, 0x4f }, { 0x01eb, 0x6f }, { 0x01eb, 0x6f }, { 0x01ec, 0x4f },
/*   char   O         char   o         char   o         char   j         char   j */
{ 0x01ec, 0x4f }, { 0x01ed, 0x6f }, { 0x01ed, 0x6f }, { 0x01f0, 0x6a }, { 0x01f0, 0x6a },
/*   char   g         char   g         char   '         char   '         char   " */
{ 0x0261, 0x67 }, { 0x0261, 0x67 }, { 0x02b9, 0x27 }, { 0x02b9, 0x27 }, { 0x02ba, 0x22 },
/*   char   "         char   '         char   '         char   ^         char   ^ */
{ 0x02ba, 0x22 }, { 0x02bc, 0x27 }, { 0x02bc, 0x27 }, { 0x02c4, 0x5e }, { 0x02c4, 0x5e },
/*   char   �         char   �         char   '         char   '         char   � */
{ 0x02c6, 0x88 }, { 0x02c6, 0x88 }, { 0x02c8, 0x27 }, { 0x02c8, 0x27 }, { 0x02c9, 0xaf },
/*   char   �         char   �         char   �         char   `         char   ` */
{ 0x02c9, 0xaf }, { 0x02ca, 0xb4 }, { 0x02ca, 0xb4 }, { 0x02cb, 0x60 }, { 0x02cb, 0x60 },
/*   char   _         char   _         char   �         char   �         char   � */
{ 0x02cd, 0x5f }, { 0x02cd, 0x5f }, { 0x02da, 0xb0 }, { 0x02da, 0xb0 }, { 0x02dc, 0x98 },
/*   char   �         char   `         char   `         char   �         char   � */
{ 0x02dc, 0x98 }, { 0x0300, 0x60 }, { 0x0300, 0x60 }, { 0x0301, 0xb4 }, { 0x0301, 0xb4 },
/*   char   ^         char   ^         char   ~         char   ~         char   � */
{ 0x0302, 0x5e }, { 0x0302, 0x5e }, { 0x0303, 0x7e }, { 0x0303, 0x7e }, { 0x0304, 0xaf },
/*   char   �         char   �         char   �         char   �         char   � */
{ 0x0304, 0xaf }, { 0x0305, 0xaf }, { 0x0305, 0xaf }, { 0x0308, 0xa8 }, { 0x0308, 0xa8 },
/*   char   �         char   �         char   "         char   "         char   � */
{ 0x030a, 0xb0 }, { 0x030a, 0xb0 }, { 0x030e, 0x22 }, { 0x030e, 0x22 }, { 0x0327, 0xb8 },
/*   char   �         char   _         char   _         char   _         char   _ */
{ 0x0327, 0xb8 }, { 0x0331, 0x5f }, { 0x0331, 0x5f }, { 0x0332, 0x5f }, { 0x0332, 0x5f },
/*   char   ;         char   ;         char   G         char   G         char   T */
{ 0x037e, 0x3b }, { 0x037e, 0x3b }, { 0x0393, 0x47 }, { 0x0393, 0x47 }, { 0x0398, 0x54 },
/*   char   T         char   S         char   S         char   F         char   F */
{ 0x0398, 0x54 }, { 0x03a3, 0x53 }, { 0x03a3, 0x53 }, { 0x03a6, 0x46 }, { 0x03a6, 0x46 },
/*   char   O         char   O         char   a         char   a         char   � */
{ 0x03a9, 0x4f }, { 0x03a9, 0x4f }, { 0x03b1, 0x61 }, { 0x03b1, 0x61 }, { 0x03b2, 0xdf },
/*   char   �         char   d         char   d         char   e         char   e */
{ 0x03b2, 0xdf }, { 0x03b4, 0x64 }, { 0x03b4, 0x64 }, { 0x03b5, 0x65 }, { 0x03b5, 0x65 },
/*   char   �         char   �         char   p         char   p         char   s */
{ 0x03bc, 0xb5 }, { 0x03bc, 0xb5 }, { 0x03c0, 0x70 }, { 0x03c0, 0x70 }, { 0x03c3, 0x73 },
/*   char   s         char   t         char   t         char   f         char   f */
{ 0x03c3, 0x73 }, { 0x03c4, 0x74 }, { 0x03c4, 0x74 }, { 0x03c6, 0x66 }, { 0x03c6, 0x66 },
/*   char   h         char   h         char   :         char   :         char   % */
{ 0x04bb, 0x68 }, { 0x04bb, 0x68 }, { 0x0589, 0x3a }, { 0x0589, 0x3a }, { 0x066a, 0x25 },
/*   char   %         char   +         char   +         char   +         char   + */
{ 0x066a, 0x25 }, { 0x2000, 0x2b }, { 0x2001, 0x2b }, { 0x2002, 0x2b }, { 0x2003, 0x2b },
/*   char   +         char   +         char   +         char   -         char   - */
{ 0x2004, 0x2b }, { 0x2005, 0x2b }, { 0x2006, 0x2b }, { 0x2010, 0x2d }, { 0x2011, 0x2d },
/*   char   �         char   �         char   =         char   �         char   � */
{ 0x2013, 0x96 }, { 0x2014, 0x97 }, { 0x2017, 0x3d }, { 0x2018, 0x91 }, { 0x2019, 0x92 },
/*   char   �         char   �         char   �         char   �         char   � */
{ 0x201a, 0x82 }, { 0x201c, 0x93 }, { 0x201d, 0x94 }, { 0x201e, 0x84 }, { 0x2020, 0x86 },
/*   char   �         char   �         char   �         char   �         char   � */
{ 0x2021, 0x87 }, { 0x2022, 0x95 }, { 0x2024, 0xb7 }, { 0x2026, 0x85 }, { 0x2030, 0x89 },
/*   char   '         char   `         char   �         char   �         char    */
{ 0x2032, 0x27 }, { 0x2035, 0x60 }, { 0x2039, 0x8b }, { 0x203a, 0x9b }, { 0x2044, 0x2f },
/*   char   �         char   4         char   5         char   6         char   7 */
{ 0x2070, 0xb0 }, { 0x2074, 0x34 }, { 0x2075, 0x35 }, { 0x2076, 0x36 }, { 0x2077, 0x37 },
/*   char   8         char   n         char   0         char   1         char   2 */
{ 0x2078, 0x38 }, { 0x207f, 0x6e }, { 0x2080, 0x30 }, { 0x2081, 0x31 }, { 0x2082, 0x32 },
/*   char   3         char   4         char   5         char   6         char   7 */
{ 0x2083, 0x33 }, { 0x2084, 0x34 }, { 0x2085, 0x35 }, { 0x2086, 0x36 }, { 0x2087, 0x37 },
/*   char   8         char   9         char   �         char   �         char   P */
{ 0x2088, 0x38 }, { 0x2089, 0x39 }, { 0x20a1, 0xa2 }, { 0x20a4, 0xa3 }, { 0x20a7, 0x50 },
/*   char   �         char   C         char   E         char   g         char   H */
{ 0x20ac, 0x80 }, { 0x2102, 0x43 }, { 0x2107, 0x45 }, { 0x210a, 0x67 }, { 0x210b, 0x48 },
/*   char   H         char   H         char   h         char   I         char   I */
{ 0x210c, 0x48 }, { 0x210d, 0x48 }, { 0x210e, 0x68 }, { 0x2110, 0x49 }, { 0x2111, 0x49 },
/*   char   L         char   l         char   N         char   P         char   P */
{ 0x2112, 0x4c }, { 0x2113, 0x6c }, { 0x2115, 0x4e }, { 0x2118, 0x50 }, { 0x2119, 0x50 },
/*   char   Q         char   R         char   R         char   R         char   � */
{ 0x211a, 0x51 }, { 0x211b, 0x52 }, { 0x211c, 0x52 }, { 0x211d, 0x52 }, { 0x2122, 0x99 },
/*   char   Z         char   Z         char   K         char   �         char   B */
{ 0x2124, 0x5a }, { 0x2128, 0x5a }, { 0x212a, 0x4b }, { 0x212b, 0xc5 }, { 0x212c, 0x42 },
/*   char   C         char   e         char   e         char   E         char   F */
{ 0x212d, 0x43 }, { 0x212e, 0x65 }, { 0x212f, 0x65 }, { 0x2130, 0x45 }, { 0x2131, 0x46 },
/*   char   M         char   o         char   �         char   -         char   � */
{ 0x2133, 0x4d }, { 0x2134, 0x6f }, { 0x2205, 0xd8 }, { 0x2212, 0x2d }, { 0x2213, 0xb1 },
/*   char    /         char    *         char   �         char   �         char   v */
{ 0x2215, 0x2f }, { 0x2217, 0x2a }, { 0x2218, 0xb0 }, { 0x2219, 0xb7 }, { 0x221a, 0x76 },
/*   char   8         char   |         char   n         char   :         char   ~ */
{ 0x221e, 0x38 }, { 0x2223, 0x7c }, { 0x2229, 0x6e }, { 0x2236, 0x3a }, { 0x223c, 0x7e },
/*   char   �         char   =         char   =         char   =         char   � */
{ 0x2248, 0x98 }, { 0x2261, 0x3d }, { 0x2264, 0x3d }, { 0x2265, 0x3d }, { 0x226a, 0xab },
/*   char   �         char   �         char   �         char   ^         char   � */
{ 0x226b, 0xbb }, { 0x22c5, 0xb7 }, { 0x2302, 0xa6 }, { 0x2303, 0x5e }, { 0x2310, 0xac },
/*   char   (         char   )         char   <         char   >         char   - */
{ 0x2320, 0x28 }, { 0x2321, 0x29 }, { 0x2329, 0x3c }, { 0x232a, 0x3e }, { 0x2500, 0x2d },
/*   char   �         char   +         char   +         char   +         char   + */
{ 0x2502, 0xa6 }, { 0x250c, 0x2b }, { 0x2510, 0x2b }, { 0x2514, 0x2b }, { 0x2518, 0x2b },
/*   char   +         char   �         char   -         char   -         char   + */
{ 0x251c, 0x2b }, { 0x2524, 0xa6 }, { 0x252c, 0x2d }, { 0x2534, 0x2d }, { 0x253c, 0x2b },
/*   char   -         char   �         char   +         char   +         char   + */
{ 0x2550, 0x2d }, { 0x2551, 0xa6 }, { 0x2552, 0x2b }, { 0x2553, 0x2b }, { 0x2554, 0x2b },
/*   char   +         char   +         char   +         char   +         char   + */
{ 0x2555, 0x2b }, { 0x2556, 0x2b }, { 0x2557, 0x2b }, { 0x2558, 0x2b }, { 0x2559, 0x2b },
/*   char   +         char   +         char   +         char   +         char   � */
{ 0x255a, 0x2b }, { 0x255b, 0x2b }, { 0x255c, 0x2b }, { 0x255d, 0x2b }, { 0x255e, 0xa6 },
/*   char   �         char   �         char   �         char   �         char   � */
{ 0x255f, 0xa6 }, { 0x2560, 0xa6 }, { 0x2561, 0xa6 }, { 0x2562, 0xa6 }, { 0x2563, 0xa6 },
/*   char   -         char   -         char   -         char   -         char   - */
{ 0x2564, 0x2d }, { 0x2565, 0x2d }, { 0x2566, 0x2d }, { 0x2567, 0x2d }, { 0x2568, 0x2d },
/*   char   -         char   +         char   +         char   +         char   � */
{ 0x2569, 0x2d }, { 0x256a, 0x2b }, { 0x256b, 0x2b }, { 0x256c, 0x2b }, { 0x2580, 0xaf },
/*   char   _         char   �         char   �         char   �         char   � */
{ 0x2584, 0x5f }, { 0x2588, 0xa6 }, { 0x258c, 0xa6 }, { 0x2590, 0xa6 }, { 0x2591, 0xa6 },
/*   char   �         char   �         char   �         char   �         char   | */
{ 0x2592, 0xa6 }, { 0x2593, 0xa6 }, { 0x25a0, 0xa6 }, { 0x263c, 0xa4 }, { 0x2758, 0x7c },
/*   char   +         char   <         char   >         char   �         char   � */
{ 0x3000, 0x2b }, { 0x3008, 0x3c }, { 0x3009, 0x3e }, { 0x300a, 0xab }, { 0x300b, 0xbb },
/*   char   [         char   ]         char   �         char   !         char   " */
{ 0x301a, 0x5b }, { 0x301b, 0x5d }, { 0x30fb, 0xb7 }, { 0xff01, 0x21 }, { 0xff02, 0x22 },
/*   char   #         char   $         char   %         char   &         char   ' */
{ 0xff03, 0x23 }, { 0xff04, 0x24 }, { 0xff05, 0x25 }, { 0xff06, 0x26 }, { 0xff07, 0x27 },
/*   char   (         char   )         char    *         char   +         char   , */
{ 0xff08, 0x28 }, { 0xff09, 0x29 }, { 0xff0a, 0x2a }, { 0xff0b, 0x2b }, { 0xff0c, 0x2c },
/*   char   -         char   .         char            char   0         char   1 */
{ 0xff0d, 0x2d }, { 0xff0e, 0x2e }, { 0xff0f, 0x2f }, { 0xff10, 0x30 }, { 0xff11, 0x31 },
/*   char   2         char   3         char   4         char   5         char   6 */
{ 0xff12, 0x32 }, { 0xff13, 0x33 }, { 0xff14, 0x34 }, { 0xff15, 0x35 }, { 0xff16, 0x36 },
/*   char   7         char   8         char   9         char   :         char   ; */
{ 0xff17, 0x37 }, { 0xff18, 0x38 }, { 0xff19, 0x39 }, { 0xff1a, 0x3a }, { 0xff1b, 0x3b },
/*   char   <         char   =         char   >         char   @         char   A */
{ 0xff1c, 0x3c }, { 0xff1d, 0x3d }, { 0xff1e, 0x3e }, { 0xff20, 0x40 }, { 0xff21, 0x41 },
/*   char   B         char   C         char   D         char   E         char   F */
{ 0xff22, 0x42 }, { 0xff23, 0x43 }, { 0xff24, 0x44 }, { 0xff25, 0x45 }, { 0xff26, 0x46 },
/*   char   G         char   H         char   I         char   J         char   K */
{ 0xff27, 0x47 }, { 0xff28, 0x48 }, { 0xff29, 0x49 }, { 0xff2a, 0x4a }, { 0xff2b, 0x4b },
/*   char   L         char   M         char   N         char   O         char   P */
{ 0xff2c, 0x4c }, { 0xff2d, 0x4d }, { 0xff2e, 0x4e }, { 0xff2f, 0x4f }, { 0xff30, 0x50 },
/*   char   Q         char   R         char   S         char   T         char   U */
{ 0xff31, 0x51 }, { 0xff32, 0x52 }, { 0xff33, 0x53 }, { 0xff34, 0x54 }, { 0xff35, 0x55 },
/*   char   V         char   W         char   X         char   Y         char   Z */
{ 0xff36, 0x56 }, { 0xff37, 0x57 }, { 0xff38, 0x58 }, { 0xff39, 0x59 }, { 0xff3a, 0x5a },
/*   char   [         char   ]         char   ^         char   _         char   ` */
{ 0xff3b, 0x5b }, { 0xff3d, 0x5d }, { 0xff3e, 0x5e }, { 0xff3f, 0x5f }, { 0xff40, 0x60 },
/*   char   a         char   b         char   c         char   d         char   e */
{ 0xff41, 0x61 }, { 0xff42, 0x62 }, { 0xff43, 0x63 }, { 0xff44, 0x64 }, { 0xff45, 0x65 },
/*   char   f         char   g         char   h         char   i         char   j */
{ 0xff46, 0x66 }, { 0xff47, 0x67 }, { 0xff48, 0x68 }, { 0xff49, 0x69 }, { 0xff4a, 0x6a },
/*   char   k         char   l         char   m         char   n         char   o */
{ 0xff4b, 0x6b }, { 0xff4c, 0x6c }, { 0xff4d, 0x6d }, { 0xff4e, 0x6e }, { 0xff4f, 0x6f },
/*   char   p         char   q         char   r         char   s         char   t */
{ 0xff50, 0x70 }, { 0xff51, 0x71 }, { 0xff52, 0x72 }, { 0xff53, 0x73 }, { 0xff54, 0x74 },
/*   char   u         char   v         char   w         char   x         char   y */
{ 0xff55, 0x75 }, { 0xff56, 0x76 }, { 0xff57, 0x77 }, { 0xff58, 0x78 }, { 0xff59, 0x79 },
/*   char   z         char   {         char   |         char   }         char   ~ */
{ 0xff5a, 0x7a }, { 0xff5b, 0x7b }, { 0xff5c, 0x7c }, { 0xff5d, 0x7d }, { 0xff5e, 0x7e },
/* end-of-array marker */
{ 0, 0 }    };

/************************************************
* Set the values
************************************************/
void init_codes(){
	int i;
    unicode_entry *ptr;
	
	for (i=0;i<65536;i++)
		codes[i]=0x0;  /*question mark*/
	
	/*the first 128 entries are the same as ascii*/
	for (i=0;i<128;i++)
		codes[i] = (char) i;
	
    ptr=unicode_data;
    while(ptr->index != 0) {
        codes[ptr->index] = (char) ptr->val;
        ptr++;
    }


}