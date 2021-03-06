//
// The developer of the original code and/or files is Tripwire, Inc.
// Portions created by Tripwire, Inc. are copyright (C) 2000 Tripwire,
// Inc. Tripwire is a registered trademark of Tripwire, Inc.  All rights
// reserved.
// 
// This program is free software.  The contents of this file are subject
// to the terms of the GNU General Public License as published by the
// Free Software Foundation; either version 2 of the License, or (at your
// option) any later version.  You may redistribute it and/or modify it
// only in compliance with the GNU General Public License.
// 
// This program is distributed in the hope that it will be useful.
// However, this program is distributed AS-IS WITHOUT ANY
// WARRANTY; INCLUDING THE IMPLIED WARRANTY OF MERCHANTABILITY OR FITNESS
// FOR A PARTICULAR PURPOSE.  Please see the GNU General Public License
// for more details.
// 
// You should have received a copy of the GNU General Public License
// along with this program; if not, write to the Free Software
// Foundation, Inc., 59 Temple Place - Suite 330, Boston, MA 02111-1307,
// USA.
// 
// Nothing in the GNU General Public License or any other license to use
// the code or files shall permit you to use Tripwire's trademarks,
// service marks, or other intellectual property without Tripwire's
// prior written consent.
// 
// If you have any questions, please contact Tripwire, Inc. at either
// info@tripwire.org or www.tripwire.org.
//
//
// Name....: twadminstrings.h
// Date....: 05/11/99
// Creator.: Brian McFeely (bmcfeely)
//

#ifndef __TWADMINSTRINGS_H
#define __TWADMINSTRINGS_H

#include "twadmin.h"    // for: STRINGTABLE syntax

//--Message Keys

TSS_BeginStringIds( twadmin )

    STR_TWADMIN_VERSION,
    STR_TWADMIN_USAGE_SUMMARY,
	STR_TWADMIN_HELP_CREATE_CFGFILE,
	STR_TWADMIN_HELP_PRINT_CFGFILE,
	STR_TWADMIN_HELP_CREATE_POLFILE,
	STR_TWADMIN_HELP_PRINT_POLFILE,
	STR_TWADMIN_HELP_REMOVE_ENCRYPTION,
	STR_TWADMIN_HELP_ENCRYPT,
	STR_TWADMIN_HELP_EXAMINE,
	STR_TWADMIN_HELP_GENERATE_KEYS,
    STR_KEYGEN_VERBOSE_OUTPUT_FILES,
    STR_KEYGEN_VERBOSE_PASSPHRASES,
    STR_KEYGEN_VERBOSE_SITEKEY,
    STR_KEYGEN_VERBOSE_LOCALKEY,
    STR_UPCONFIG_VERBOSE_PT_CONFIG,
    STR_UPCONFIG_CREATING_CONFIG,
    STR_UPCONFIG_VERBOSE_PT_POLICY,
	STR_SITEKEYFILE,
	STR_LOCALKEYFILE,
    STR_SITEKEY_EXISTS_1,
    STR_SITEKEY_EXISTS_2,
    STR_LOCALKEY_EXISTS_1,
    STR_LOCALKEY_EXISTS_2,
    STR_KEYFILE_BACKED_UP_AS,
    STR_CONVERTING_FILES,
	STR_EXAMINING_FILE,
	STR_KEYS_DECRYPT,
    STR_BACKUP_EXISTS_1,
    STR_BACKUP_EXISTS_2,
    STR_PASSPHRASE_HINT,
	STR_POL_NOT_UPDATED,
    STR_ENCRYPT_TYPE_NONE,
    STR_ENCRYPT_TYPE_COMP,
    STR_ENCRYPT_TYPE_ASYM,
    STR_ENCRYPT_TYPE_UNK,
    STR_FILE_TYPE_DB,
    STR_FILE_TYPE_REP,
    STR_FILE_TYPE_CFG,
    STR_FILE_TYPE_POL,
    STR_FILE_TYPE_KEY,
    STR_FILE_TYPE_UNK,
    STR_ENTER_SITE_PASS,
    STR_VERIFY_SITE_PASS,
    STR_ENTER_LOCAL_PASS,
    STR_VERIFY_LOCAL_PASS,
    STR_REMOVE_ENCRYPTION_WARNING,
    STR_ENCRYPTION_REMOVED,
    STR_ENCRYPTION_SUCCEEDED,
    STR_FILE,
    STR_ENDQUOTE_NEWLINE,

    // key generation
    STR_GENERATING_KEYS,
    STR_GENERATION_COMPLETE,

    // Extra error strings
    STR_ERR2_NO_PT_CONFIG,
    STR_ERR2_NO_CONFIG,
    STR_ERR2_NO_PT_POLICY,
    STR_ERR2_NO_POLICY,
    STR_ERR2_CONFIG_OPEN,
    STR_ERR2_SITE_KEY_NOENCRYPT_NOT_SPECIFIED,
    STR_ERR2_LOCAL_KEY_NOT_SPECIFIED,
    STR_ERR2_KEYS_NOT_SPECIFIED,
    STR_ERR2_KEY_FILENAMES_IDENTICAL,
    STR_ERR2_SITE_KEY_DOESNT_EXIST,
    STR_ERR2_SITE_KEY_READ_ONLY,
    STR_ERR2_LOCAL_KEY_DOESNT_EXIST,
    STR_ERR2_LOCAL_KEY_READ_ONLY,
    STR_ERR2_COULDNT_RENAME_FILE,
    STR_ERR2_CONVERSION_FILE_READ_ONLY1,
    STR_ERR2_CONVERSION_FILE_READ_ONLY2,
    STR_ERR2_UNABLE_TO_PRINT_POLICY,
    STR_ERR2_CAN_NOT_ENCRYPT_KEYFILE,
    STR_ERR2_CAN_NOT_DECRYPT_KEYFILE,
    STR_ERR2_NO_FILES_SPECIFIED,
    STR_ERR2_LONE_SITE_PASSPHRASE,
    STR_ERR2_LONE_LOCAL_PASSPHRASE,

    STR_ERR2_FILE_DOES_NOT_EXIST,
    STR_ERR2_FILE_COULD_NOT_BE_OPENED,
    STR_ERR2_FILE_COULD_NOT_BE_READ,
    STR_ERR2_FILE_NOT_A_TW_FILE,
    STR_ERR2_FILE_COULD_NOT_BE_EXAMINED,

    //now a ERR1 str STR_ERR2_FILE_TYPE_UNKNOWN, 
    STR_ERR2_ENCODING_TYPE_UNKNOWN,
    STR_ERR2_FILE_NOT_ENCRYPED,
    //STR_ERR2_REMOVE_ENCRYPTION_WARNING,
    STR_ERR2_REMOVE_ENCRYPTION_FAILED,
    //STR_ERR2_ENCRYPTION_REMOVED,
    STR_ERR2_COULD_NOT_OPEN_PROVIDED_KEYFILE,
    STR_ERR2_FILE_ALREADY_ENCRYPTED,
    STR_ERR2_ENCRYPTION_FAILED,
    
    // keygeneration
    STR_ERR2_KEYGEN_FILEWRITE,
    STR_ERR2_KEYGEN,
    STR_ERR2_KEYGEN2,
	STR_ERR2_PASSPHRASE_NOKEY,

    STR_ERR2_CREATE_CFG_MISSING_KEYFILE,
    STR_ERR2_CREATE_CFG_SITEKEY_MISMATCH1,
    STR_ERR2_CREATE_CFG_SITEKEY_MISMATCH2,
    STR_ERR2_CREATE_CFG_SITEKEY_MISMATCH3

TSS_EndStringIds( twadmin )

#endif//__TWADMINSTRINGS_H

