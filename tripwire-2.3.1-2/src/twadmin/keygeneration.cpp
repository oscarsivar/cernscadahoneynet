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
///////////////////////////////////////////////////////////////////////////////
// keygeneration.cpp 
//

#include "stdtwadmin.h"

#include "keygeneration.h"
#include "twcrypto/crypto.h"
#include "twcrypto/keyfile.h"
#include "core/error.h"
#include "twadminstrings.h"
#include "core/usernotify.h"


#ifndef _DEBUG
const cElGamalSig::KeySize TRIPWIRE_PUBLIC_KEYSIZE = cElGamalSig::KEY1024;
#else
const cElGamalSig::KeySize TRIPWIRE_PUBLIC_KEYSIZE = cElGamalSig::KEY1024;
#endif

struct tGK
{
    bool    doneFlag;
    int     retValue;
    int8*   passphrase;
    int     passphraseLen;
    const TCHAR* keyPath;

    enum ReturnValue
    {
        OK = 0,
        INVALIDPARAM = 1,
        GENERATION_ERROR = 2,
        FILE_WRITE_ERROR = 3,
        LAST
    };

    tGK() 
    {
        doneFlag = false;
        retValue = 0;
        passphrase = 0;
        passphraseLen = 0;
        keyPath = 0;
    }
};

static void GeneratePublicPrivateKeys(void* pParams)
{
    tGK* pGK = (tGK*)pParams;

    if (pGK->doneFlag != false ||
        pGK->keyPath == 0 ||
        _tcslen(pGK->keyPath) == 0)
    {
        pGK->retValue = tGK::INVALIDPARAM;
        pGK->doneFlag = true;
        return;
    }

    try {
        cKeyFile keyfile;

#ifdef _DEBUG
        cDebug d("GeneratePublicPrivateKeys");
        d.TraceDebug("calling keyfile.GenerateKeys()\n");
#endif
        
        try
        {
            keyfile.GenerateKeys(TRIPWIRE_PUBLIC_KEYSIZE, pGK->passphrase, pGK->passphraseLen);
        }
        catch(eKeyFile&)
        {
            pGK->retValue = tGK::GENERATION_ERROR;
            pGK->doneFlag = true;
            return;
        }

#ifdef _DEBUG
        d.TraceDebug(_T("writing to keyfile %s\n"), pGK->keyPath);
#endif

        try
        {
            keyfile.WriteFile(pGK->keyPath);
        }
        catch(eKeyFile&)
        {
            pGK->retValue = tGK::FILE_WRITE_ERROR;
            pGK->doneFlag = true;
            return;
        }
    }
    catch(eError& e)
    {
        (void)e;
        pGK->retValue = tGK::GENERATION_ERROR;
        pGK->doneFlag = true;
        return;
    }

    pGK->retValue = tGK::OK;
    pGK->doneFlag = true;
    return;
}

bool GenerateKey(const TCHAR* keyPath, wc16_string passphrase)
{
#if IS_LITTLE_ENDIAN
    passphrase.swapbytes();
#endif

#ifdef _DEBUG
    // test reading in the keys
    wc16_string passphrase_copy = passphrase.c_str();
    wc16_string passphrase_copy2 = passphrase.c_str();
#endif

    iUserNotify::GetInstance()->Notify(iUserNotify::V_NORMAL, TSS_GetString(cTWAdmin, twadmin::STR_GENERATING_KEYS).c_str());

#if IS_UNIX
    fflush(stdout);
#endif

    tGK gk;
    gk.passphrase = (int8*)passphrase.data();
    gk.passphraseLen = passphrase.length() * sizeof(WCHAR16);
    gk.keyPath = keyPath;

#if IS_UNIX
    GeneratePublicPrivateKeys(&gk);
#endif

    if (gk.retValue != tGK::OK)
    {
        switch (gk.retValue)
        {
        case tGK::FILE_WRITE_ERROR:
            TCERR << std::endl << TSS_GetString(cTWAdmin, twadmin::STR_ERR2_KEYGEN_FILEWRITE) << gk.keyPath << std::endl;
        default:
            TCERR << std::endl << TSS_GetString(cTWAdmin, twadmin::STR_ERR2_KEYGEN) << gk.keyPath 
                  << TSS_GetString(cTWAdmin, twadmin::STR_ERR2_KEYGEN2) << std::endl;
            break;
        }

        return false;
    }

#ifdef _DEBUG
    // test reading in the keys
    cKeyFile keyfile;

    keyfile.ReadFile(keyPath);

    ASSERT(keyfile.GetPrivateKey((int8*)passphrase_copy.data(), passphrase_copy.length() * sizeof(WCHAR16)) != 0);
    keyfile.ReleasePrivateKey();

    //keyfile.WriteFile(_T("tripwire2.key"));

    // test memory writing
    int8    mem[4000];
    ASSERT(4000 > keyfile.GetWriteLen());

    keyfile.WriteMem(mem);

    cKeyFile k2;
    k2.ReadMem(mem);

    k2.GetPrivateKey((int8*)passphrase_copy2.data(), passphrase_copy2.length() * sizeof(WCHAR16));
    k2.ReleasePrivateKey();
#endif

    iUserNotify::GetInstance()->Notify(iUserNotify::V_NORMAL, TSS_GetString(cTWAdmin, twadmin::STR_GENERATION_COMPLETE).c_str());

    return true;
}

