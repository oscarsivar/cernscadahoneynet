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
// fspropcalc.h
//
// cFSPropCalc -- an FS fco visitor that "calculates" (or evaluates, populates, ...)
//					the fco's properties
#ifndef __FSPROPCALC_H
#define __FSPROPCALC_H

#ifndef __FCOPROPCALC_H
#include "fco/fcopropcalc.h"
#endif
#ifndef __FSVISITOR_H
#include "fsvisitor.h"
#endif
#ifndef __FCOPROPVECTOR_H
#include "fco/fcopropvector.h"
#endif

TSS_EXCEPTION( eFSPropCalc,				    eError )
//TSS_EXCEPTION( eFSPropCalcResetAccessTime,	eFSPropCalc ) // this was never used

class cFSPropCalc : public iFCOPropCalc, public iFSVisitor
{
public:
	cFSPropCalc();
	virtual ~cFSPropCalc();

	// from iFSVisitor
	virtual void VisitFSObject(cFSObject& obj);

	// from iFCOPropCalc
	virtual void					SetPropVector(const cFCOPropVector& pv);
	virtual const cFCOPropVector&	GetPropVector() const;
	virtual iFCOVisitor*			GetVisitor();
	virtual const iFCOVisitor*		GetVisitor() const;

	virtual void					SetErrorBucket(cErrorBucket* pBucket)				;
	virtual const cErrorBucket*		GetErrorBucket()							const	;

	virtual CollisionAction			GetCollisionAction()			const;
	virtual void					SetCollisionAction(CollisionAction a);

    virtual int                     GetCalcFlags() const;
    virtual void                    SetCalcFlags( int i );
private:
    cFSPropCalc( const cFSPropCalc& );
    void operator =( const cFSPropCalc& );

	cFCOPropVector					mPropVector;
	cErrorBucket*					mpErrorBucket;
	iFCOPropCalc::CollisionAction	mCollAction;
    int                             mCalcFlags;
};

inline int cFSPropCalc::GetCalcFlags() const
{
	return mCalcFlags;
}

inline void cFSPropCalc::SetCalcFlags( int i )
{
	mCalcFlags = i;
}


#endif //__FSPROPCALC_H

