/*
* A vague catch all include file for Botan
* (C) 1999-2007 Jack Lloyd
*
* Botan is released under the Simplified BSD License (see license.txt)
*/

#ifndef BOTAN_BOTAN_H_
#define BOTAN_BOTAN_H_

/*
* There is no real reason for this header to exist beyond historical
* reasons. The application should instead include the specific header
* files that define the interfaces it intends to use.
*
* This header file will be removed in Botan 3.x
*/

//#include <botan/lookup.h>
#include "base/lookup.h"
//#include <botan/version.h>
#include "utils/version.h"
//#include <botan/parsing.h>
#include "utils/parsing.h"
//#include <botan/init.h>
#include "base/init.h"
//#include <botan/rng.h>
#include "rng/rng.h"
//#include <botan/secmem.h>
#include "base/secmem.h"

#if defined(BOTAN_HAS_AUTO_SEEDING_RNG)
//  #include <botan/auto_rng.h>
    #include "rng/auto_rng/auto_rng.h"

#endif

#if defined(BOTAN_HAS_FILTERS)
//  #include <botan/filters.h>
#include "filters/filters.h"

#endif

#if defined(BOTAN_HAS_PUBLIC_KEY_CRYPTO)
//  #include <botan/x509_key.h>
#include "pubkey/x509_key.h"

//  #include <botan/pkcs8.h>
//#include <botan/pkcs8.h>
#include "pubkey/pkcs8.h"

#endif

BOTAN_DEPRECATED_HEADER(botan.h)

#endif
