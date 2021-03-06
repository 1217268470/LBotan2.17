/*
* TLS cipher suite information
*
* This file was automatically generated from the IANA assignments
* (tls-parameters.txt hash fe1ef8f3492b0708f3b14c9e8f8de55188c1b3c0)
* by ./src/scripts/tls_suite_info.py on 2019-05-24
*
* Botan is released under the Simplified BSD License (see license.txt)
*/

//#include <botan/tls_ciphersuite.h>
#include "tls/tls_ciphersuite.h"

namespace Botan {

namespace TLS {

//static
const std::vector<Ciphersuite>& Ciphersuite::all_known_ciphersuites()
   {
   // Note that this list of ciphersuites is ordered by id!
   static const std::vector<Ciphersuite> g_ciphersuite_list = {
      Ciphersuite(0x000A, "RSA_WITH_3DES_EDE_CBC_SHA", Auth_Method::IMPLICIT, Kex_Algo::STATIC_RSA, "3DES", 24, "SHA-1", 20, KDF_Algo::SHA_1, Nonce_Format::CBC_MODE),
      Ciphersuite(0x0013, "DHE_DSS_WITH_3DES_EDE_CBC_SHA", Auth_Method::DSA, Kex_Algo::DH, "3DES", 24, "SHA-1", 20, KDF_Algo::SHA_1, Nonce_Format::CBC_MODE),
      Ciphersuite(0x0016, "DHE_RSA_WITH_3DES_EDE_CBC_SHA", Auth_Method::RSA, Kex_Algo::DH, "3DES", 24, "SHA-1", 20, KDF_Algo::SHA_1, Nonce_Format::CBC_MODE),
      Ciphersuite(0x001B, "DH_anon_WITH_3DES_EDE_CBC_SHA", Auth_Method::ANONYMOUS, Kex_Algo::DH, "3DES", 24, "SHA-1", 20, KDF_Algo::SHA_1, Nonce_Format::CBC_MODE),
      Ciphersuite(0x002F, "RSA_WITH_AES_128_CBC_SHA", Auth_Method::IMPLICIT, Kex_Algo::STATIC_RSA, "AES-128", 16, "SHA-1", 20, KDF_Algo::SHA_1, Nonce_Format::CBC_MODE),
      Ciphersuite(0x0032, "DHE_DSS_WITH_AES_128_CBC_SHA", Auth_Method::DSA, Kex_Algo::DH, "AES-128", 16, "SHA-1", 20, KDF_Algo::SHA_1, Nonce_Format::CBC_MODE),
      Ciphersuite(0x0033, "DHE_RSA_WITH_AES_128_CBC_SHA", Auth_Method::RSA, Kex_Algo::DH, "AES-128", 16, "SHA-1", 20, KDF_Algo::SHA_1, Nonce_Format::CBC_MODE),
      Ciphersuite(0x0034, "DH_anon_WITH_AES_128_CBC_SHA", Auth_Method::ANONYMOUS, Kex_Algo::DH, "AES-128", 16, "SHA-1", 20, KDF_Algo::SHA_1, Nonce_Format::CBC_MODE),
      Ciphersuite(0x0035, "RSA_WITH_AES_256_CBC_SHA", Auth_Method::IMPLICIT, Kex_Algo::STATIC_RSA, "AES-256", 32, "SHA-1", 20, KDF_Algo::SHA_1, Nonce_Format::CBC_MODE),
      Ciphersuite(0x0038, "DHE_DSS_WITH_AES_256_CBC_SHA", Auth_Method::DSA, Kex_Algo::DH, "AES-256", 32, "SHA-1", 20, KDF_Algo::SHA_1, Nonce_Format::CBC_MODE),
      Ciphersuite(0x0039, "DHE_RSA_WITH_AES_256_CBC_SHA", Auth_Method::RSA, Kex_Algo::DH, "AES-256", 32, "SHA-1", 20, KDF_Algo::SHA_1, Nonce_Format::CBC_MODE),
      Ciphersuite(0x003A, "DH_anon_WITH_AES_256_CBC_SHA", Auth_Method::ANONYMOUS, Kex_Algo::DH, "AES-256", 32, "SHA-1", 20, KDF_Algo::SHA_1, Nonce_Format::CBC_MODE),
      Ciphersuite(0x003C, "RSA_WITH_AES_128_CBC_SHA256", Auth_Method::IMPLICIT, Kex_Algo::STATIC_RSA, "AES-128", 16, "SHA-256", 32, KDF_Algo::SHA_256, Nonce_Format::CBC_MODE),
      Ciphersuite(0x003D, "RSA_WITH_AES_256_CBC_SHA256", Auth_Method::IMPLICIT, Kex_Algo::STATIC_RSA, "AES-256", 32, "SHA-256", 32, KDF_Algo::SHA_256, Nonce_Format::CBC_MODE),
      Ciphersuite(0x0040, "DHE_DSS_WITH_AES_128_CBC_SHA256", Auth_Method::DSA, Kex_Algo::DH, "AES-128", 16, "SHA-256", 32, KDF_Algo::SHA_256, Nonce_Format::CBC_MODE),
      Ciphersuite(0x0041, "RSA_WITH_CAMELLIA_128_CBC_SHA", Auth_Method::IMPLICIT, Kex_Algo::STATIC_RSA, "Camellia-128", 16, "SHA-1", 20, KDF_Algo::SHA_1, Nonce_Format::CBC_MODE),
      Ciphersuite(0x0044, "DHE_DSS_WITH_CAMELLIA_128_CBC_SHA", Auth_Method::DSA, Kex_Algo::DH, "Camellia-128", 16, "SHA-1", 20, KDF_Algo::SHA_1, Nonce_Format::CBC_MODE),
      Ciphersuite(0x0045, "DHE_RSA_WITH_CAMELLIA_128_CBC_SHA", Auth_Method::RSA, Kex_Algo::DH, "Camellia-128", 16, "SHA-1", 20, KDF_Algo::SHA_1, Nonce_Format::CBC_MODE),
      Ciphersuite(0x0046, "DH_anon_WITH_CAMELLIA_128_CBC_SHA", Auth_Method::ANONYMOUS, Kex_Algo::DH, "Camellia-128", 16, "SHA-1", 20, KDF_Algo::SHA_1, Nonce_Format::CBC_MODE),
      Ciphersuite(0x0067, "DHE_RSA_WITH_AES_128_CBC_SHA256", Auth_Method::RSA, Kex_Algo::DH, "AES-128", 16, "SHA-256", 32, KDF_Algo::SHA_256, Nonce_Format::CBC_MODE),
      Ciphersuite(0x006A, "DHE_DSS_WITH_AES_256_CBC_SHA256", Auth_Method::DSA, Kex_Algo::DH, "AES-256", 32, "SHA-256", 32, KDF_Algo::SHA_256, Nonce_Format::CBC_MODE),
      Ciphersuite(0x006B, "DHE_RSA_WITH_AES_256_CBC_SHA256", Auth_Method::RSA, Kex_Algo::DH, "AES-256", 32, "SHA-256", 32, KDF_Algo::SHA_256, Nonce_Format::CBC_MODE),
      Ciphersuite(0x006C, "DH_anon_WITH_AES_128_CBC_SHA256", Auth_Method::ANONYMOUS, Kex_Algo::DH, "AES-128", 16, "SHA-256", 32, KDF_Algo::SHA_256, Nonce_Format::CBC_MODE),
      Ciphersuite(0x006D, "DH_anon_WITH_AES_256_CBC_SHA256", Auth_Method::ANONYMOUS, Kex_Algo::DH, "AES-256", 32, "SHA-256", 32, KDF_Algo::SHA_256, Nonce_Format::CBC_MODE),
      Ciphersuite(0x0084, "RSA_WITH_CAMELLIA_256_CBC_SHA", Auth_Method::IMPLICIT, Kex_Algo::STATIC_RSA, "Camellia-256", 32, "SHA-1", 20, KDF_Algo::SHA_1, Nonce_Format::CBC_MODE),
      Ciphersuite(0x0087, "DHE_DSS_WITH_CAMELLIA_256_CBC_SHA", Auth_Method::DSA, Kex_Algo::DH, "Camellia-256", 32, "SHA-1", 20, KDF_Algo::SHA_1, Nonce_Format::CBC_MODE),
      Ciphersuite(0x0088, "DHE_RSA_WITH_CAMELLIA_256_CBC_SHA", Auth_Method::RSA, Kex_Algo::DH, "Camellia-256", 32, "SHA-1", 20, KDF_Algo::SHA_1, Nonce_Format::CBC_MODE),
      Ciphersuite(0x0089, "DH_anon_WITH_CAMELLIA_256_CBC_SHA", Auth_Method::ANONYMOUS, Kex_Algo::DH, "Camellia-256", 32, "SHA-1", 20, KDF_Algo::SHA_1, Nonce_Format::CBC_MODE),
      Ciphersuite(0x008B, "PSK_WITH_3DES_EDE_CBC_SHA", Auth_Method::IMPLICIT, Kex_Algo::PSK, "3DES", 24, "SHA-1", 20, KDF_Algo::SHA_1, Nonce_Format::CBC_MODE),
      Ciphersuite(0x008C, "PSK_WITH_AES_128_CBC_SHA", Auth_Method::IMPLICIT, Kex_Algo::PSK, "AES-128", 16, "SHA-1", 20, KDF_Algo::SHA_1, Nonce_Format::CBC_MODE),
      Ciphersuite(0x008D, "PSK_WITH_AES_256_CBC_SHA", Auth_Method::IMPLICIT, Kex_Algo::PSK, "AES-256", 32, "SHA-1", 20, KDF_Algo::SHA_1, Nonce_Format::CBC_MODE),
      Ciphersuite(0x008F, "DHE_PSK_WITH_3DES_EDE_CBC_SHA", Auth_Method::IMPLICIT, Kex_Algo::DHE_PSK, "3DES", 24, "SHA-1", 20, KDF_Algo::SHA_1, Nonce_Format::CBC_MODE),
      Ciphersuite(0x0090, "DHE_PSK_WITH_AES_128_CBC_SHA", Auth_Method::IMPLICIT, Kex_Algo::DHE_PSK, "AES-128", 16, "SHA-1", 20, KDF_Algo::SHA_1, Nonce_Format::CBC_MODE),
      Ciphersuite(0x0091, "DHE_PSK_WITH_AES_256_CBC_SHA", Auth_Method::IMPLICIT, Kex_Algo::DHE_PSK, "AES-256", 32, "SHA-1", 20, KDF_Algo::SHA_1, Nonce_Format::CBC_MODE),
      Ciphersuite(0x0096, "RSA_WITH_SEED_CBC_SHA", Auth_Method::IMPLICIT, Kex_Algo::STATIC_RSA, "SEED", 16, "SHA-1", 20, KDF_Algo::SHA_1, Nonce_Format::CBC_MODE),
      Ciphersuite(0x0099, "DHE_DSS_WITH_SEED_CBC_SHA", Auth_Method::DSA, Kex_Algo::DH, "SEED", 16, "SHA-1", 20, KDF_Algo::SHA_1, Nonce_Format::CBC_MODE),
      Ciphersuite(0x009A, "DHE_RSA_WITH_SEED_CBC_SHA", Auth_Method::RSA, Kex_Algo::DH, "SEED", 16, "SHA-1", 20, KDF_Algo::SHA_1, Nonce_Format::CBC_MODE),
      Ciphersuite(0x009B, "DH_anon_WITH_SEED_CBC_SHA", Auth_Method::ANONYMOUS, Kex_Algo::DH, "SEED", 16, "SHA-1", 20, KDF_Algo::SHA_1, Nonce_Format::CBC_MODE),
      Ciphersuite(0x009C, "RSA_WITH_AES_128_GCM_SHA256", Auth_Method::IMPLICIT, Kex_Algo::STATIC_RSA, "AES-128/GCM", 16, "AEAD", 0, KDF_Algo::SHA_256, Nonce_Format::AEAD_IMPLICIT_4),
      Ciphersuite(0x009D, "RSA_WITH_AES_256_GCM_SHA384", Auth_Method::IMPLICIT, Kex_Algo::STATIC_RSA, "AES-256/GCM", 32, "AEAD", 0, KDF_Algo::SHA_384, Nonce_Format::AEAD_IMPLICIT_4),
      Ciphersuite(0x009E, "DHE_RSA_WITH_AES_128_GCM_SHA256", Auth_Method::RSA, Kex_Algo::DH, "AES-128/GCM", 16, "AEAD", 0, KDF_Algo::SHA_256, Nonce_Format::AEAD_IMPLICIT_4),
      Ciphersuite(0x009F, "DHE_RSA_WITH_AES_256_GCM_SHA384", Auth_Method::RSA, Kex_Algo::DH, "AES-256/GCM", 32, "AEAD", 0, KDF_Algo::SHA_384, Nonce_Format::AEAD_IMPLICIT_4),
      Ciphersuite(0x00A2, "DHE_DSS_WITH_AES_128_GCM_SHA256", Auth_Method::DSA, Kex_Algo::DH, "AES-128/GCM", 16, "AEAD", 0, KDF_Algo::SHA_256, Nonce_Format::AEAD_IMPLICIT_4),
      Ciphersuite(0x00A3, "DHE_DSS_WITH_AES_256_GCM_SHA384", Auth_Method::DSA, Kex_Algo::DH, "AES-256/GCM", 32, "AEAD", 0, KDF_Algo::SHA_384, Nonce_Format::AEAD_IMPLICIT_4),
      Ciphersuite(0x00A6, "DH_anon_WITH_AES_128_GCM_SHA256", Auth_Method::ANONYMOUS, Kex_Algo::DH, "AES-128/GCM", 16, "AEAD", 0, KDF_Algo::SHA_256, Nonce_Format::AEAD_IMPLICIT_4),
      Ciphersuite(0x00A7, "DH_anon_WITH_AES_256_GCM_SHA384", Auth_Method::ANONYMOUS, Kex_Algo::DH, "AES-256/GCM", 32, "AEAD", 0, KDF_Algo::SHA_384, Nonce_Format::AEAD_IMPLICIT_4),
      Ciphersuite(0x00A8, "PSK_WITH_AES_128_GCM_SHA256", Auth_Method::IMPLICIT, Kex_Algo::PSK, "AES-128/GCM", 16, "AEAD", 0, KDF_Algo::SHA_256, Nonce_Format::AEAD_IMPLICIT_4),
      Ciphersuite(0x00A9, "PSK_WITH_AES_256_GCM_SHA384", Auth_Method::IMPLICIT, Kex_Algo::PSK, "AES-256/GCM", 32, "AEAD", 0, KDF_Algo::SHA_384, Nonce_Format::AEAD_IMPLICIT_4),
      Ciphersuite(0x00AA, "DHE_PSK_WITH_AES_128_GCM_SHA256", Auth_Method::IMPLICIT, Kex_Algo::DHE_PSK, "AES-128/GCM", 16, "AEAD", 0, KDF_Algo::SHA_256, Nonce_Format::AEAD_IMPLICIT_4),
      Ciphersuite(0x00AB, "DHE_PSK_WITH_AES_256_GCM_SHA384", Auth_Method::IMPLICIT, Kex_Algo::DHE_PSK, "AES-256/GCM", 32, "AEAD", 0, KDF_Algo::SHA_384, Nonce_Format::AEAD_IMPLICIT_4),
      Ciphersuite(0x00AE, "PSK_WITH_AES_128_CBC_SHA256", Auth_Method::IMPLICIT, Kex_Algo::PSK, "AES-128", 16, "SHA-256", 32, KDF_Algo::SHA_256, Nonce_Format::CBC_MODE),
      Ciphersuite(0x00AF, "PSK_WITH_AES_256_CBC_SHA384", Auth_Method::IMPLICIT, Kex_Algo::PSK, "AES-256", 32, "SHA-384", 48, KDF_Algo::SHA_384, Nonce_Format::CBC_MODE),
      Ciphersuite(0x00B2, "DHE_PSK_WITH_AES_128_CBC_SHA256", Auth_Method::IMPLICIT, Kex_Algo::DHE_PSK, "AES-128", 16, "SHA-256", 32, KDF_Algo::SHA_256, Nonce_Format::CBC_MODE),
      Ciphersuite(0x00B3, "DHE_PSK_WITH_AES_256_CBC_SHA384", Auth_Method::IMPLICIT, Kex_Algo::DHE_PSK, "AES-256", 32, "SHA-384", 48, KDF_Algo::SHA_384, Nonce_Format::CBC_MODE),
      Ciphersuite(0x00BA, "RSA_WITH_CAMELLIA_128_CBC_SHA256", Auth_Method::IMPLICIT, Kex_Algo::STATIC_RSA, "Camellia-128", 16, "SHA-256", 32, KDF_Algo::SHA_256, Nonce_Format::CBC_MODE),
      Ciphersuite(0x00BD, "DHE_DSS_WITH_CAMELLIA_128_CBC_SHA256", Auth_Method::DSA, Kex_Algo::DH, "Camellia-128", 16, "SHA-256", 32, KDF_Algo::SHA_256, Nonce_Format::CBC_MODE),
      Ciphersuite(0x00BE, "DHE_RSA_WITH_CAMELLIA_128_CBC_SHA256", Auth_Method::RSA, Kex_Algo::DH, "Camellia-128", 16, "SHA-256", 32, KDF_Algo::SHA_256, Nonce_Format::CBC_MODE),
      Ciphersuite(0x00BF, "DH_anon_WITH_CAMELLIA_128_CBC_SHA256", Auth_Method::ANONYMOUS, Kex_Algo::DH, "Camellia-128", 16, "SHA-256", 32, KDF_Algo::SHA_256, Nonce_Format::CBC_MODE),
      Ciphersuite(0x00C0, "RSA_WITH_CAMELLIA_256_CBC_SHA256", Auth_Method::IMPLICIT, Kex_Algo::STATIC_RSA, "Camellia-256", 32, "SHA-256", 32, KDF_Algo::SHA_256, Nonce_Format::CBC_MODE),
      Ciphersuite(0x00C3, "DHE_DSS_WITH_CAMELLIA_256_CBC_SHA256", Auth_Method::DSA, Kex_Algo::DH, "Camellia-256", 32, "SHA-256", 32, KDF_Algo::SHA_256, Nonce_Format::CBC_MODE),
      Ciphersuite(0x00C4, "DHE_RSA_WITH_CAMELLIA_256_CBC_SHA256", Auth_Method::RSA, Kex_Algo::DH, "Camellia-256", 32, "SHA-256", 32, KDF_Algo::SHA_256, Nonce_Format::CBC_MODE),
      Ciphersuite(0x00C5, "DH_anon_WITH_CAMELLIA_256_CBC_SHA256", Auth_Method::ANONYMOUS, Kex_Algo::DH, "Camellia-256", 32, "SHA-256", 32, KDF_Algo::SHA_256, Nonce_Format::CBC_MODE),
      Ciphersuite(0x16B7, "CECPQ1_RSA_WITH_CHACHA20_POLY1305_SHA256", Auth_Method::RSA, Kex_Algo::CECPQ1, "ChaCha20Poly1305", 32, "AEAD", 0, KDF_Algo::SHA_256, Nonce_Format::AEAD_XOR_12),
      Ciphersuite(0x16B8, "CECPQ1_ECDSA_WITH_CHACHA20_POLY1305_SHA256", Auth_Method::ECDSA, Kex_Algo::CECPQ1, "ChaCha20Poly1305", 32, "AEAD", 0, KDF_Algo::SHA_256, Nonce_Format::AEAD_XOR_12),
      Ciphersuite(0x16B9, "CECPQ1_RSA_WITH_AES_256_GCM_SHA384", Auth_Method::RSA, Kex_Algo::CECPQ1, "AES-256/GCM", 32, "AEAD", 0, KDF_Algo::SHA_384, Nonce_Format::AEAD_IMPLICIT_4),
      Ciphersuite(0x16BA, "CECPQ1_ECDSA_WITH_AES_256_GCM_SHA384", Auth_Method::ECDSA, Kex_Algo::CECPQ1, "AES-256/GCM", 32, "AEAD", 0, KDF_Algo::SHA_384, Nonce_Format::AEAD_IMPLICIT_4),
      Ciphersuite(0xC008, "ECDHE_ECDSA_WITH_3DES_EDE_CBC_SHA", Auth_Method::ECDSA, Kex_Algo::ECDH, "3DES", 24, "SHA-1", 20, KDF_Algo::SHA_1, Nonce_Format::CBC_MODE),
      Ciphersuite(0xC009, "ECDHE_ECDSA_WITH_AES_128_CBC_SHA", Auth_Method::ECDSA, Kex_Algo::ECDH, "AES-128", 16, "SHA-1", 20, KDF_Algo::SHA_1, Nonce_Format::CBC_MODE),
      Ciphersuite(0xC00A, "ECDHE_ECDSA_WITH_AES_256_CBC_SHA", Auth_Method::ECDSA, Kex_Algo::ECDH, "AES-256", 32, "SHA-1", 20, KDF_Algo::SHA_1, Nonce_Format::CBC_MODE),
      Ciphersuite(0xC012, "ECDHE_RSA_WITH_3DES_EDE_CBC_SHA", Auth_Method::RSA, Kex_Algo::ECDH, "3DES", 24, "SHA-1", 20, KDF_Algo::SHA_1, Nonce_Format::CBC_MODE),
      Ciphersuite(0xC013, "ECDHE_RSA_WITH_AES_128_CBC_SHA", Auth_Method::RSA, Kex_Algo::ECDH, "AES-128", 16, "SHA-1", 20, KDF_Algo::SHA_1, Nonce_Format::CBC_MODE),
      Ciphersuite(0xC014, "ECDHE_RSA_WITH_AES_256_CBC_SHA", Auth_Method::RSA, Kex_Algo::ECDH, "AES-256", 32, "SHA-1", 20, KDF_Algo::SHA_1, Nonce_Format::CBC_MODE),
      Ciphersuite(0xC017, "ECDH_anon_WITH_3DES_EDE_CBC_SHA", Auth_Method::ANONYMOUS, Kex_Algo::ECDH, "3DES", 24, "SHA-1", 20, KDF_Algo::SHA_1, Nonce_Format::CBC_MODE),
      Ciphersuite(0xC018, "ECDH_anon_WITH_AES_128_CBC_SHA", Auth_Method::ANONYMOUS, Kex_Algo::ECDH, "AES-128", 16, "SHA-1", 20, KDF_Algo::SHA_1, Nonce_Format::CBC_MODE),
      Ciphersuite(0xC019, "ECDH_anon_WITH_AES_256_CBC_SHA", Auth_Method::ANONYMOUS, Kex_Algo::ECDH, "AES-256", 32, "SHA-1", 20, KDF_Algo::SHA_1, Nonce_Format::CBC_MODE),
      Ciphersuite(0xC01A, "SRP_SHA_WITH_3DES_EDE_CBC_SHA", Auth_Method::IMPLICIT, Kex_Algo::SRP_SHA, "3DES", 24, "SHA-1", 20, KDF_Algo::SHA_1, Nonce_Format::CBC_MODE),
      Ciphersuite(0xC01B, "SRP_SHA_RSA_WITH_3DES_EDE_CBC_SHA", Auth_Method::RSA, Kex_Algo::SRP_SHA, "3DES", 24, "SHA-1", 20, KDF_Algo::SHA_1, Nonce_Format::CBC_MODE),
      Ciphersuite(0xC01C, "SRP_SHA_DSS_WITH_3DES_EDE_CBC_SHA", Auth_Method::DSA, Kex_Algo::SRP_SHA, "3DES", 24, "SHA-1", 20, KDF_Algo::SHA_1, Nonce_Format::CBC_MODE),
      Ciphersuite(0xC01D, "SRP_SHA_WITH_AES_128_CBC_SHA", Auth_Method::IMPLICIT, Kex_Algo::SRP_SHA, "AES-128", 16, "SHA-1", 20, KDF_Algo::SHA_1, Nonce_Format::CBC_MODE),
      Ciphersuite(0xC01E, "SRP_SHA_RSA_WITH_AES_128_CBC_SHA", Auth_Method::RSA, Kex_Algo::SRP_SHA, "AES-128", 16, "SHA-1", 20, KDF_Algo::SHA_1, Nonce_Format::CBC_MODE),
      Ciphersuite(0xC01F, "SRP_SHA_DSS_WITH_AES_128_CBC_SHA", Auth_Method::DSA, Kex_Algo::SRP_SHA, "AES-128", 16, "SHA-1", 20, KDF_Algo::SHA_1, Nonce_Format::CBC_MODE),
      Ciphersuite(0xC020, "SRP_SHA_WITH_AES_256_CBC_SHA", Auth_Method::IMPLICIT, Kex_Algo::SRP_SHA, "AES-256", 32, "SHA-1", 20, KDF_Algo::SHA_1, Nonce_Format::CBC_MODE),
      Ciphersuite(0xC021, "SRP_SHA_RSA_WITH_AES_256_CBC_SHA", Auth_Method::RSA, Kex_Algo::SRP_SHA, "AES-256", 32, "SHA-1", 20, KDF_Algo::SHA_1, Nonce_Format::CBC_MODE),
      Ciphersuite(0xC022, "SRP_SHA_DSS_WITH_AES_256_CBC_SHA", Auth_Method::DSA, Kex_Algo::SRP_SHA, "AES-256", 32, "SHA-1", 20, KDF_Algo::SHA_1, Nonce_Format::CBC_MODE),
      Ciphersuite(0xC023, "ECDHE_ECDSA_WITH_AES_128_CBC_SHA256", Auth_Method::ECDSA, Kex_Algo::ECDH, "AES-128", 16, "SHA-256", 32, KDF_Algo::SHA_256, Nonce_Format::CBC_MODE),
      Ciphersuite(0xC024, "ECDHE_ECDSA_WITH_AES_256_CBC_SHA384", Auth_Method::ECDSA, Kex_Algo::ECDH, "AES-256", 32, "SHA-384", 48, KDF_Algo::SHA_384, Nonce_Format::CBC_MODE),
      Ciphersuite(0xC027, "ECDHE_RSA_WITH_AES_128_CBC_SHA256", Auth_Method::RSA, Kex_Algo::ECDH, "AES-128", 16, "SHA-256", 32, KDF_Algo::SHA_256, Nonce_Format::CBC_MODE),
      Ciphersuite(0xC028, "ECDHE_RSA_WITH_AES_256_CBC_SHA384", Auth_Method::RSA, Kex_Algo::ECDH, "AES-256", 32, "SHA-384", 48, KDF_Algo::SHA_384, Nonce_Format::CBC_MODE),
      Ciphersuite(0xC02B, "ECDHE_ECDSA_WITH_AES_128_GCM_SHA256", Auth_Method::ECDSA, Kex_Algo::ECDH, "AES-128/GCM", 16, "AEAD", 0, KDF_Algo::SHA_256, Nonce_Format::AEAD_IMPLICIT_4),
      Ciphersuite(0xC02C, "ECDHE_ECDSA_WITH_AES_256_GCM_SHA384", Auth_Method::ECDSA, Kex_Algo::ECDH, "AES-256/GCM", 32, "AEAD", 0, KDF_Algo::SHA_384, Nonce_Format::AEAD_IMPLICIT_4),
      Ciphersuite(0xC02F, "ECDHE_RSA_WITH_AES_128_GCM_SHA256", Auth_Method::RSA, Kex_Algo::ECDH, "AES-128/GCM", 16, "AEAD", 0, KDF_Algo::SHA_256, Nonce_Format::AEAD_IMPLICIT_4),
      Ciphersuite(0xC030, "ECDHE_RSA_WITH_AES_256_GCM_SHA384", Auth_Method::RSA, Kex_Algo::ECDH, "AES-256/GCM", 32, "AEAD", 0, KDF_Algo::SHA_384, Nonce_Format::AEAD_IMPLICIT_4),
      Ciphersuite(0xC034, "ECDHE_PSK_WITH_3DES_EDE_CBC_SHA", Auth_Method::IMPLICIT, Kex_Algo::ECDHE_PSK, "3DES", 24, "SHA-1", 20, KDF_Algo::SHA_1, Nonce_Format::CBC_MODE),
      Ciphersuite(0xC035, "ECDHE_PSK_WITH_AES_128_CBC_SHA", Auth_Method::IMPLICIT, Kex_Algo::ECDHE_PSK, "AES-128", 16, "SHA-1", 20, KDF_Algo::SHA_1, Nonce_Format::CBC_MODE),
      Ciphersuite(0xC036, "ECDHE_PSK_WITH_AES_256_CBC_SHA", Auth_Method::IMPLICIT, Kex_Algo::ECDHE_PSK, "AES-256", 32, "SHA-1", 20, KDF_Algo::SHA_1, Nonce_Format::CBC_MODE),
      Ciphersuite(0xC037, "ECDHE_PSK_WITH_AES_128_CBC_SHA256", Auth_Method::IMPLICIT, Kex_Algo::ECDHE_PSK, "AES-128", 16, "SHA-256", 32, KDF_Algo::SHA_256, Nonce_Format::CBC_MODE),
      Ciphersuite(0xC038, "ECDHE_PSK_WITH_AES_256_CBC_SHA384", Auth_Method::IMPLICIT, Kex_Algo::ECDHE_PSK, "AES-256", 32, "SHA-384", 48, KDF_Algo::SHA_384, Nonce_Format::CBC_MODE),
      Ciphersuite(0xC050, "RSA_WITH_ARIA_128_GCM_SHA256", Auth_Method::IMPLICIT, Kex_Algo::STATIC_RSA, "ARIA-128/GCM", 16, "AEAD", 0, KDF_Algo::SHA_256, Nonce_Format::AEAD_IMPLICIT_4),
      Ciphersuite(0xC051, "RSA_WITH_ARIA_256_GCM_SHA384", Auth_Method::IMPLICIT, Kex_Algo::STATIC_RSA, "ARIA-256/GCM", 32, "AEAD", 0, KDF_Algo::SHA_384, Nonce_Format::AEAD_IMPLICIT_4),
      Ciphersuite(0xC052, "DHE_RSA_WITH_ARIA_128_GCM_SHA256", Auth_Method::RSA, Kex_Algo::DH, "ARIA-128/GCM", 16, "AEAD", 0, KDF_Algo::SHA_256, Nonce_Format::AEAD_IMPLICIT_4),
      Ciphersuite(0xC053, "DHE_RSA_WITH_ARIA_256_GCM_SHA384", Auth_Method::RSA, Kex_Algo::DH, "ARIA-256/GCM", 32, "AEAD", 0, KDF_Algo::SHA_384, Nonce_Format::AEAD_IMPLICIT_4),
      Ciphersuite(0xC056, "DHE_DSS_WITH_ARIA_128_GCM_SHA256", Auth_Method::DSA, Kex_Algo::DH, "ARIA-128/GCM", 16, "AEAD", 0, KDF_Algo::SHA_256, Nonce_Format::AEAD_IMPLICIT_4),
      Ciphersuite(0xC057, "DHE_DSS_WITH_ARIA_256_GCM_SHA384", Auth_Method::DSA, Kex_Algo::DH, "ARIA-256/GCM", 32, "AEAD", 0, KDF_Algo::SHA_384, Nonce_Format::AEAD_IMPLICIT_4),
      Ciphersuite(0xC05A, "DH_anon_WITH_ARIA_128_GCM_SHA256", Auth_Method::ANONYMOUS, Kex_Algo::DH, "ARIA-128/GCM", 16, "AEAD", 0, KDF_Algo::SHA_256, Nonce_Format::AEAD_IMPLICIT_4),
      Ciphersuite(0xC05B, "DH_anon_WITH_ARIA_256_GCM_SHA384", Auth_Method::ANONYMOUS, Kex_Algo::DH, "ARIA-256/GCM", 32, "AEAD", 0, KDF_Algo::SHA_384, Nonce_Format::AEAD_IMPLICIT_4),
      Ciphersuite(0xC05C, "ECDHE_ECDSA_WITH_ARIA_128_GCM_SHA256", Auth_Method::ECDSA, Kex_Algo::ECDH, "ARIA-128/GCM", 16, "AEAD", 0, KDF_Algo::SHA_256, Nonce_Format::AEAD_IMPLICIT_4),
      Ciphersuite(0xC05D, "ECDHE_ECDSA_WITH_ARIA_256_GCM_SHA384", Auth_Method::ECDSA, Kex_Algo::ECDH, "ARIA-256/GCM", 32, "AEAD", 0, KDF_Algo::SHA_384, Nonce_Format::AEAD_IMPLICIT_4),
      Ciphersuite(0xC060, "ECDHE_RSA_WITH_ARIA_128_GCM_SHA256", Auth_Method::RSA, Kex_Algo::ECDH, "ARIA-128/GCM", 16, "AEAD", 0, KDF_Algo::SHA_256, Nonce_Format::AEAD_IMPLICIT_4),
      Ciphersuite(0xC061, "ECDHE_RSA_WITH_ARIA_256_GCM_SHA384", Auth_Method::RSA, Kex_Algo::ECDH, "ARIA-256/GCM", 32, "AEAD", 0, KDF_Algo::SHA_384, Nonce_Format::AEAD_IMPLICIT_4),
      Ciphersuite(0xC06A, "PSK_WITH_ARIA_128_GCM_SHA256", Auth_Method::IMPLICIT, Kex_Algo::PSK, "ARIA-128/GCM", 16, "AEAD", 0, KDF_Algo::SHA_256, Nonce_Format::AEAD_IMPLICIT_4),
      Ciphersuite(0xC06B, "PSK_WITH_ARIA_256_GCM_SHA384", Auth_Method::IMPLICIT, Kex_Algo::PSK, "ARIA-256/GCM", 32, "AEAD", 0, KDF_Algo::SHA_384, Nonce_Format::AEAD_IMPLICIT_4),
      Ciphersuite(0xC06C, "DHE_PSK_WITH_ARIA_128_GCM_SHA256", Auth_Method::IMPLICIT, Kex_Algo::DHE_PSK, "ARIA-128/GCM", 16, "AEAD", 0, KDF_Algo::SHA_256, Nonce_Format::AEAD_IMPLICIT_4),
      Ciphersuite(0xC06D, "DHE_PSK_WITH_ARIA_256_GCM_SHA384", Auth_Method::IMPLICIT, Kex_Algo::DHE_PSK, "ARIA-256/GCM", 32, "AEAD", 0, KDF_Algo::SHA_384, Nonce_Format::AEAD_IMPLICIT_4),
      Ciphersuite(0xC072, "ECDHE_ECDSA_WITH_CAMELLIA_128_CBC_SHA256", Auth_Method::ECDSA, Kex_Algo::ECDH, "Camellia-128", 16, "SHA-256", 32, KDF_Algo::SHA_256, Nonce_Format::CBC_MODE),
      Ciphersuite(0xC073, "ECDHE_ECDSA_WITH_CAMELLIA_256_CBC_SHA384", Auth_Method::ECDSA, Kex_Algo::ECDH, "Camellia-256", 32, "SHA-384", 48, KDF_Algo::SHA_384, Nonce_Format::CBC_MODE),
      Ciphersuite(0xC076, "ECDHE_RSA_WITH_CAMELLIA_128_CBC_SHA256", Auth_Method::RSA, Kex_Algo::ECDH, "Camellia-128", 16, "SHA-256", 32, KDF_Algo::SHA_256, Nonce_Format::CBC_MODE),
      Ciphersuite(0xC077, "ECDHE_RSA_WITH_CAMELLIA_256_CBC_SHA384", Auth_Method::RSA, Kex_Algo::ECDH, "Camellia-256", 32, "SHA-384", 48, KDF_Algo::SHA_384, Nonce_Format::CBC_MODE),
      Ciphersuite(0xC07A, "RSA_WITH_CAMELLIA_128_GCM_SHA256", Auth_Method::IMPLICIT, Kex_Algo::STATIC_RSA, "Camellia-128/GCM", 16, "AEAD", 0, KDF_Algo::SHA_256, Nonce_Format::AEAD_IMPLICIT_4),
      Ciphersuite(0xC07B, "RSA_WITH_CAMELLIA_256_GCM_SHA384", Auth_Method::IMPLICIT, Kex_Algo::STATIC_RSA, "Camellia-256/GCM", 32, "AEAD", 0, KDF_Algo::SHA_384, Nonce_Format::AEAD_IMPLICIT_4),
      Ciphersuite(0xC07C, "DHE_RSA_WITH_CAMELLIA_128_GCM_SHA256", Auth_Method::RSA, Kex_Algo::DH, "Camellia-128/GCM", 16, "AEAD", 0, KDF_Algo::SHA_256, Nonce_Format::AEAD_IMPLICIT_4),
      Ciphersuite(0xC07D, "DHE_RSA_WITH_CAMELLIA_256_GCM_SHA384", Auth_Method::RSA, Kex_Algo::DH, "Camellia-256/GCM", 32, "AEAD", 0, KDF_Algo::SHA_384, Nonce_Format::AEAD_IMPLICIT_4),
      Ciphersuite(0xC080, "DHE_DSS_WITH_CAMELLIA_128_GCM_SHA256", Auth_Method::DSA, Kex_Algo::DH, "Camellia-128/GCM", 16, "AEAD", 0, KDF_Algo::SHA_256, Nonce_Format::AEAD_IMPLICIT_4),
      Ciphersuite(0xC081, "DHE_DSS_WITH_CAMELLIA_256_GCM_SHA384", Auth_Method::DSA, Kex_Algo::DH, "Camellia-256/GCM", 32, "AEAD", 0, KDF_Algo::SHA_384, Nonce_Format::AEAD_IMPLICIT_4),
      Ciphersuite(0xC084, "DH_anon_WITH_CAMELLIA_128_GCM_SHA256", Auth_Method::ANONYMOUS, Kex_Algo::DH, "Camellia-128/GCM", 16, "AEAD", 0, KDF_Algo::SHA_256, Nonce_Format::AEAD_IMPLICIT_4),
      Ciphersuite(0xC085, "DH_anon_WITH_CAMELLIA_256_GCM_SHA384", Auth_Method::ANONYMOUS, Kex_Algo::DH, "Camellia-256/GCM", 32, "AEAD", 0, KDF_Algo::SHA_384, Nonce_Format::AEAD_IMPLICIT_4),
      Ciphersuite(0xC086, "ECDHE_ECDSA_WITH_CAMELLIA_128_GCM_SHA256", Auth_Method::ECDSA, Kex_Algo::ECDH, "Camellia-128/GCM", 16, "AEAD", 0, KDF_Algo::SHA_256, Nonce_Format::AEAD_IMPLICIT_4),
      Ciphersuite(0xC087, "ECDHE_ECDSA_WITH_CAMELLIA_256_GCM_SHA384", Auth_Method::ECDSA, Kex_Algo::ECDH, "Camellia-256/GCM", 32, "AEAD", 0, KDF_Algo::SHA_384, Nonce_Format::AEAD_IMPLICIT_4),
      Ciphersuite(0xC08A, "ECDHE_RSA_WITH_CAMELLIA_128_GCM_SHA256", Auth_Method::RSA, Kex_Algo::ECDH, "Camellia-128/GCM", 16, "AEAD", 0, KDF_Algo::SHA_256, Nonce_Format::AEAD_IMPLICIT_4),
      Ciphersuite(0xC08B, "ECDHE_RSA_WITH_CAMELLIA_256_GCM_SHA384", Auth_Method::RSA, Kex_Algo::ECDH, "Camellia-256/GCM", 32, "AEAD", 0, KDF_Algo::SHA_384, Nonce_Format::AEAD_IMPLICIT_4),
      Ciphersuite(0xC08E, "PSK_WITH_CAMELLIA_128_GCM_SHA256", Auth_Method::IMPLICIT, Kex_Algo::PSK, "Camellia-128/GCM", 16, "AEAD", 0, KDF_Algo::SHA_256, Nonce_Format::AEAD_IMPLICIT_4),
      Ciphersuite(0xC08F, "PSK_WITH_CAMELLIA_256_GCM_SHA384", Auth_Method::IMPLICIT, Kex_Algo::PSK, "Camellia-256/GCM", 32, "AEAD", 0, KDF_Algo::SHA_384, Nonce_Format::AEAD_IMPLICIT_4),
      Ciphersuite(0xC090, "DHE_PSK_WITH_CAMELLIA_128_GCM_SHA256", Auth_Method::IMPLICIT, Kex_Algo::DHE_PSK, "Camellia-128/GCM", 16, "AEAD", 0, KDF_Algo::SHA_256, Nonce_Format::AEAD_IMPLICIT_4),
      Ciphersuite(0xC091, "DHE_PSK_WITH_CAMELLIA_256_GCM_SHA384", Auth_Method::IMPLICIT, Kex_Algo::DHE_PSK, "Camellia-256/GCM", 32, "AEAD", 0, KDF_Algo::SHA_384, Nonce_Format::AEAD_IMPLICIT_4),
      Ciphersuite(0xC094, "PSK_WITH_CAMELLIA_128_CBC_SHA256", Auth_Method::IMPLICIT, Kex_Algo::PSK, "Camellia-128", 16, "SHA-256", 32, KDF_Algo::SHA_256, Nonce_Format::CBC_MODE),
      Ciphersuite(0xC095, "PSK_WITH_CAMELLIA_256_CBC_SHA384", Auth_Method::IMPLICIT, Kex_Algo::PSK, "Camellia-256", 32, "SHA-384", 48, KDF_Algo::SHA_384, Nonce_Format::CBC_MODE),
      Ciphersuite(0xC096, "DHE_PSK_WITH_CAMELLIA_128_CBC_SHA256", Auth_Method::IMPLICIT, Kex_Algo::DHE_PSK, "Camellia-128", 16, "SHA-256", 32, KDF_Algo::SHA_256, Nonce_Format::CBC_MODE),
      Ciphersuite(0xC097, "DHE_PSK_WITH_CAMELLIA_256_CBC_SHA384", Auth_Method::IMPLICIT, Kex_Algo::DHE_PSK, "Camellia-256", 32, "SHA-384", 48, KDF_Algo::SHA_384, Nonce_Format::CBC_MODE),
      Ciphersuite(0xC09A, "ECDHE_PSK_WITH_CAMELLIA_128_CBC_SHA256", Auth_Method::IMPLICIT, Kex_Algo::ECDHE_PSK, "Camellia-128", 16, "SHA-256", 32, KDF_Algo::SHA_256, Nonce_Format::CBC_MODE),
      Ciphersuite(0xC09B, "ECDHE_PSK_WITH_CAMELLIA_256_CBC_SHA384", Auth_Method::IMPLICIT, Kex_Algo::ECDHE_PSK, "Camellia-256", 32, "SHA-384", 48, KDF_Algo::SHA_384, Nonce_Format::CBC_MODE),
      Ciphersuite(0xC09C, "RSA_WITH_AES_128_CCM", Auth_Method::IMPLICIT, Kex_Algo::STATIC_RSA, "AES-128/CCM", 16, "AEAD", 0, KDF_Algo::SHA_256, Nonce_Format::AEAD_IMPLICIT_4),
      Ciphersuite(0xC09D, "RSA_WITH_AES_256_CCM", Auth_Method::IMPLICIT, Kex_Algo::STATIC_RSA, "AES-256/CCM", 32, "AEAD", 0, KDF_Algo::SHA_256, Nonce_Format::AEAD_IMPLICIT_4),
      Ciphersuite(0xC09E, "DHE_RSA_WITH_AES_128_CCM", Auth_Method::RSA, Kex_Algo::DH, "AES-128/CCM", 16, "AEAD", 0, KDF_Algo::SHA_256, Nonce_Format::AEAD_IMPLICIT_4),
      Ciphersuite(0xC09F, "DHE_RSA_WITH_AES_256_CCM", Auth_Method::RSA, Kex_Algo::DH, "AES-256/CCM", 32, "AEAD", 0, KDF_Algo::SHA_256, Nonce_Format::AEAD_IMPLICIT_4),
      Ciphersuite(0xC0A0, "RSA_WITH_AES_128_CCM_8", Auth_Method::IMPLICIT, Kex_Algo::STATIC_RSA, "AES-128/CCM(8)", 16, "AEAD", 0, KDF_Algo::SHA_256, Nonce_Format::AEAD_IMPLICIT_4),
      Ciphersuite(0xC0A1, "RSA_WITH_AES_256_CCM_8", Auth_Method::IMPLICIT, Kex_Algo::STATIC_RSA, "AES-256/CCM(8)", 32, "AEAD", 0, KDF_Algo::SHA_256, Nonce_Format::AEAD_IMPLICIT_4),
      Ciphersuite(0xC0A2, "DHE_RSA_WITH_AES_128_CCM_8", Auth_Method::RSA, Kex_Algo::DH, "AES-128/CCM(8)", 16, "AEAD", 0, KDF_Algo::SHA_256, Nonce_Format::AEAD_IMPLICIT_4),
      Ciphersuite(0xC0A3, "DHE_RSA_WITH_AES_256_CCM_8", Auth_Method::RSA, Kex_Algo::DH, "AES-256/CCM(8)", 32, "AEAD", 0, KDF_Algo::SHA_256, Nonce_Format::AEAD_IMPLICIT_4),
      Ciphersuite(0xC0A4, "PSK_WITH_AES_128_CCM", Auth_Method::IMPLICIT, Kex_Algo::PSK, "AES-128/CCM", 16, "AEAD", 0, KDF_Algo::SHA_256, Nonce_Format::AEAD_IMPLICIT_4),
      Ciphersuite(0xC0A5, "PSK_WITH_AES_256_CCM", Auth_Method::IMPLICIT, Kex_Algo::PSK, "AES-256/CCM", 32, "AEAD", 0, KDF_Algo::SHA_256, Nonce_Format::AEAD_IMPLICIT_4),
      Ciphersuite(0xC0A6, "DHE_PSK_WITH_AES_128_CCM", Auth_Method::IMPLICIT, Kex_Algo::DHE_PSK, "AES-128/CCM", 16, "AEAD", 0, KDF_Algo::SHA_256, Nonce_Format::AEAD_IMPLICIT_4),
      Ciphersuite(0xC0A7, "DHE_PSK_WITH_AES_256_CCM", Auth_Method::IMPLICIT, Kex_Algo::DHE_PSK, "AES-256/CCM", 32, "AEAD", 0, KDF_Algo::SHA_256, Nonce_Format::AEAD_IMPLICIT_4),
      Ciphersuite(0xC0A8, "PSK_WITH_AES_128_CCM_8", Auth_Method::IMPLICIT, Kex_Algo::PSK, "AES-128/CCM(8)", 16, "AEAD", 0, KDF_Algo::SHA_256, Nonce_Format::AEAD_IMPLICIT_4),
      Ciphersuite(0xC0A9, "PSK_WITH_AES_256_CCM_8", Auth_Method::IMPLICIT, Kex_Algo::PSK, "AES-256/CCM(8)", 32, "AEAD", 0, KDF_Algo::SHA_256, Nonce_Format::AEAD_IMPLICIT_4),
      Ciphersuite(0xC0AA, "PSK_DHE_WITH_AES_128_CCM_8", Auth_Method::IMPLICIT, Kex_Algo::DHE_PSK, "AES-128/CCM(8)", 16, "AEAD", 0, KDF_Algo::SHA_256, Nonce_Format::AEAD_IMPLICIT_4),
      Ciphersuite(0xC0AB, "PSK_DHE_WITH_AES_256_CCM_8", Auth_Method::IMPLICIT, Kex_Algo::DHE_PSK, "AES-256/CCM(8)", 32, "AEAD", 0, KDF_Algo::SHA_256, Nonce_Format::AEAD_IMPLICIT_4),
      Ciphersuite(0xC0AC, "ECDHE_ECDSA_WITH_AES_128_CCM", Auth_Method::ECDSA, Kex_Algo::ECDH, "AES-128/CCM", 16, "AEAD", 0, KDF_Algo::SHA_256, Nonce_Format::AEAD_IMPLICIT_4),
      Ciphersuite(0xC0AD, "ECDHE_ECDSA_WITH_AES_256_CCM", Auth_Method::ECDSA, Kex_Algo::ECDH, "AES-256/CCM", 32, "AEAD", 0, KDF_Algo::SHA_256, Nonce_Format::AEAD_IMPLICIT_4),
      Ciphersuite(0xC0AE, "ECDHE_ECDSA_WITH_AES_128_CCM_8", Auth_Method::ECDSA, Kex_Algo::ECDH, "AES-128/CCM(8)", 16, "AEAD", 0, KDF_Algo::SHA_256, Nonce_Format::AEAD_IMPLICIT_4),
      Ciphersuite(0xC0AF, "ECDHE_ECDSA_WITH_AES_256_CCM_8", Auth_Method::ECDSA, Kex_Algo::ECDH, "AES-256/CCM(8)", 32, "AEAD", 0, KDF_Algo::SHA_256, Nonce_Format::AEAD_IMPLICIT_4),
      Ciphersuite(0xCCA8, "ECDHE_RSA_WITH_CHACHA20_POLY1305_SHA256", Auth_Method::RSA, Kex_Algo::ECDH, "ChaCha20Poly1305", 32, "AEAD", 0, KDF_Algo::SHA_256, Nonce_Format::AEAD_XOR_12),
      Ciphersuite(0xCCA9, "ECDHE_ECDSA_WITH_CHACHA20_POLY1305_SHA256", Auth_Method::ECDSA, Kex_Algo::ECDH, "ChaCha20Poly1305", 32, "AEAD", 0, KDF_Algo::SHA_256, Nonce_Format::AEAD_XOR_12),
      Ciphersuite(0xCCAA, "DHE_RSA_WITH_CHACHA20_POLY1305_SHA256", Auth_Method::RSA, Kex_Algo::DH, "ChaCha20Poly1305", 32, "AEAD", 0, KDF_Algo::SHA_256, Nonce_Format::AEAD_XOR_12),
      Ciphersuite(0xCCAB, "PSK_WITH_CHACHA20_POLY1305_SHA256", Auth_Method::IMPLICIT, Kex_Algo::PSK, "ChaCha20Poly1305", 32, "AEAD", 0, KDF_Algo::SHA_256, Nonce_Format::AEAD_XOR_12),
      Ciphersuite(0xCCAC, "ECDHE_PSK_WITH_CHACHA20_POLY1305_SHA256", Auth_Method::IMPLICIT, Kex_Algo::ECDHE_PSK, "ChaCha20Poly1305", 32, "AEAD", 0, KDF_Algo::SHA_256, Nonce_Format::AEAD_XOR_12),
      Ciphersuite(0xCCAD, "DHE_PSK_WITH_CHACHA20_POLY1305_SHA256", Auth_Method::IMPLICIT, Kex_Algo::DHE_PSK, "ChaCha20Poly1305", 32, "AEAD", 0, KDF_Algo::SHA_256, Nonce_Format::AEAD_XOR_12),
      Ciphersuite(0xD001, "ECDHE_PSK_WITH_AES_128_GCM_SHA256", Auth_Method::IMPLICIT, Kex_Algo::ECDHE_PSK, "AES-128/GCM", 16, "AEAD", 0, KDF_Algo::SHA_256, Nonce_Format::AEAD_IMPLICIT_4),
      Ciphersuite(0xD002, "ECDHE_PSK_WITH_AES_256_GCM_SHA384", Auth_Method::IMPLICIT, Kex_Algo::ECDHE_PSK, "AES-256/GCM", 32, "AEAD", 0, KDF_Algo::SHA_384, Nonce_Format::AEAD_IMPLICIT_4),
      Ciphersuite(0xD003, "ECDHE_PSK_WITH_AES_128_CCM_8_SHA256", Auth_Method::IMPLICIT, Kex_Algo::ECDHE_PSK, "AES-128/CCM(8)", 16, "AEAD", 0, KDF_Algo::SHA_256, Nonce_Format::AEAD_IMPLICIT_4),
      Ciphersuite(0xD005, "ECDHE_PSK_WITH_AES_128_CCM_SHA256", Auth_Method::IMPLICIT, Kex_Algo::ECDHE_PSK, "AES-128/CCM", 16, "AEAD", 0, KDF_Algo::SHA_256, Nonce_Format::AEAD_IMPLICIT_4),
      Ciphersuite(0xFFC0, "DHE_RSA_WITH_AES_128_OCB_SHA256", Auth_Method::RSA, Kex_Algo::DH, "AES-128/OCB(12)", 16, "AEAD", 0, KDF_Algo::SHA_256, Nonce_Format::AEAD_XOR_12),
      Ciphersuite(0xFFC1, "DHE_RSA_WITH_AES_256_OCB_SHA256", Auth_Method::RSA, Kex_Algo::DH, "AES-256/OCB(12)", 32, "AEAD", 0, KDF_Algo::SHA_256, Nonce_Format::AEAD_XOR_12),
      Ciphersuite(0xFFC2, "ECDHE_RSA_WITH_AES_128_OCB_SHA256", Auth_Method::RSA, Kex_Algo::ECDH, "AES-128/OCB(12)", 16, "AEAD", 0, KDF_Algo::SHA_256, Nonce_Format::AEAD_XOR_12),
      Ciphersuite(0xFFC3, "ECDHE_RSA_WITH_AES_256_OCB_SHA256", Auth_Method::RSA, Kex_Algo::ECDH, "AES-256/OCB(12)", 32, "AEAD", 0, KDF_Algo::SHA_256, Nonce_Format::AEAD_XOR_12),
      Ciphersuite(0xFFC4, "ECDHE_ECDSA_WITH_AES_128_OCB_SHA256", Auth_Method::ECDSA, Kex_Algo::ECDH, "AES-128/OCB(12)", 16, "AEAD", 0, KDF_Algo::SHA_256, Nonce_Format::AEAD_XOR_12),
      Ciphersuite(0xFFC5, "ECDHE_ECDSA_WITH_AES_256_OCB_SHA256", Auth_Method::ECDSA, Kex_Algo::ECDH, "AES-256/OCB(12)", 32, "AEAD", 0, KDF_Algo::SHA_256, Nonce_Format::AEAD_XOR_12),
      Ciphersuite(0xFFC6, "PSK_WITH_AES_128_OCB_SHA256", Auth_Method::IMPLICIT, Kex_Algo::PSK, "AES-128/OCB(12)", 16, "AEAD", 0, KDF_Algo::SHA_256, Nonce_Format::AEAD_XOR_12),
      Ciphersuite(0xFFC7, "PSK_WITH_AES_256_OCB_SHA256", Auth_Method::IMPLICIT, Kex_Algo::PSK, "AES-256/OCB(12)", 32, "AEAD", 0, KDF_Algo::SHA_256, Nonce_Format::AEAD_XOR_12),
      Ciphersuite(0xFFC8, "DHE_PSK_WITH_AES_128_OCB_SHA256", Auth_Method::IMPLICIT, Kex_Algo::DHE_PSK, "AES-128/OCB(12)", 16, "AEAD", 0, KDF_Algo::SHA_256, Nonce_Format::AEAD_XOR_12),
      Ciphersuite(0xFFC9, "DHE_PSK_WITH_AES_256_OCB_SHA256", Auth_Method::IMPLICIT, Kex_Algo::DHE_PSK, "AES-256/OCB(12)", 32, "AEAD", 0, KDF_Algo::SHA_256, Nonce_Format::AEAD_XOR_12),
      Ciphersuite(0xFFCA, "ECDHE_PSK_WITH_AES_128_OCB_SHA256", Auth_Method::IMPLICIT, Kex_Algo::ECDHE_PSK, "AES-128/OCB(12)", 16, "AEAD", 0, KDF_Algo::SHA_256, Nonce_Format::AEAD_XOR_12),
      Ciphersuite(0xFFCB, "ECDHE_PSK_WITH_AES_256_OCB_SHA256", Auth_Method::IMPLICIT, Kex_Algo::ECDHE_PSK, "AES-256/OCB(12)", 32, "AEAD", 0, KDF_Algo::SHA_256, Nonce_Format::AEAD_XOR_12),
      Ciphersuite(0xFFCC, "CECPQ1_RSA_WITH_AES_256_OCB_SHA256", Auth_Method::RSA, Kex_Algo::CECPQ1, "AES-256/OCB(12)", 32, "AEAD", 0, KDF_Algo::SHA_256, Nonce_Format::AEAD_XOR_12),
      Ciphersuite(0xFFCD, "CECPQ1_ECDSA_WITH_AES_256_OCB_SHA256", Auth_Method::ECDSA, Kex_Algo::CECPQ1, "AES-256/OCB(12)", 32, "AEAD", 0, KDF_Algo::SHA_256, Nonce_Format::AEAD_XOR_12),
      };

   return g_ciphersuite_list;
   }

}

}
