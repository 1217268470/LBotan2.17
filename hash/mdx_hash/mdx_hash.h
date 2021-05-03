/*
* MDx Hash Function
* (C) 1999-2008 Jack Lloyd
*
* Botan is released under the Simplified BSD License (see license.txt)
*/

#ifndef BOTAN_MDX_BASE_H_
#define BOTAN_MDX_BASE_H_

//#include <botan/hash.h>
#include "hash/hash.h"

BOTAN_FUTURE_INTERNAL_HEADER(mdx_hash.h)

namespace Botan {

/**
* MDx Hash Function Base Class
*/
class BOTAN_PUBLIC_API(2,0) MDx_HashFunction : public HashFunction
   {
   public:
      /**
      * @param block_length is the number of bytes per block, which must
      *        be a power of 2 and at least 8.
      * @param big_byte_endian specifies if the hash uses big-endian bytes
      * @param big_bit_endian specifies if the hash uses big-endian bits
      * @param counter_size specifies the size of the counter var in bytes
      */
      MDx_HashFunction(size_t block_length,
                       bool big_byte_endian,
                       bool big_bit_endian,
                       uint8_t counter_size = 8);

      size_t hash_block_size() const override final { return m_buffer.size(); }


      /**
      * @return provider information about this implementation. Default is "base",
      * might also return "sse2", "avx2", "openssl", or some other arbitrary string.
      */
      virtual std::string provider() const { return "base"; }

//       ~MDx_HashFunction() = default;


      /**
      * @return the hash function name
      */
       std::string name() const = 0;



      /**
      * Return a new hash object with the same state as *this. This
      * allows computing the hash of several messages with a common
      * prefix more efficiently than would otherwise be possible.
      *
      * This function should be called `clone` but that was already
      * used for the case of returning an uninitialized object.
      * @return new hash object
      */
       std::unique_ptr<HashFunction> copy_state() const = 0;
   protected:
      void add_data(const uint8_t input[], size_t length) override final;
      void final_result(uint8_t output[]) override final;

      /**
      * Run the hash's compression function over a set of blocks
      * @param blocks the input
      * @param block_n the number of blocks
      */
      virtual void compress_n(const uint8_t blocks[], size_t block_n) = 0;

      void clear() override;

      /**
      * Copy the output to the buffer
      * @param buffer to put the output into
      */
      virtual void copy_out(uint8_t buffer[]) = 0;

      /**
      * Write the count, if used, to this spot
      * @param out where to write the counter to
      */
      virtual void write_count(uint8_t out[]);
   private:
      const uint8_t m_pad_char;
      const uint8_t m_counter_size;
      const uint8_t m_block_bits;
      const bool m_count_big_endian;

      uint64_t m_count;
      secure_vector<uint8_t> m_buffer;
      size_t m_position;
   };

}

#endif
