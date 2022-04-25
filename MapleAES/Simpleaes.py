"""Simple AES cipher implementation in pure Python following PEP-272 API
Homepage: https://bitbucket.org/intgr/pyaes/
The goal of this module is to be as fast as reasonable in Python while still
being Pythonic and readable/understandable. It is licensed under the permissive
MIT license.
Hopefully the code is readable and commented enough that it can serve as an
introduction to the AES cipher for Python coders. In fact, it should go along
well with the Stick Figure Guide to AES:
http://www.moserware.com/2009/09/stick-figure-guide-to-advanced.html
Contrary to intuition, this implementation numbers the 4x4 matrices from top to
bottom for efficiency reasons::
  0  4  8 12
  1  5  9 13
  2  6 10 14
  3  7 11 15
Effectively it's the transposition of what you'd expect. This actually makes
the code simpler -- except the ShiftRows step, but hopefully the explanation
there clears it up.
"""

####
# Copyright (c) 2010 Marti Raudsepp <marti@juffo.org>
#
# Permission is hereby granted, free of charge, to any person obtaining a copy
# of this software and associated documentation files (the "Software"), to deal
# in the Software without restriction, including without limitation the rights
# to use, copy, modify, merge, publish, distribute, sublicense, and/or sell
# copies of the Software, and to permit persons to whom the Software is
# furnished to do so, subject to the following conditions:
#
# The above copyright notice and this permission notice shall be included in
# all copies or substantial portions of the Software.
#
# THE SOFTWARE IS PROVIDED "AS IS", WITHOUT WARRANTY OF ANY KIND, EXPRESS OR
# IMPLIED, INCLUDING BUT NOT LIMITED TO THE WARRANTIES OF MERCHANTABILITY,
# FITNESS FOR A PARTICULAR PURPOSE AND NONINFRINGEMENT. IN NO EVENT SHALL THE
# AUTHORS OR COPYRIGHT HOLDERS BE LIABLE FOR ANY CLAIM, DAMAGES OR OTHER
# LIABILITY, WHETHER IN AN ACTION OF CONTRACT, TORT OR OTHERWISE, ARISING FROM,
# OUT OF OR IN CONNECTION WITH THE SOFTWARE OR THE USE OR OTHER DEALINGS IN
# THE SOFTWARE.
####


from array import array

# Globals mandated by PEP 272:
# http://www.python.org/dev/peps/pep-0272/
MODE_ECB = 1
MODE_CBC = 2
#MODE_CTR = 6

block_size = 16
# variable length key: 16, 24 or 32 bytes
key_size = None

def new(key, mode, IV=None):
    if mode == MODE_ECB:
        return ECBMode(AES(key))
    elif mode == MODE_CBC:
        if IV is None:
            raise ValueError

        return CBCMode(AES(key), IV)
    else:
        raise NotImplementedError

#### AES cipher implementation

class AES(object):
    block_size = 16

    def __init__(self, key):
        self.setkey(key)

    def setkey(self, key):
        """Sets the key and performs key expansion."""

        self.key = key
        self.key_size = len(key)

        if self.key_size == 16:
            self.rounds = 10
        elif self.key_size == 24:
            self.rounds = 12
        elif self.key_size == 32:
            self.rounds = 14
        else:
            raise ValueError

        self.expand_key()

    def expand_key(self):
        """Performs AES key expansion on self.key and stores in self.exkey"""

        # The key schedule specifies how parts of the key are fed into the
        # cipher's round functions. "Key expansion" means performing this
        # schedule in advance. Almost all implementations do this.
        #
        # Here's a description of AES key schedule:
        # http://en.wikipedia.org/wiki/Rijndael_key_schedule

        # The expanded key starts with the actual key itself
        exkey = array('B', self.key)

        # extra key expansion steps
        if self.key_size == 16:
            extra_cnt = 0
        elif self.key_size == 24:
            extra_cnt = 2
        else:
            extra_cnt = 3

        # 4-byte temporary variable for key expansion
        word = exkey[-4:]
        # Each expansion cycle uses 'i' once for Rcon table lookup
        for i in range(1, 11):

            #### key schedule core:
            # left-rotate by 1 byte
            word = word[1:4] + word[0:1]

            # apply S-box to all bytes
            for j in range(4):
                word[j] = aes_sbox[word[j]]

            # apply the Rcon table to the leftmost byte
            word[0] ^= aes_Rcon[i]
            #### end key schedule core

            for z in range(4):
                for j in range(4):
                    # mix in bytes from the last subkey
                    word[j] ^= exkey[-self.key_size + j]
                exkey.extend(word)

            # Last key expansion cycle always finishes here
            if len(exkey) >= (self.rounds+1) * self.block_size:
                break

            # Special substitution step for 256-bit key
            if self.key_size == 32:
                for j in range(4):
                    # mix in bytes from the last subkey XORed with S-box of
                    # current word bytes
                    word[j] = aes_sbox[word[j]] ^ exkey[-self.key_size + j]
                exkey.extend(word)

            # Twice for 192-bit key, thrice for 256-bit key
            for z in range(extra_cnt):
                for j in range(4):
                    # mix in bytes from the last subkey
                    word[j] ^= exkey[-self.key_size + j]
                exkey.extend(word)

        self.exkey = exkey

    def add_round_key(self, block, round):
        """AddRoundKey step in AES. This is where the key is mixed into plaintext"""

        offset = round * 16
        exkey = self.exkey

        for i in range(16):
            block[i] ^= exkey[offset + i]

        #print 'AddRoundKey:', block

    def sub_bytes(self, block, sbox):
        """SubBytes step, apply S-box to all bytes
        Depending on whether encrypting or decrypting, a different sbox array
        is passed in.
        """

        for i in range(16):
            block[i] = sbox[block[i]]

        #print 'SubBytes   :', block

    def shift_rows(self, b):
        """ShiftRows step. Shifts 2nd row to left by 1, 3rd row by 2, 4th row by 3
        Since we're performing this on a transposed matrix, cells are numbered
        from top to bottom first::
          0  4  8 12   ->    0  4  8 12    -- 1st row doesn't change
          1  5  9 13   ->    5  9 13  1    -- row shifted to left by 1 (wraps around)
          2  6 10 14   ->   10 14  2  6    -- shifted by 2
          3  7 11 15   ->   15  3  7 11    -- shifted by 3
        """

        b[1], b[5], b[ 9], b[13] = b[ 5], b[ 9], b[13], b[ 1]
        b[2], b[6], b[10], b[14] = b[10], b[14], b[ 2], b[ 6]
        b[3], b[7], b[11], b[15] = b[15], b[ 3], b[ 7], b[11]

        #print 'ShiftRows  :', b

    def shift_rows_inv(self, b):
        """Similar to shift_rows above, but performed in inverse for decryption."""

        b[ 5], b[ 9], b[13], b[ 1] = b[1], b[5], b[ 9], b[13]
        b[10], b[14], b[ 2], b[ 6] = b[2], b[6], b[10], b[14]
        b[15], b[ 3], b[ 7], b[11] = b[3], b[7], b[11], b[15]

        #print 'ShiftRows  :', b

    def mix_columns(self, block):
        """MixColumns step. Mixes the values in each column"""

        # Cache global multiplication tables (see below)
        mul_by_2 = gf_mul_by_2
        mul_by_3 = gf_mul_by_3

        # Since we're dealing with a transposed matrix, columns are already
        # sequential
        for col in range(0, 16, 4):
            v0, v1, v2, v3 = block[col : col+4]

            block[col  ] = mul_by_2[v0] ^ v3 ^ v2 ^ mul_by_3[v1]
            block[col+1] = mul_by_2[v1] ^ v0 ^ v3 ^ mul_by_3[v2]
            block[col+2] = mul_by_2[v2] ^ v1 ^ v0 ^ mul_by_3[v3]
            block[col+3] = mul_by_2[v3] ^ v2 ^ v1 ^ mul_by_3[v0]

        #print 'MixColumns :', block

    def mix_columns_inv(self, block):
        """Similar to mix_columns above, but performed in inverse for decryption."""

        # Cache global multiplication tables (see below)
        mul_9  = gf_mul_by_9
        mul_11 = gf_mul_by_11
        mul_13 = gf_mul_by_13
        mul_14 = gf_mul_by_14

        # Since we're dealing with a transposed matrix, columns are already
        # sequential
        for col in range(0, 16, 4):
            v0, v1, v2, v3 = block[col : col+4]

            block[col  ] = mul_14[v0] ^ mul_9[v3] ^ mul_13[v2] ^ mul_11[v1]
            block[col+1] = mul_14[v1] ^ mul_9[v0] ^ mul_13[v3] ^ mul_11[v2]
            block[col+2] = mul_14[v2] ^ mul_9[v1] ^ mul_13[v0] ^ mul_11[v3]
            block[col+3] = mul_14[v3] ^ mul_9[v2] ^ mul_13[v1] ^ mul_11[v0]

        #print 'MixColumns :', block

    def encrypt_block(self, block):
        """Encrypts a single block. This is the main AES function"""

        # For efficiency reasons, the state between steps is transmitted via a
        # mutable array, not returned
        self.add_round_key(block, 0)

        for round in range(1, self.rounds):
            self.sub_bytes(block, aes_sbox)
            self.shift_rows(block)
            self.mix_columns(block)
            self.add_round_key(block, round)

        self.sub_bytes(block, aes_sbox)
        self.shift_rows(block)
        # no mix_columns step in the last round
        self.add_round_key(block, self.rounds)

    def decrypt_block(self, block):
        """Decrypts a single block. This is the main AES decryption function"""

        # For efficiency reasons, the state between steps is transmitted via a
        # mutable array, not returned
        self.add_round_key(block, self.rounds)

        # count rounds down from (self.rounds) ... 1
        for round in range(self.rounds-1, 0, -1):
            self.shift_rows_inv(block)
            self.sub_bytes(block, aes_inv_sbox)
            self.add_round_key(block, round)
            self.mix_columns_inv(block)

        self.shift_rows_inv(block)
        self.sub_bytes(block, aes_inv_sbox)
        self.add_round_key(block, 0)
        # no mix_columns step in the last round


#### ECB mode implementation

class ECBMode(object):
    """Electronic CodeBook (ECB) mode encryption.
    Basically this mode applies the cipher function to each block individually;
    no feedback is done. NB! This is insecure for almost all purposes
    """

    def __init__(self, cipher):
        self.cipher = cipher
        self.block_size = cipher.block_size

    def ecb(self, data, block_func):
        """Perform ECB mode with the given function"""

        if len(data) % self.block_size != 0:
            raise ValueError

        block_size = self.block_size
        data = array('B', data)

        for offset in range(0, len(data), block_size):
            block = data[offset : offset+block_size]
            block_func(block)
            data[offset : offset+block_size] = block

        return data.tostring()

    def encrypt(self, data):
        """Encrypt data in ECB mode"""

        return self.ecb(data, self.cipher.encrypt_block)

    def decrypt(self, data):
        """Decrypt data in ECB mode"""

        return self.ecb(data, self.cipher.decrypt_block)

#### CBC mode

class CBCMode(object):
    """Cipher Block Chaining (CBC) mode encryption. This mode avoids content leaks.
    In CBC encryption, each plaintext block is XORed with the ciphertext block
    preceding it; decryption is simply the inverse.
    """

    # A better explanation of CBC can be found here:
    # http://en.wikipedia.org/wiki/Block_cipher_modes_of_operation#Cipher-block_chaining_.28CBC.29

    def __init__(self, cipher, IV):
        self.cipher = cipher
        self.block_size = cipher.block_size
        self.IV = array('B', IV)

    def encrypt(self, data):
        """Encrypt data in CBC mode"""

        block_size = self.block_size
        if len(data) % block_size != 0:
            raise ValueError

        data = array('B', data)
        IV = self.IV

        for offset in range(0, len(data), block_size):
            block = data[offset : offset+block_size]

            # Perform CBC chaining
            for i in range(block_size):
                block[i] ^= IV[i]

            self.cipher.encrypt_block(block)
            data[offset : offset+block_size] = block
            IV = block

        self.IV = IV
        return data.tostring()

    def decrypt(self, data):
        """Decrypt data in CBC mode"""

        block_size = self.block_size
        if len(data) % block_size != 0:
            raise ValueError

        data = array('B', data)
        IV = self.IV

        for offset in range(0, len(data), block_size):
            ctext = data[offset : offset+block_size]
            block = ctext[:]
            self.cipher.decrypt_block(block)

            # Perform CBC chaining
            #for i in range(block_size):
            #    data[offset + i] ^= IV[i]
            for i in range(block_size):
                block[i] ^= IV[i]
            data[offset : offset+block_size] = block

            IV = ctext
            #data[offset : offset+block_size] = block

        self.IV = IV
        return data.tostring()

####

def galois_multiply(a, b):
    """Galois Field multiplicaiton for AES"""
    p = 0
    while b:
        if b & 1:
            p ^= a
        a <<= 1
        if a & 0x100:
            a ^= 0x1b
        b >>= 1

    return p & 0xff

# Precompute the multiplication tables for encryption
gf_mul_by_2  = array('B', [galois_multiply(x,  2) for x in range(256)])
gf_mul_by_3  = array('B', [galois_multiply(x,  3) for x in range(256)])
# ... for decryption
gf_mul_by_9  = array('B', [galois_multiply(x,  9) for x in range(256)])
gf_mul_by_11 = array('B', [galois_multiply(x, 11) for x in range(256)])
gf_mul_by_13 = array('B', [galois_multiply(x, 13) for x in range(256)])
gf_mul_by_14 = array('B', [galois_multiply(x, 14) for x in range(256)])

####

# The S-box is a 256-element array, that maps a single byte value to another
# byte value. Since it's designed to be reversible, each value occurs only once
# in the S-box
#
# More information: http://en.wikipedia.org/wiki/Rijndael_S-box

aes_sbox = array('B', [99, 124, 119, 123, 242, 107, 111, 197, 48, 1, 103, 43, 254, 215, 171, 118, 202, 130, 201, 125, 250, 89, 71, 240, 173, 212, 162, 175, 156, 164, 114, 192, 183, 253, 147, 38, 54, 63, 247, 204, 52, 165, 229, 241, 113, 216, 49, 21, 4, 199, 35, 195, 24, 150, 5, 154, 7, 18, 128, 226, 235, 39, 178, 117, 9, 131, 44, 26, 27, 110, 90, 160, 82, 59, 214, 179, 41, 227, 47, 132, 83, 209, 0, 237, 32, 252, 177, 91, 106, 203, 190, 57, 74, 76, 88, 207, 208, 239, 170, 251, 67, 77, 51, 133, 69, 249, 2, 127, 80, 60, 159, 168, 81, 163, 64, 143, 146, 157, 56, 245, 188, 182, 218, 33, 16, 255, 243, 210, 205, 12, 19, 236, 95, 151, 68, 23, 196, 167, 126, 61, 100, 93, 25, 115, 96, 129, 79, 220, 34, 42, 144, 136, 70, 238, 184, 20, 222, 94, 11, 219, 224, 50, 58, 10, 73, 6, 36, 92, 194, 211, 172, 98, 145, 149, 228, 121, 231, 200, 55, 109, 141, 213, 78, 169, 108, 86, 244, 234, 101, 122, 174, 8, 186, 120, 37, 46, 28, 166, 180, 198, 232, 221, 116, 31, 75, 189, 139, 138, 112, 62, 181, 102, 72, 3, 246, 14, 97, 53, 87, 185, 134, 193, 29, 158, 225, 248, 152, 17, 105, 217, 142, 148, 155, 30, 135, 233, 206, 85, 40, 223, 140, 161, 137, 13, 191, 230, 66, 104, 65, 153, 45, 15, 176, 84, 187, 22])

# This is the inverse of the above. In other words:
# aes_inv_sbox[aes_sbox[val]] == val

aes_inv_sbox = array('B', [82, 9, 106, 213, 48, 54, 165, 56, 191, 64, 163, 158, 129, 243, 215, 251, 124, 227, 57, 130, 155, 47, 255, 135, 52, 142, 67, 68, 196, 222, 233, 203, 84, 123, 148, 50, 166, 194, 35, 61, 238, 76, 149, 11, 66, 250, 195, 78, 8, 46, 161, 102, 40, 217, 36, 178, 118, 91, 162, 73, 109, 139, 209, 37, 114, 248, 246, 100, 134, 104, 152, 22, 212, 164, 92, 204, 93, 101, 182, 146, 108, 112, 72, 80, 253, 237, 185, 218, 94, 21, 70, 87, 167, 141, 157, 132, 144, 216, 171, 0, 140, 188, 211, 10, 247, 228, 88, 5, 184, 179, 69, 6, 208, 44, 30, 143, 202, 63, 15, 2, 193, 175, 189, 3, 1, 19, 138, 107, 58, 145, 17, 65, 79, 103, 220, 234, 151, 242, 207, 206, 240, 180, 230, 115, 150, 172, 116, 34, 231, 173, 53, 133, 226, 249, 55, 232, 28, 117, 223, 110, 71, 241, 26, 113, 29, 41, 197, 137, 111, 183, 98, 14, 170, 24, 190, 27, 252, 86, 62, 75, 198, 210, 121, 32, 154, 219, 192, 254, 120, 205, 90, 244, 31, 221, 168, 51, 136, 7, 199, 49, 177, 18, 16, 89, 39, 128, 236, 95, 96, 81, 127, 169, 25, 181, 74, 13, 45, 229, 122, 159, 147, 201, 156, 239, 160, 224, 59, 77, 174, 42, 245, 176, 200, 235, 187, 60, 131, 83, 153, 97, 23, 43, 4, 126, 186, 119, 214, 38, 225, 105, 20, 99, 85, 33, 12, 125])

# The Rcon table is used in AES's key schedule (key expansion)
# It's a pre-computed table of exponentation of 2 in AES's finite field
#
# More information: http://en.wikipedia.org/wiki/Rijndael_key_schedule

aes_Rcon = array('B', [141, 1, 2, 4, 8, 16, 32, 64, 128, 27, 54, 108, 216, 171, 77, 154, 47, 94, 188, 99, 198, 151, 53, 106, 212, 179, 125, 250, 239, 197, 145, 57, 114, 228, 211, 189, 97, 194, 159, 37, 74, 148, 51, 102, 204, 131, 29, 58, 116, 232, 203, 141, 1, 2, 4, 8, 16, 32, 64, 128, 27, 54, 108, 216, 171, 77, 154, 47, 94, 188, 99, 198, 151, 53, 106, 212, 179, 125, 250, 239, 197, 145, 57, 114, 228, 211, 189, 97, 194, 159, 37, 74, 148, 51, 102, 204, 131, 29, 58, 116, 232, 203, 141, 1, 2, 4, 8, 16, 32, 64, 128, 27, 54, 108, 216, 171, 77, 154, 47, 94, 188, 99, 198, 151, 53, 106, 212, 179, 125, 250, 239, 197, 145, 57, 114, 228, 211, 189, 97, 194, 159, 37, 74, 148, 51, 102, 204, 131, 29, 58, 116, 232, 203, 141, 1, 2, 4, 8, 16, 32, 64, 128, 27, 54, 108, 216, 171, 77, 154, 47, 94, 188, 99, 198, 151, 53, 106, 212, 179, 125, 250, 239, 197, 145, 57, 114, 228, 211, 189, 97, 194, 159, 37, 74, 148, 51, 102, 204, 131, 29, 58, 116, 232, 203, 141, 1, 2, 4, 8, 16, 32, 64, 128, 27, 54, 108, 216, 171, 77, 154, 47, 94, 188, 99, 198, 151, 53, 106, 212, 179, 125, 250, 239, 197, 145, 57, 114, 228, 211, 189, 97, 194, 159, 37, 74, 148, 51, 102, 204, 131, 29, 58, 116, 232, 203])
