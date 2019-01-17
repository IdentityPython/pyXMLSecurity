# Data Primitives conversions
# according to ISO 18033 and PKCS#1
# Author: Peio Popov <peio@peio.org>
# License: Public Domain
# Version: 0.5

"""
Example usage:

from DataPrimitives import DataPrimitives

dp = DataPrimitives()

# Convert string to bits
string2bits    = dp.OS2BSP('abc')
# string2bits  = 011000010110001001100011

# Convert bits to integer
bits2integer   = dp.BS2IP('011000010110001001100011')
# bits2integer = 6382179

# Convert integer string to string
integer2string = dp.I2OSP(6382179, 3)
# integer2string = abc
"""

import six

# TODO: Add various level of explanation
# TODO: Add reference implementaions


class ISO18033Primitives:

    def __init__(self, explain=False):
        self.__all__ = ['Explain', 'OS2BSP', 'BS2OSP', 'BS2IP', 'I2BSP', 'OS2IP', 'I2OSP', 'strxor']
        self.explain = explain

    def Explain(self, explanation, *vars):
        """Print an explanation message"""
        if self.explain:
            print(explanation % vars)

    # A bit is one of the two symbols 0 or 1.
    # An octet is a bit string of length 8.

    # 5.2.4 Bit string/integer conversion
    # Primitives BS2IP and I2BSP to convert between bit strings and integers are defined as follows.

    def BS2IP(self, x):
        """The function BS2IP (x) maps a bit string x to an integer value"""

        zero_pad = len(x) % 8
        x = x.zfill(zero_pad)
        bit_num = len(x) - 1
        sum = 0

        self.Explain('Convert %d bit string:%s to integer:', bit_num + 1, x)
        for bit in x:
            if self.explain:
                print('\tbit num', bit_num, 'is', bit,)
            if bit == '1':
                self.Explain('\tsum is %d + %d(2**%d) = %d', sum, 2 ** bit_num, bit_num, sum + 2 ** bit_num)
                sum = sum + 2 ** bit_num
            else:
                self.Explain('\tsum is %d', sum)

            bit_num = bit_num - 1
        self.Explain('Return: %d', sum)
        return sum

    def I2BSP(self, m, l):
        """The function I2BSP (m, l) takes as input two non-negative integers m and l, and outputs the
        unique bit string x of length l such that BS2IP (x) = m, if such an x exists. Otherwise, the
        function fails.
        """
        assert m >= 0, 'm should be non-negative integer'
        assert l >= 0, 'l should be non-negative integer'
        assert 2 ** l >= m, '2**l should be smaller than m'

        bit_str = ''
        reminder = m
        pow = l - 1

        self.Explain('Convert integer %d to %d bit string:', m, l)
        while pow >= 0:
            if reminder >= 2 ** pow:
                self.Explain('\tReminder: %d >= 2**%d(%d) - %dth bit is 1', reminder, pow, 2 ** pow, pow)
                reminder = reminder - 2 ** pow
                bit_str = bit_str + '1'
            else:
                self.Explain('\tReminder: %d <  2**%d(%d) - %dth bit is 0', reminder, pow, 2 ** pow, pow)
                bit_str = bit_str + '0'

            pow = pow - 1

        self.Explain('Return: %s', bit_str)
        return bit_str

    def BS2OSP(self, y):
        """The function BS2OSP (y) takes as input a bit string y, whose length is a multiple of 8, and
        outputs the unique octet string x such that y = OS2BSP (x)."""
        assert not (len(y) % 8), 'should be multiple of 8'

        octet_str = ''
        self.Explain('Convert bit string %s to symbol octets', y)
        for i in range(0, len(y) - 1, 8):
            bit_str = str(y[i:i + 8])
            ord_num = self.BS2IP(bit_str)
            ascii_char = chr(ord_num)
            octet_str = octet_str + ascii_char

            self.Explain('\t%s is decimal %d = ascii symbol: %s', bit_str, ord_num, ascii_char)

        self.Explain('Retrun: %s', octet_str)
        return octet_str

    def OS2BSP(self, x):
        """The function OS2BSP (x) takes as input an octet string x = x1 , . . . , xl , and outputs the bit
        string y = x1 - xl ."""

        bit_str = ''

        self.Explain('Convert string %s to bits:', x)
        for char in x:
            if isinstance(char, six.text_type) or isinstance(char, six.binary_type):
                x_ascii_num = ord(char)
            elif isinstance(char, six.integer_types):
                x_ascii_num = char
            else:
                raise ValueError('Unknown type ({}) for char'.format(type(char)))
            bit_str = bit_str + self.I2BSP(x_ascii_num, 8)
            self.Explain('\t%s is number %d which in binary is %s', char, x_ascii_num, bit_str[-8:])

        self.Explain('Return: %s', bit_str)
        return bit_str

    # 5.2.5.
    # ISO-18033-2 Primitives OS2IP and I2OSP to convert between octet strings and integers

    def OS2IP(self, x):
        """Takes as input an octet string BS2IP (OS2BSP (x)) and outputs the integer"""
        return self.BS2IP(self.OS2BSP(x))

    def I2OSP(self, m, l=16):
        """ The function I2OSP (m, l) takes as input two non-negative integers m and l, and outputs the
        unique octet string x of length l such that OS2IP (x) = m, if such an x exists. Otherwise, the
        function fails."""
        assert m >= 0, 'm should be non-negative integer'
        assert l > 0, 'm should be non-negative integer'

        m = self.I2BSP(m, l * 8)

        octet_string = ''
        for octet in range(0, len(m) - 1, 8):
            octet_string = octet_string + self.BS2OSP(m[octet:octet + 8])

        self.Explain('Return: %s', octet_string)
        return octet_string

    def strxor(self, a, b):
        """Accept octet strings a and b
        Return bit string xored result of xor of a and b"""
        a = self.OS2BSP(a)
        b = self.OS2BSP(b)

        if len(a) > len(b):
            a, b = b, a

        xored = ''
        for bit in range(0, len(a)):
            xored = xored + str(int(a[bit]) ^ int(b[bit]))

        self.Explain('XOR a and b:')
        self.Explain('a     = %s', a)
        self.Explain('b     = %s', b)
        self.Explain('xored = %s', xored)

        return xored


# Alias


class ISOPrimitives(ISO18033Primitives):
    pass


# Alias


class DataPrimitives(ISOPrimitives):
    pass


class PKCS1Primitives(ISO18033Primitives):
    """Defined in section 4 of RSA PKCS#1"""

    def OS2IP(self, X):
        """OS2IP converts an octet string to a nonnegative integer.
        OS2IP (X)
        Input: X octet string to be converted
        Output: x corresponding nonnegative integer"""

        xLen = len(X)
        x = 0

        # Base 256 encoding
        for i in range(0, xLen):
            char2int = ord(X[i])
            pow = xLen - i - 1
            x = x + 256 ** pow * char2int
            if self.explain:
                print('256**', pow, '* ord(' + X[i] + ')->', char2int, '=', 256 ** pow * char2int, '|', 'x =', x)

        return x

    def I2OSP(self, x, xLen):
        """I2OSP converts a nonnegative integer to an octet string of a specified length.
        I2OSP (x, xLen)
        Input: x nonnegative integer to be converted
        xLen intended length of the resulting octet string
        Output: X corresponding octet string of length xLen
        Error: "integer too large"
        """
        assert x > 0, 'x should be non-negative integer'
        assert x <= 256 ** xLen, 'integer too large'

        x = int(x)
        X = ''

        # Base 256 decoding
        for char in range(0, xLen):
            if self.explain:
                print(chr(x % 256), x)
            X = X + chr(x % 256)
            x = x - x % 256
            x = x / 256

        X = X[::-1]  # reverse string X
        return X


# Alias


class RSAPrimitives(PKCS1Primitives):
    pass


class ReferenceImplementations():
    from binascii import a2b_hex, b2a_hex

    def BS2IP(self, x):
        return long(x, 2)

    def BS2OSP(self, m):
        """m = int(m,2)
        m = char(m)"""
        # b2a_hex()

    def I2BSP(self, m, l):
        m = bin(m)[2:]
        m = m.zfill(l)

        return m

    def OS2BSP(self, m):
        # hex_string = '%X' % longint
        # print a2b_hex()
        pass

    def I2OSP(self, longint, length):
        """I2OSP(longint, length) -> bytes

        I2OSP converts a long integer into a string of bytes (an Octet String).
        It is defined in the  PKCS #1 v2.1: RSA Cryptography Standard (June 14, 2002)
        """
        hex_string = '%X' % longint
        if len(hex_string) > 2 * length:
            raise ValueError('integer %i too large to encode in %i octets' % (longint, length))
        return a2b_hex(hex_string.zfill(2 * length))

    def strxor(a, b):
        """XOR of two strings"""
        return "".join([chr(ord(x) ^ ord(y)) for (x, y) in zip(a, b)])


if __name__ == '__main__':
    print('''        Example usage:

        from DataPrimitives import DataPrimitives

        dp = DataPrimitives()

        # Convert string to bits
        string2bits    = dp.OS2BSP('abc') 
        # string2bits  = 011000010110001001100011

        # Convert bits to integer
        bits2integer   = dp.BS2IP('011000010110001001100011')
        # bits2integer = 6382179

        # Convert integer string to string
        integer2string = dp.I2OSP(6382179, 3)
        # integer2string = abc

        You may turn on the explanation mode by suppling a True argument to the main class. 

        Example: 
                tutor = DataPrimitives(True)
                tutor.BS2OSP("011000010110001001100011")  

        This will print out every transformation:
                Convert bit string 011000010110001001100011 to symbol octets
                Convert 8 bit string:01100001 to integer:
                    bit num 7 is 0     sum is 0
                    bit num 6 is 1     sum is 0 + 64(2**6) = 64
                    bit num 5 is 1     sum is 64 + 32(2**5) = 96
                    bit num 4 is 0     sum is 96
                    bit num 3 is 0     sum is 96
                    bit num 2 is 0     sum is 96
                    bit num 1 is 0     sum is 96
                    bit num 0 is 1     sum is 96 + 1(2**0) = 97
                Return: 97
                    01100001 is decimal 97 = ascii symbol: a
                Convert 8 bit string:01100010 to integer:
                    bit num 7 is 0     sum is 0
                    bit num 6 is 1     sum is 0 + 64(2**6) = 64
                    bit num 5 is 1     sum is 64 + 32(2**5) = 96
                    bit num 4 is 0     sum is 96
                    bit num 3 is 0     sum is 96
                    bit num 2 is 0     sum is 96
                    bit num 1 is 1     sum is 96 + 2(2**1) = 98
                    bit num 0 is 0     sum is 98
                Return: 98
                    01100010 is decimal 98 = ascii symbol: b
                Convert 8 bit string:01100011 to integer:
                    bit num 7 is 0     sum is 0
                    bit num 6 is 1     sum is 0 + 64(2**6) = 64
                    bit num 5 is 1     sum is 64 + 32(2**5) = 96
                    bit num 4 is 0     sum is 96
                    bit num 3 is 0     sum is 96
                    bit num 2 is 0     sum is 96
                    bit num 1 is 1     sum is 96 + 2(2**1) = 98
                    bit num 0 is 1     sum is 98 + 1(2**0) = 99
                Return: 99
                    01100011 is decimal 99 = ascii symbol: c
                Retrun: abc


        ''')
