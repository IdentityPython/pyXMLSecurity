
import unittest
from xmlsec.DataPrimitives import DataPrimitives
from xmlsec.utils import dsssig2sigvalue, sigvalue2dsssig, b64e, b64d

dp = DataPrimitives()


class UtilTest(unittest.TestCase):

    def test_ip_o(self):
        x = 1432
        arr = dp.I2OSP(x, 32)
        assert(arr is not None)
        y = dp.OS2IP(arr)
        assert (y == x)
