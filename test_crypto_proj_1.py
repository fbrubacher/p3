import unittest

import crypto_proj


class TestCryptoProject(unittest.TestCase):

    def setUp(self):
        self.proj = crypto_proj.CryptoProject()

    def test_task_1(self):
        m = self.proj.task_1()
        self.assertEqual(m, '0x232eb2585b6f919e3d72df04aa3e67')

    def test_task_2(self):
        password, salt = self.proj.task_2()
        self.assertEqual(password, 'amelia')
        self.assertEqual(salt, 'hotstuff')

    def test_task_3(self):
        d = self.proj.task_3()
        self.assertEqual(d, '0x5ae3f468128c9b1')

    def test_task_4(self):
        d, waldo = self.proj.task_4()
        self.assertEqual(d, '0xab0d9fdbd00975e5d6379efc12a86d96b4c6ff62bf3e9e3541851855e32edf132d5998c6fcfc27813647a32631c62164106ed65b86e493a510a17342a137c5c41a45530acf7876d170c15cdedb3604aa9166e2fc2e3e3d1976c3b6be293b67cfb9e7977c3b4e9e80ce06073a3119d2a9d91f8410f1271a860fec0bd223701801')
        self.assertEqual(waldo, '561bcea6072580b91ef4b9c24feec5409dfcc7cdf955be9e558a5af6')

    def test_task_5(self):
        msg = self.proj.task_5()
        self.assertEqual(msg, 'bdornier3, how are you doing? Me? I\'m in a glass case of emotion!')


if __name__ == '__main__':
    unittest.main()
