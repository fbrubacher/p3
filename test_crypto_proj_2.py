import unittest

import crypto_proj


class TestCryptoProject(unittest.TestCase):

    def setUp(self):
        self.proj = crypto_proj.CryptoProject()

    def test_task_1(self):
        m = self.proj.task_1()
        self.assertEqual(m, '0xcbc57a9e3e49a87e3b9f14d132ff302f')

    def test_task_2(self):
        password, salt = self.proj.task_2()
        self.assertEqual(password, 'lollypop')
        self.assertEqual(salt, 'bandit')

    def test_task_3(self):
        d = self.proj.task_3()
        self.assertEqual(d, '0x803370c3c0ee601')

    def test_task_4(self):
        d, waldo = self.proj.task_4()
        self.assertEqual(d, '0x39b90dd975e376f70d0188b9a916b21f4bdcca4d9cfe74f52cf7500eb11aa63d65dd9674b79d7e9650d5df525c6a620e4c4b8afc7d960cf0308f39aa77277b940cfdf86caae9244dd61466097dcf60f12058845d9f3af5a2b2cb1c702cc3b7326872d7dc58edde7f9bedc4da72399997b51120ff0832ba72a81c3fe3925b3061')
        self.assertEqual(waldo, '98f479d9fce5842e6361d3b600f03a5ce64ac7d7b306766c5a82aa83')

    def test_task_5(self):
        msg = self.proj.task_5()
        self.assertEqual(msg, 'ctaylor, how are you doing? Me? I\'m in a glass case of emotion!')


if __name__ == '__main__':
    unittest.main()
