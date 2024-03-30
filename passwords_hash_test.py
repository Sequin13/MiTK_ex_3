import unittest
from LoginHasher import Login_Hasher

class TestLoginHasher(unittest.TestCase):

    def setUp(self):
        self.db_file = 'test.db'
        self.login_hasher = Login_Hasher(self.db_file)

    def test_add_user(self):
        self.login_hasher.add_user('test_user', 'password123')
        self.assertTrue(self.login_hasher.verify_login('test_user', 'password123'))

    def test_verify_login_correct(self):
        self.assertTrue(self.login_hasher.verify_login('test_user', 'password123'))

    def test_already_taken_login(self):
        self.login_hasher.add_user('test_user', 'password567')
        with self.assertLogs() as cm:
            self.login_hasher.add_user('test_user', 'password567')
        self.assertIn('Login is already taken.', cm.output[0])

    def test_verify_login_incorrect(self):
        self.assertFalse(self.login_hasher.verify_login('test_user', 'wrong_password'))

    def test_verify_login_non_existent_user(self):
        self.assertFalse(self.login_hasher.verify_login('non_existent_user', 'password'))

if __name__ == '__main__':
    unittest.main()
