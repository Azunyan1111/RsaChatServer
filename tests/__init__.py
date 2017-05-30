import unittest
import main
import base64
import hashlib


class TestStringMethods(unittest.TestCase):

    def test_setup_mongodb(self):
        main.debug = True
        main.setup_mongodb()
        self.assertEqual(main.db.name, "TestDataBase")
        self.assertEqual(main.users_collection.name, "UsersCollection")
        self.assertEqual(main.friend_collection.name, "FriendCollection")
        self.assertEqual(main.chat_collection.name, "CatCollection")

    def test_set_new_user(self):
        self.assertTrue(main.set_new_user("hoge", "foo").acknowledged)

    def test_check_rsa_public_key(self):
        self.assertTrue(main.check_rsa_public_key("-----BEGIN PUBLIC KEY-----"
                                                    "MIIBIjANBgkqhkiG9w0BAQEFAAOCAQ8AMIIBCgKCAQEAv88HOrKd/4VE5nixLLxy"
                                                    "Vwh7DMVcpOeuLpUOZUN2r6vbubzeiRbyQN1sidEn8TFfeDJ01ubERV+wpjhbIVs5"
                                                    "LE6f/nROhFAdSl7JKcaZFYnI4GxWSkO8zG9bvfCAKMFQBWpjAhttZIT3TMx/o77d"
                                                    "I+TAhf+jwPPG+Bwtptg/LHMDvd5LC8DxMmRDPCYw2QKQSLlEnYewFmW51bBAM1HB"
                                                    "68B5PTgNMZ/PfwK3mKqAezLkTm4gyYXUrmlyNHKIjCz9kD1OCafPBcSKguqFIWzn"
                                                    "LrsTsY/0SQ/0voxUC9NLN7TutekJoFpByY9nJ0JPgigXSbP2z8GeLRATj2sfGdQ9"
                                                    "KQIDAQAB"
                                                    "-----END PUBLIC KEY-----"))
        self.assertFalse(main.check_rsa_public_key("-----BEGIN PUBLIC KEY-----"
                                                    "MIIBIjANBgkqhkiG9w0BAQEFAAOCAQ8AMIIBCgKCAQEAv88HOrKd/4VE5nixLLxy"
                                                    "Vwh7DMVcpOeuLpUOZUN2r6vbubzeiRbyQN1sidEn8TFfeDJ01ubERV+wpjhbIVs5"
                                                    "LE6f/nROhFAdSl7JKcaZFYnI4GxWSkO8zG9bvfCAKMFQBWpjAhttZIT3TMx/o77d"
                                                    "I+TAhf+jwPPG+Bwtptg/LHMDvd5LC8DxMmRDPCYw2QKQSLlEnYewFmW51bBAM1HB"
                                                    "68B5PTgNMZ/PfwK3mKqAezLkTm4gyYXUrmlyNHKIjCz9kD1OCafPBcSKguqFIWzn"
                                                    "LrsTsY/0SQ/0voxUC9NLN7TutekJoFpByY9nJ0JPgigXSbP2z8GeLRATj2sfGdQ9"
                                                    "KQIDAQAB+plas"
                                                    "-----END PUBLIC KEY-----"))

    def test_get_rsa_public_key(self):
        self.assertEqual(base64.b64encode(hashlib.sha256(main.get_rsa_public_key().exportKey()).digest()),
                         "WVKwnQQgQT/JhtR4vyjUgfbkVKhAV9BpxezDT7wMyRg=")

    def test_get_rsa_private_ket(self):
        self.assertEqual(base64.b64encode(hashlib.sha256(main.get_rsa_private_ket().exportKey()).digest()),
                         "HHf3BBEWLOU7hMOVaPg2f3Wk0J+SWDMzM3y/1gtnTKs=")

    def test_get_aes_encrypt(self):
        self.assertEqual(main.get_aes_encrypt("test_message", "test_password", "test_iv"), "wBCsz/YaEIoMJgMWC4dbfQ==")

    def test_get_aes_decrypt(self):
        self.assertEqual(main.get_aes_decrypt("wBCsz/YaEIoMJgMWC4dbfQ==", "test_password", "test_iv"), "test_message")

    def test_get_rsa_encrypt(self):
        self.assertEqual(main.get_rsa_encrypt("test_message"), "l2coZCOhoYkPiWFu7lIMj+p/DZoBnk1tpS76ebEUPC++2XpL4kPYBO"
                                                               "zrmK8NmSZOLfJ78Hcc2CLGJ2WALyLgGK+ETremZp3ZZmezNyY9TH/g"
                                                               "wHh60sASbOYYINJstny9ur5fRh2z9jWAJXqakwmer8LOdpu9EyKGZz"
                                                               "JKj7oJlyJnOtfk+q+lFtImAoePTpoYNh5i5PsXhRWm7nc+SxuQwmtH"
                                                               "upwMS79Ix/rTEfxZ2WxbEZ/1b20juec3On11V7Hj9t3HeX8tErT9zT"
                                                               "8yOpzjEFWNvcdS7GnybsBw+JoRbRUZY6aOt9sejhEjfa/1uiVUlsUH"
                                                               "I2eZcivIYsqO69UEeg==")

    def test_get_rsa_decrypt(self):
        self.assertEqual(main.get_rsa_encrypt("l2coZCOhoYkPiWFu7lIMj+p/DZoBnk1tpS76ebEUPC++2XpL4kPYBO"
                                                "zrmK8NmSZOLfJ78Hcc2CLGJ2WALyLgGK+ETremZp3ZZmezNyY9TH/g"
                                                "wHh60sASbOYYINJstny9ur5fRh2z9jWAJXqakwmer8LOdpu9EyKGZz"
                                                "JKj7oJlyJnOtfk+q+lFtImAoePTpoYNh5i5PsXhRWm7nc+SxuQwmtH"
                                                "upwMS79Ix/rTEfxZ2WxbEZ/1b20juec3On11V7Hj9t3HeX8tErT9zT"
                                                "8yOpzjEFWNvcdS7GnybsBw+JoRbRUZY6aOt9sejhEjfa/1uiVUlsUH"
                                                "I2eZcivIYsqO69UEeg=="), "test_message")


if __name__ == "__main__":
    suite = unittest.TestLoader().loadTestsFromTestCase(TestStringMethods)
    unittest.TextTestRunner(verbosity=2).run(suite)
