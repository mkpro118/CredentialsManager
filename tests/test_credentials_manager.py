import os
import tempfile
import unittest

try:
    from credentials_manager import (CredentialsManager,
                                     CredentialsNotFoundError)
except ImportError:
    import pathlib
    import sys

    tests = pathlib.Path(__file__).resolve().parent
    src = tests.parent / 'src'
    sys.path.insert(0, str(src))

    from credentials_manager import (CredentialsManager,
                                     CredentialsNotFoundError)


class TestCredentialsManager(unittest.TestCase):
    def setUp(self):
        self.password = "test_password"
        self.cm = CredentialsManager(self.password)

    def test_store_and_get(self):
        name = "test_cred"
        data = "test_data"
        self.cm.store(name, data)
        retrieved_data = self.cm.get(name)
        self.assertEqual(data, retrieved_data)

    def test_overwrite_protection(self):
        name = "test_cred"
        data1 = "test_data1"
        data2 = "test_data2"
        self.cm.store(name, data1)
        with self.assertRaises(ValueError):
            self.cm.store(name, data2)
        self.cm.store(name, data2, overwrite=True)
        retrieved_data = self.cm.get(name)
        self.assertEqual(data2, retrieved_data)

    def test_get_nonexistent(self):
        with self.assertRaises(ValueError):
            self.cm.get("nonexistent_cred")

    def test_update_password(self):
        name = "test_cred"
        data = "test_data"
        self.cm.store(name, data)

        new_password = "new_test_password"
        self.cm.update_password(self.password, new_password)

        # Credential should still be accessible with new password
        retrieved_data = self.cm.get(name)
        self.assertEqual(data, retrieved_data)

        # Old password should no longer work
        with self.assertRaises(ValueError):
            self.cm.update_password(self.password, "another_password")

    def test_update_password_incorrect_old_password(self):
        with self.assertRaises(ValueError):
            self.cm.update_password("wrong_password", "new_password")

    def test_update_password_multiple_credentials(self):
        credentials = {"cred1": "data1", "cred2": "data2", "cred3": "data3"}
        for name, data in credentials.items():
            self.cm.store(name, data)

        new_password = "new_test_password"
        self.cm.update_password(self.password, new_password)

        for name, data in credentials.items():
            retrieved_data = self.cm.get(name)
            self.assertEqual(data, retrieved_data)

    def test_save_and_load(self):
        name = "test_cred"
        data = "test_data"
        self.cm.store(name, data)

        with tempfile.NamedTemporaryFile(delete=False) as tmp:
            filename = tmp.name
            self.cm.save(filename)

        loaded_cm = CredentialsManager.load(filename, self.password)
        retrieved_data = loaded_cm.get(name)
        self.assertEqual(data, retrieved_data)

        os.unlink(filename)

    def test_load_nonexistent_file(self):
        with self.assertRaises(CredentialsNotFoundError):
            CredentialsManager.load("nonexistent_file.json", self.password)

    def test_load_invalid_file(self):
        with tempfile.NamedTemporaryFile(mode='w', delete=False) as tmp:
            tmp.write("invalid json")
            filename = tmp.name

        with self.assertRaises(ValueError):
            CredentialsManager.load(filename, self.password)

        os.unlink(filename)

    def test_load_wrong_password(self):
        name = "test_cred"
        data = "test_data"
        self.cm.store(name, data)

        with tempfile.NamedTemporaryFile(delete=False) as tmp:
            filename = tmp.name
            self.cm.save(filename)

        with self.assertRaises(ValueError):
            CredentialsManager.load(filename, "wrong_password")

        os.unlink(filename)

    def test_different_system_info(self):
        # This test is to ensure that the same password on different
        # invocations produce different encryption keys
        cm1 = CredentialsManager(self.password)
        cm2 = CredentialsManager(self.password)

        # Store the same data in both managers
        name = "test_cred"
        data = "test_data"
        cm1.store(name, data)
        cm2.store(name, data)

        # The internal representations should be different
        # Cheating a little for testing
        self.assertNotEqual(
            cm1._CredentialsManager__mapping[name],
            cm2._CredentialsManager__mapping[name],
        )

        # But both should decrypt to the same data
        self.assertEqual(cm1.get(name), cm2.get(name))


if __name__ == '__main__':
    unittest.main()
