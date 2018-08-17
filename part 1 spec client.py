"""Secure client implementation

This is a skeleton file for you to build your secure file store client.

Fill in the methods for the class Client per the project specification.

You may add additional functions and classes as desired, as long as your
Client class conforms to the specification. Be sure to test against the
included functionality tests.
"""
from ast import literal_eval
from base_client import BaseClient, IntegrityError
from Crypto.Random.random import randint
from crypto import CryptoError

SHA_STRING = 'SHA256'
KEY_LENGTH = 16

def path_join(*strings):
    """Joins a list of strings putting a "/" between each.

    :param strings: a list of strings to join
    :returns: a string
    """
    return '/'.join(strings)

class Client(BaseClient):
    def __init__(self, storage_server, public_key_server, crypto_object,
                 username):
        super().__init__(storage_server, public_key_server, crypto_object,
                         username)
        key_dir = path_join(self.username, 'key_dir')
        if not self.storage_server.get(key_dir):
            k_e = self.crypto.get_random_bytes(KEY_LENGTH) #symmetric encryption key
            k_m = self.crypto.get_random_bytes(KEY_LENGTH) #symmetric MAC key
            k_n = self.crypto.get_random_bytes(KEY_LENGTH) #symmetric key for filename
            c = self.crypto.asymmetric_encrypt(k_e+k_m+k_n, self.elg_priv_key)
            sig = self.crypto.asymmetric_sign(c, self.rsa_priv_key)
            d = sig+c
            key_dir = path_join(self.username, 'key_dir')
            self.storage_server.put(key_dir, d)

    def upload(self, name, value):
        k_e, k_m, k_n = self.get_keys()
        ciphertext = self.crypto.symmetric_encrypt(value, k_e, \
                                            cipher_name='AES', \
                                            mode_name= 'CTR', \
                                            counter = self.crypto.new_counter(8*KEY_LENGTH))
        mac = self.crypto.message_authentication_code(str((ciphertext, name)), k_m, SHA_STRING)
        h_name = self.crypto.message_authentication_code(name, k_n, SHA_STRING)
        uid = self.resolve(path_join(self.username, h_name))
        upload_value = str((ciphertext, mac)) + "[DATA]"
        self.storage_server.put(uid, upload_value)
        return True

    def download(self, name):
        k_e, k_m, k_n = self.get_keys()
        h_name = self.crypto.message_authentication_code(name, k_n, SHA_STRING)
        uid = self.resolve(path_join(self.username, h_name))
        data = self.storage_server.get(uid)
        #Return None if no data stored at name
        if data == None:
            return data
        try:
            # Check to see if the file has been tampered with
            (ciphertext, mac) = literal_eval(data[:-6])
            if mac != self.crypto.message_authentication_code(str((ciphertext, name)), k_m, SHA_STRING):
                raise IntegrityError
            value = self.crypto.symmetric_decrypt(ciphertext, k_e, \
                                                cipher_name='AES', \
                                                mode_name= 'CTR', \
                                                counter = self.crypto.new_counter(8*KEY_LENGTH) )
            return value
        except:
            raise IntegrityError

    def resolve(self, uid):
        while True:
            res = self.storage_server.get(uid)
            if res is None or res.endswith("[DATA]"):
                return uid
            elif res.endswith("[POINTER]"):
                uid = res[:-9]
            else:
                raise IntegrityError()

    def share(self, user, name):
        k_e, k_m, k_n = self.get_keys()
        h_name = self.crypto.message_authentication_code(name, k_n, SHA_STRING)
        uid = self.resolve(path_join(self.username, h_name))
        data = self.storage_server.get(uid)

        h_name = self.crypto.cryptographic_hash(self.username + name, SHA_STRING)
        m = path_join(self.username, "sharewith", user, h_name)
        self.storage_server.put(m, path_join(self.username, h_name) + "[POINTER]")
        return m

    def receive_share(self, from_username, newname, message):
        h_new_name = self.crypto.cryptographic_hash(self.username + newname, SHA_STRING)
        my_id = path_join(self.username, h_new_name)
        self.storage_server.put(my_id, message + "[POINTER]")

    def revoke(self, user, name):
        sharename = path_join(self.username, "sharewith", user, name)
        self.storage_server.delete(sharename)

    def get_keys(self):
        key_dir = path_join(self.username, 'key_dir')
        d = self.storage_server.get(key_dir)
        if d == None:
            raise IntegrityError
        else:
            sig, c = d[:512], d[512:]
        if not self.crypto.asymmetric_verify(c, sig, self.rsa_priv_key):
            raise IntegrityError
        keys = self.crypto.asymmetric_decrypt(c, self.elg_priv_key)
        return keys[:32], keys[32:64], keys[64:96]

