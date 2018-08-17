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


class Client(BaseClient):
    def __init__(self, storage_server, public_key_server, crypto_object,
                 username):
        super().__init__(storage_server, public_key_server, crypto_object,
                         username)

    def upload(self, name, value):
        pk = self.pks.get_encryption_key(self.username)
        k = self.crypto.get_random_bytes(KEY_LENGTH)
        c = self.crypto.symmetric_encrypt(value, k, \
                                            cipher_name='AES', \
                                            mode_name= 'CTR', \
                                            counter = self.crypto.new_counter(8*KEY_LENGTH) )
        mac_k = self.crypto.get_random_bytes(KEY_LENGTH)
        mac = self.crypto.message_authentication_code(c, mac_k, SHA_STRING)

        h_name = self.crypto.cryptographic_hash(self.username + name, SHA_STRING)
        enc_k = self.crypto.asymmetric_encrypt(k, pk)
        enc_mac_k = self.crypto.asymmetric_encrypt(mac_k, pk)
        self.storage_server.put(h_name, str((enc_k, c, mac, enc_mac_k)))
        return True

    def download(self, name):
        h_name = self.crypto.cryptographic_hash(self.username + name, SHA_STRING)
        data = self.storage_server.get(h_name)

        #Return None if no data stored at name
        if data == None:
            return data

        (enc_k, c, mac, enc_mac_k) = literal_eval(data)

        # Check to see if the file has been tampered with
        pk = self.pks.get_encryption_key(self.username)
        try:
            mac_k = self.crypto.asymmetric_decrypt(enc_mac_k, self.elg_priv_key)
            if mac != self.crypto.message_authentication_code(c, mac_k, SHA_STRING):
                raise IntegrityError

            k = self.crypto.asymmetric_decrypt(enc_k, self.elg_priv_key)
            m = self.crypto.symmetric_decrypt(c, k, \
                                                cipher_name='AES', \
                                                mode_name= 'CTR', \
                                                counter = self.crypto.new_counter(8*KEY_LENGTH) )
            return m
        except:
            raise IntegrityError



    def share(self, user, name):
        # Replace with your implementation (not needed for Part 1)
        raise NotImplementedError

    def receive_share(self, from_username, newname, message):
        # Replace with your implementation (not needed for Part 1)
        raise NotImplementedError

    def revoke(self, user, name):
        # Replace with your implementation (not needed for Part 1)
        raise NotImplementedError
