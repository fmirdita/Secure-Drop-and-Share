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
import json

SHA_STRING = 'SHA256'
KEY_LENGTH = 16
SIG_LENGTH = 512
DATA_POINTER_LENGTH = 6
POINTER_LENGTH = 9

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
            k_n = self.crypto.get_random_bytes(KEY_LENGTH) #symmetric key for filename
            c = self.crypto.asymmetric_encrypt(k_n, self.elg_priv_key)
            sig = self.crypto.asymmetric_sign(c, self.rsa_priv_key)
            d = sig+c
            self.storage_server.put(key_dir, d)

    def upload(self, name, value):
        k_n = self.get_name_key()
        h_name = self.crypto.message_authentication_code(name, k_n, SHA_STRING)
        uid = self.resolve(path_join(self.username, h_name))
        d_k, d_m = self.get_file_keys(uid)
        ciphertext = self.crypto.symmetric_encrypt(value, d_k, \
                                            cipher_name='AES', \
                                            mode_name= 'CTR', \
                                            counter = self.crypto.new_counter(8*KEY_LENGTH))
        mac = self.crypto.message_authentication_code(str((ciphertext, uid)), d_m, SHA_STRING)
        upload_value = str((ciphertext, mac)) + "[DATA]"
        self.storage_server.put(uid, upload_value)
        return True

    def download(self, name):
        k_n = self.get_name_key()
        h_name = self.crypto.message_authentication_code(name, k_n, SHA_STRING)
        p = path_join(self.username, h_name)
        uid = self.resolve(path_join(self.username, h_name))
        data = self.storage_server.get(uid)
        if data == None:
            return data
        try:
            d_k, d_m = self.get_file_keys(uid)
            (ciphertext, mac) = literal_eval(data[:-DATA_POINTER_LENGTH])
            if mac != self.crypto.message_authentication_code(str((ciphertext, uid)), d_m, SHA_STRING):
                raise IntegrityError
            value = self.crypto.symmetric_decrypt(ciphertext, d_k, \
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
        k_n = self.get_name_key()
        h_name = self.crypto.message_authentication_code(name, k_n, SHA_STRING)
        uid = self.resolve(path_join(self.username, h_name))
        d_k, d_m = self.get_file_keys(uid)

        new_user_pk = self.pks.get_encryption_key(user)
        new_keys = self.crypto.asymmetric_encrypt(d_k+d_m, new_user_pk)
        sig = self.crypto.asymmetric_sign(new_keys, self.rsa_priv_key)

        file_key_dir = path_join(uid, 'key_dir')
        d = json.loads(self.storage_server.get(file_key_dir))
        if user not in d:
            d[user] = [sig + new_keys, []]
            d[self.username][1].append(user)
        self.storage_server.put(file_key_dir, json.dumps(d))

        return uid

    def receive_share(self, from_username, newname, message):
        k_n = self.get_name_key()
        h_name = self.crypto.message_authentication_code(newname, k_n, SHA_STRING)
        uid = message

        file_key_dir = path_join(uid, 'key_dir')
        d = json.loads(self.storage_server.get(file_key_dir))
        sig_and_keys = d[self.username][0]
        sig, keys = sig_and_keys[:SIG_LENGTH], sig_and_keys[SIG_LENGTH:]

        shared_from_pk = self.pks.get_signature_key(from_username)
        if not self.crypto.asymmetric_verify(keys, sig, shared_from_pk):
            raise IntegrityError
        keys = self.crypto.asymmetric_decrypt(keys, self.elg_priv_key)
        keys = self.crypto.asymmetric_encrypt(keys, self.elg_priv_key)
        sig = self.crypto.asymmetric_sign(keys, self.rsa_priv_key)
        d[self.username][0] = sig+keys
        self.storage_server.put(file_key_dir, json.dumps(d))

        h_new_name = self.crypto.message_authentication_code(newname, k_n, SHA_STRING)
        my_id = path_join(self.username, h_new_name)
        self.storage_server.put(my_id, message + "[POINTER]")

    def revoke(self, user, name):
        k_n = self.get_name_key()
        h_name = self.crypto.message_authentication_code(name, k_n, SHA_STRING)
        uid = self.resolve(path_join(self.username, h_name))
        d_k, d_m = self.get_file_keys(uid)

        file_key_dir = path_join(uid, 'key_dir')
        key_dict = json.loads(self.storage_server.get(file_key_dir))
        shared_users = key_dict[self.username][1]
        #TODO: verify ORIGINAL OWNER
        if key_dict['ORIGINAL_OWNER'] == self.username:
            if user not in shared_users:
                return
            else:
                shared_users.remove(user)
                self.cascade_revoke(user, key_dict)
                #update file key 
                d_k = self.crypto.get_random_bytes(KEY_LENGTH) 
                d_m = self.crypto.get_random_bytes(KEY_LENGTH)
                file = self.download(name)
                for k, v in key_dict.items():
                    if k != 'ORIGINAL_OWNER':
                        user_pk = self.pks.get_encryption_key(k)
                        keys = self.crypto.asymmetric_encrypt(d_k+d_m, user_pk)
                        sig = self.crypto.asymmetric_sign(keys, self.rsa_priv_key)
                        shared_users = key_dict[k][1]
                        key_dict[k] = [sig+keys, shared_users]
                self.storage_server.put(file_key_dir, json.dumps(key_dict))
                self.upload(name, file)
        else:
            #no revoke access 
            raise IntegrityError

    def cascade_revoke(self, user, key_dict):
        """
        Go through all the users of the revoked user. Recursively revoke
        access to the file for those users.
        """
        if user in key_dict:
            revoked_shared_users = key_dict[user][1]
            key_dict.pop(user)
            for shared_user in revoked_shared_users:
                self.cascade_revoke(shared_user, key_dict)
        
    def get_name_key(self):
        key_dir = path_join(self.username, 'key_dir')
        d = self.storage_server.get(key_dir)
        if d == None:
            raise IntegrityError
        else:
            sig, c = d[:SIG_LENGTH], d[SIG_LENGTH:]
        if not self.crypto.asymmetric_verify(c, sig, self.rsa_priv_key):
            raise IntegrityError
        return self.crypto.asymmetric_decrypt(c, self.elg_priv_key)

    def get_file_keys(self, uid):
        """
        Returns D_K, D_M
        D_K: the key with which a certain document is encrypted
        D_M: the key used to MAC the encryption, uid of a file
        If these keys do not exist, this funciton generates them and stores 
        them in the file's key dictionary, which contains usernames as keys,
        and the keys encrypted with the user's public key as values
        """
        file_key_dir = path_join(uid, 'key_dir')
        d = self.storage_server.get(file_key_dir)
        if d == None:
            key_dir = path_join(uid, 'key_dir')
            d_k = self.crypto.get_random_bytes(KEY_LENGTH) 
            d_m = self.crypto.get_random_bytes(KEY_LENGTH)
            keys = self.crypto.asymmetric_encrypt(d_k+d_m, self.elg_priv_key)
            sig = self.crypto.asymmetric_sign(keys, self.rsa_priv_key)
            d = {   'ORIGINAL_OWNER' : self.username,
                    self.username : [sig + keys, []]}
            self.storage_server.put(key_dir, json.dumps(d))
        else:
            d = json.loads(d)
            sig_and_keys = d[self.username][0]
            sig, keys = sig_and_keys[:SIG_LENGTH], sig_and_keys[SIG_LENGTH:]
        if not self.crypto.asymmetric_verify(keys, sig, self.rsa_priv_key):
            # check to see if this matches the signature of the original owner 
            original_owner = d['ORIGINAL_OWNER']
            orig_own_pk = self.pks.get_signature_key(original_owner)
            if not self.crypto.asymmetric_verify(keys, sig, orig_own_pk):
                raise IntegrityError
            else:
                keys = self.crypto.asymmetric_decrypt(keys, self.elg_priv_key)
                keys = self.crypto.asymmetric_encrypt(keys, self.elg_priv_key)
                sig = self.crypto.asymmetric_sign(keys, self.rsa_priv_key)
                d[self.username][0] = sig+keys
                self.storage_server.put(file_key_dir, json.dumps(d))
        keys = self.crypto.asymmetric_decrypt(keys, self.elg_priv_key)
        return keys[:2*KEY_LENGTH], keys[2*KEY_LENGTH:4*KEY_LENGTH]


