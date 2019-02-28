from Crypto.Cipher import AES
import getpass
import hashlib
import binascii
import sys
import os
import array


class Crypter():
    def __init__(self, full_filepath, pwd, ct_data, salt="3c0ea47b-32ec-495f-bb88-c41c4c10dd13ad2c338d-4746-4a97-843b-76f5b7b8fe9b1ece25e9-39b0-479e-84d0-f5e7945cf5ac"):
        self.full_filepath = full_filepath
        self.salt = salt.encode()
        self.ct_data = ct_data
        try:
            self.hpwd = self._gethash(pwd)
        except Exception as e:
            pwd = ""
            full_filepath = ""
            ct_data = ""
            salt = ""
            self.full_filepath = ""
            self.salt = ""
            self.ct_data = ""
            self.hpwd = ""
            raise Exception("Failed to hash.")
        del pwd

        

    def _gethash(self,pwd):
        bpwd = pwd.encode()
        hkey = hashlib.pbkdf2_hmac("sha256",bpwd,self.salt,100000,dklen=32)
        del bpwd
        del pwd
        return hkey

    def _enc(self):
        cipher = AES.new(self.hpwd,AES.MODE_EAX)
        ct_data = self.ct_data.encode()
        self.ct_data = None
        ctxt, tag = cipher.encrypt_and_digest(ct_data)
        del ct_data
        outf = open(self.full_filepath,"wb")
        [outf.write(x) for x in (cipher.nonce, tag, ctxt)]
        outf.close()

    def _dec(self):
        infile = open(self.full_filepath,"rb")
        nonce, tag, ctext = [infile.read(x) for x in (16,16,-1)]
        cipher = AES.new(self.hpwd,AES.MODE_EAX,nonce)
        ct_data = cipher.decrypt_and_verify(ctext, tag)
        ct_data = ct_data.decode()
        infile.close()
        return ct_data

    def enc(self):
        try:
            self._enc()
        except Exception as e:
            self.full_filepath = ""
            self.salt = ""
            self.ct_data = ""
            self.hpwd = ""
            raise Exception("Failed to encrypt")

    

    def dec(self):
        try:
            return self._dec()
        except Exception as e:
            self.full_filepath = ""
            self.salt = ""
            self.ct_data = ""
            self.hpwd = ""
            raise Exception("Failed to encrypt")

    def destroy_object(self):
        self.full_filepath = ""
        self.salt = ""
        self.ct_data = ""
        self.hpwd = ""


if __name__ == "__main__":
    pwd = getpass.getpass("pw:")
    fname = getpass.getpass("fname")
    data = raw_input("Data:")
    crypter_object = Crypter(full_filepath="./{}.enc".format(str(fname)), pwd=pwd, ct_data=data)
    del pwd
    if sys.argv[1] == "enc":
        crypter_object.enc()
        crypter_object.destroy_object()
    elif sys.argv[1] == "dec":
        r = crypter_object.dec()
        print(r)
        crypter_object.destroy_object()
    elif sys.argv[1] == "both":
        crypter_object.enc()
        r = crypter_object.dec()
        print(r)
        crypter_object.destroy_object()
    
        
        
