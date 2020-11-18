from flask import Flask, request, render_template
from Crypto.Cipher import AES
from Crypto.Util import Counter
import os

FLAG = os.environ.get("FLAG") or "PLEASE_SET_A_FLAG"
KEY = os.environ.get("KEY") or os.urandom(32)

app = Flask(__name__)

class Encryptor(object):
    def __init__(self, key, nonce):
        self.nonce = nonce[:15]
        self.key = key
    
    def encrypt(self, plaintext):
        self._reset()
        key = AES.new(self.key, AES.MODE_CTR, counter=self.counter)
        return self.nonce.hex() + key.encrypt(plaintext.encode()).hex()
    
    def decrypt(self, ciphertext):
        self._reset()
        key = AES.new(self.key, AES.MODE_CTR, counter=self.counter)
        return key.decrypt(bytes.fromhex(ciphertext)).decode()
    
    def _reset(self):
        self.counter = Counter.new(nbits=8, prefix=self.nonce, initial_value=0, little_endian=False, allow_wraparound=True)



@app.route('/encrypt')
def encrypt():
    plaintext = request.args.get("plaintext")
    
    if not plaintext or len(plaintext) == 0:
        return "Something wents wrong"
    
    nonce = os.urandom(15)
    encryptor = Encryptor(KEY, nonce)
    return encryptor.encrypt(plaintext + FLAG)

@app.route('/decrypt')
def decrypt():
    ciphertext = request.args.get("ciphertext")
    nonce = bytes.fromhex(ciphertext[:30])
    ciphertext = ciphertext[30:]
    encryptor = Encryptor(KEY, nonce)
    plaintext = encryptor.decrypt(ciphertext) 
    if not plaintext.endswith(FLAG):
        return "Something wents wrong"
    else:
        return plaintext[:-len(FLAG)]

@app.route('/')
def index():
    return render_template('index.html')

if __name__ == '__main__':
    app.run(debug=True, port=5000)