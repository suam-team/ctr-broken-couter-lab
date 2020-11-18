from flask import Flask, request, render_template
from Crypto.Cipher import AES
from Crypto.Util import Counter
import os

FLAG = os.environ.get("FLAG") or "PLEASE_SET_A_FLAG"
KEY = os.environ.get("KEY") or os.urandom(32)
NONCE = os.environ.get("KEY") or os.urandom(15)

app = Flask(__name__)

class Encryptor(object):
    def __init__(self, key, nonce):
        self.nonce = nonce[:15]
        self.key = key
    
    def encrypt(self, plaintext):
        self._reset()
        key = AES.new(self.key, AES.MODE_CTR, counter=self.counter)
        return key.encrypt(plaintext.encode()).hex()
    
    def decrypt(self, ciphertext):
        self._reset()
        key = AES.new(self.key, AES.MODE_CTR, counter=self.counter)
        return key.decrypt(bytes.fromhex(ciphertext)).decode()
    
    def _reset(self):
        self.counter = Counter.new(nbits=8, prefix=self.nonce, initial_value=0, little_endian=False, allow_wraparound=True)

encryptor = Encryptor(KEY, NONCE)

@app.route('/encrypt')
def encrypt():
    plaintext = request.args.get("plaintext")
    return encryptor.encrypt(plaintext + FLAG)

@app.route('/decrypt')
def decrypt():
    ciphertext = request.args.get("ciphertext")
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