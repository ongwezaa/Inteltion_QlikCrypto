from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes
import base64
import os

key = '!A%D*G-KaPdRgUkXp2s5v8y/B?E(H+Mb'.encode('utf-8')
iv = '0000000000000000'.encode('utf-8')

encryptedData = 'n29tomofeAcaEmp368DI9MdwGTnelUjRhaRaMGJztSmVW1gjWDeZI16WURbB8ONb'

ciphertext = base64.b64decode(encryptedData)

cipher = Cipher(algorithms.AES(key), modes.CBC(iv))

decryptor = cipher.decryptor()

decryptedText = decryptor.update(ciphertext) + decryptor.finalize()

print (decryptedText.decode('utf-8'))
