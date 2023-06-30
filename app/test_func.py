import base64
import os
import pyqrcode
import io
import png
otp_secret = base64.b32encode(os.urandom(10)).decode('utf-8')
print(otp_secret)


username = 'tuantd1@test.com'
# otp_secret = 'BXGDD3H2GLKABSX6'

# qrcode = 'otpauth://totp/2FA-S3:{0}?secret={1}&issuer=2FA-S3'.format(username, otp_secret)
qrcode = 'otpauth://totp/s3.fptvds.vn:{0}?secret={1}&issuer=s3.fptvds.vn'.format(username, otp_secret)
print(qrcode)
url = pyqrcode.create(qrcode)
file = io.BytesIO()
url.png(file, scale=6)
# Insert "encoded" into the database
encoded = base64.b64encode(file.getvalue()).decode("ascii")
print(encoded)
