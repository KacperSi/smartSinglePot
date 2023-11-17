import secrets
import string

alphabet = string.digits
pwd_length = 6

# generate a password string
pwd = ''
for i in range(pwd_length):
  pwd += ''.join(secrets.choice(alphabet))

print(pwd)