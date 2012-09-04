There are a number of password generators such as SuperGenPass,
PwdHash, etc. that generate a site-specific password from a master
password and the site's URL. An attacker who obtains your site-specific  
password and the site's URL could attempt to determine your
master password by brute-force. Typically, these password generators
work by combining your master password with the site's URL and
computing a cryptographic (SHA1 or MD5) hash (perhaps using HMAC).
These hashes were designed such that they could be calculated very
quickly, which the opposite of what we want. A more secure method
would be to use PBKDF2 or bcrypt or Colin Percival's new scrypt
algorithm, which would make a brute-force  attack many orders of
magnitude more difficult.

This project uses Colin Percival's scrypt as a password generator.

For documentation on how to use it, see

  https://github.com/chrisoei/scrypt-genpass/wiki

For more details of how scrypt works, see

  http://www.tarsnap.com/scrypt.html
