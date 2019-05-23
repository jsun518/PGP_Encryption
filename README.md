# PGP_Encryption
# This program is used to generate encrypted key pairs and enable encryption/decryption for files based on PGP encryption algorithm.
Different parameters need to be passed in for different scenarios, below are the examples:
# command to generate key pair
java -DGEN_KEY_PAIR=1 -DENCRYPTION=0 -DDECRYPTION=0 -DID=<ID> -DPWD=<PASSWORD> -DGEN_PRIV_KEY=<directory>/<private key file name> -DGEN_PUB_KEY=<directory>/<public key file name> -jar <jar file name>
# command to encrypt file
java -DGEN_KEY_PAIR=0 -DENCRYPTION=1 -DDECRYPTION=0 -DEXISTPUBKEYFILE=<directory>/<public key file name> -DCIPHEREDFILEOUTPUT=<directory>/<ciphered file name> -DORIGINALFILEINPUT=<directory>/<file to be encrypted> -jar <jar file name>
# command to encrypt multiple files
java -DGEN_KEY_PAIR=0 -DENCRYPTION=1 -DDECRYPTION=0 -DEXISTPUBKEYFILE=<directory>/<public key file name>  -DORIGINALFILEINPUT=<directory>/<file1 to be encrypted>,<directory>/<file2 to be encrypted> -jar <jar file name>
# command to encrypt the whole folder
java -DGEN_KEY_PAIR=0 -DENCRYPTION=1 -DDECRYPTION=0 -DEXISTPUBKEYFILE=<directory>/<public key file name> -DCIPHERDIR=<encrypt directory> -DCIPHEROUTPUTDIR=<decrypt directory> -jar PGP_Encryption-1.0-SNAPSHOT-pkg.jar
# command to decrypt file
java -DGEN_KEY_PAIR=0 -DENCRYPTION=0 -DDECRYPTION=1 -DPWD=<private key password> -DCIPHEREDFILEINPUT=<directory>/<file name to be decrypted> -DDECRYPTEDFILEOUTPUT=<directory>/<file name that is decrypted> -DPRIVATEKEYFILE=<directory>/<private key file> -jar <jar file name>'

The jar file is located in /target/PGP_Encryption-1.0-SNAPSHOT-pkg.jar

As for summary, below are all the parameters used for the program
# GEN_KEY_PAIR
  - 0: skip generating key pairs
  - 1: generate key pairs
# ENCRYPTION
  - 0: skip encryption
  - 1: do encryption
# DECRYPTION
  - 0: skip decryption
  - 1: do decryption
# ID
  - ID used to generate a new public key
# PWD
  - Password to generate a new private key
  - Password to decrypt an existing private key
# GEN_PRIV_KEY
  - target directory and file name for the private key
# GEN_PUB_KEY
  - target directory and file name for the public key
# CIPHERDIR
  - source directory to be encrypted: all files in the directory will be encrypted, if no output directory is named, then will create encrypted file in the same location
# CIPHEROUTPUTDIR
  - output directory of the encryption when encrypting the whole directory
# EXISTPUBKEYFILE
  - existed public key file to be used for encryption
# CIPHEREDFILEOUTPUT
  - encrypted file as output
# ORIGINALFILEINPUT
  - original file to be encrypted
# CIPHEREDFILEINPUT
  - encrypted file to be deciphered
# PRIVATEKEYFILE
  - private key file used for decryption
# DECRYPTEDFILEOUTPUT
  - output file after decryption
