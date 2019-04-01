# passwd
A simple golang password hashing package

# Description

A common problem to solve is storing passwords at rest, mainly for authentication and similar use cases.
A common response is to encrypt the password using a key derivation algorithm in order to resist offline attacks 
on the hashed password, such as: 
- exhaustive search
- dictionnary attacks
- rainbow tables
- etc..

New "password hashing" algorithms (PHC) have emerged in order to counter the increase in hardware assets
available to crack those passwords easily when they are stolen.

Those new algorithms increase the cost of an attack and slow down the discovery of the original password.
Unfortunately they requires various complex parameters to be used properly.

This package attempts to provide a safe and easy interface to produce/verify a hashed password,
while giving the ability to tune for specific/custom needs if necessary.

Choices are limited on purpose, to keep things simple and to avoid a user to shoot himself in the foot.
3 algorithms are implemented:

- bcrypt (using x/crypto/bcrypt)
- scrypt (using x/crypto/scrypt)
- argon2id (using x/crypto/argon2)

A default and a paranoid profile are available for each.

# How to Use the package

example basic usage:

1. Instanciate a password hashing profile:
    p := passwd.New(passwd.Argon2idCommon)

2. Hash your password
    hashed, err := p.Hash( []byte("mypassword") )

3. done.


example password check/comparison :

1. err := passwd.Compare(hashedpassword, []byte("password"))

2. done.

# Status

This is work in progress and the default are still being worked out tuned.
Work In Progress / Readme, Documentation & Examples coming..
