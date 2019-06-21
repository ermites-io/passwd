[![Documentation](https://godoc.org/github.com/unix4fun/passwd?status.svg)](http://godoc.org/github.com/unix4fun/passwd)
[![Go Report Card](https://goreportcard.com/badge/github.com/unix4fun/passwd)](https://goreportcard.com/report/github.com/unix4fun/passwd)
[![License](https://img.shields.io/badge/License-BSD%203--Clause-blue.svg)](https://opensource.org/licenses/BSD-3-Clause)

# passwd
A simple golang password hashing package

# Description

New "password hashing" algorithms (PHC) have emerged in order to counter the increase in hardware assets
available to crack passwords easily when they are stolen.

Those new algorithms increase the cost of an attack and slow down the discovery of the original password.
Unfortunately they requires various non-trivial parameters to be used properly.

This package attempts to provide a safe and easy interface to produce/verify a hashed password,
while giving the ability to tune for specific/custom needs if necessary.

3 algorithms are implemented:

- bcrypt (using x/crypto/bcrypt, FOR LEGACY reasons)
- scrypt (using x/crypto/scrypt)
- argon2id (using x/crypto/argon2)

(to keep things simple and to avoid a user to shoot himself in the foot)
Parameters choices are limited and translated into static "profiles":
- Default
- Paranoid
(as it is WIP, it might switch to 3 profiles based on usage needs like : interactive, default, paranoid)

# How to Use the package

## Public vs Masked parameters

Commonly password hashing includes hashing parameters in order to make it easy for interoperability.

But you might decide you don't interoperate with other systems and you control your authentication mechanism,
as such you might be willing to make things slightly more annoying for an attacker reaching your stored password 
by "masking" your parameters (instead of embedding them in the resulting hash)

Public parameters allows you to use the hashed password to directly provide a simple ```passwd.Compare()``` function.
Masked parameters requires you to say what parameters you use AND to call the ```(p *Profile).Compare()``` method 
of the profile.

Attacker would have to not only grab the stored password, but also to guess the parameters you use
with your key derivation in order to attack it offline.

## example basic usage with public parameters:

Instanciate a password hashing profile:
```
   p := passwd.New(passwd.Argon2idDefault)
````

Hash your password:
```
   hashed, err := p.Hash( []byte("mypassword") )
```

done, that's it, now you store `hashed`
```
   hashed: '$2id$GlQX3F.KSYw1JLVv.LKDT.$1$65536$8$32$97DO7W9m/I8CTEQFKDa.VvEBTX1WepVv4qaWlt0OqH6'
```


## example password check/comparison :

check a hash against a password:
```
   err := passwd.Compare(hashedpassword, []byte("password"))
```

done.


## example basic usage with masked parameters:

Instanciate a password hashing profile:
```
   p := passwd.NewMasked(passwd.Argon2idDefault)
````

Hash your password:
```
   hashed, err := p.Hash( []byte("mypassword") )
```

done, that's it, now you store `hashed`
```
   hashed: $2id$ihFFCGUfBHTqUfvUIos6X.$AmClxc.3uj6LsxjVGqpOZggyqIL.wQJ9zjY23ztsETK
```


## example masked parameters password check/comparison :

check a hash against a password:
```
   p := passwd.NewMasked(passwd.Argon2idDefault)
   err := p.Compare(hashedpassword, []byte("password"))
```

done.

# Important Notes

bcrypt() is just a wrapper to x/crypto/bcrypt, only scrypt and argon support MaskedParameters.
bcrypt() is implemented for migration ease purposes, Compare will works perfectly with bcrypt 
while encrypting new password and changing old ones can use the new "profile".

# Changelog

* v0.1.2: fix hash parsing.
* v0.1.1: fix /issues/1
* v0.1.0: initial release

# Status

This package exclusively uses crypto algorithm implementations shipped in go extended crypto packages (located in ```x/crypto/```)

This is work in progress and the default are still being worked out.
Feedback is welcome.

An example tool/usage lies in ```cmd/pcrypt``` in this repository, hopefully it helps understanding how to use this package.

## Featuring (because there is always a star in your production..)

* [Argon2](https://en.wikipedia.org/wiki/Argon2) for today key stretching.
* [Scrypt](http://en.wikipedia.org/wiki/Scrypt) for key stretching.
* [Go](http://golang.org) because it works.
