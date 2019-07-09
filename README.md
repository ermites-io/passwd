[![Documentation](https://godoc.org/git.sr.ht/~eau/passwd?status.svg)](http://godoc.org/git.sr.ht/~eau/passwd)
[![License](https://img.shields.io/badge/License-BSD%203--Clause-blue.svg)](https://opensource.org/licenses/BSD-3-Clause)
[![builds.sr.ht status](https://builds.sr.ht/~eau/passwd.svg)](https://builds.sr.ht/~eau/passwd?)

# passwd
A simple golang password hashing package

# Description

New "password hashing" algorithms (PHC) have emerged in order to counter the increase in hardware assets
available to crack passwords easily when they are stolen.

Those new algorithms increase the cost of an attack and slow down the discovery of the original password.
Unfortunately they requires various non-trivial parameters to be used properly.

This package attempts to provide a safe and easy interface to produce/verify a hashed password,
while giving the ability to tune for specific/custom needs if necessary.

3 algorithms are used:

- bcrypt (using `x/crypto/bcrypt`, FOR LEGACY reasons)
- scrypt (using `x/crypto/scrypt`)
- argon2id (using `x/crypto/argon2`)

To keep things simple and to avoid a user to shoot himself in the foot, parameters choices are (for now) limited/translated into 2 static "profiles" for each algorithms:

- Default
- Paranoid

You can also decide to use your own *Argon2* or *Scrypt* custom parameters with this package.

# How to Use the package

## About Hashing Profiles
It is an attempt to dimension crypto parameters to common use cases (interactive/web auth/blabla) vs file storage

- Default  : ~interactive.
- Paranoid : file storage.

Custom profiles allow a user to define its own hashing parameters if those default don't fit.

## Public vs Masked parameters

Commonly password hashing includes hashing parameters in order to provide interoperability.

if no interoperability is needed (outside your authentication needs) and to make things slightly more annoying for a regular 
attacker, you might "mask" your parameters (instead of embedding them in the resulting hash).

### Public parameters (common practice)

Public parameters will embbed the derivation parameters in the resulting hash.
This allows you to simply use the **`passwd.Compare()`** function against a hash without
the need of a profile object.

### Masked parameters

Masked parameters will remove the derivation parameters from the resulting hash.
This requires you to **`passwd.NewMasked()`** before calling the profile **`Compare()`**
method.

An attacker would have to not only grab the stored password, but also to guess the parameters you use
with your key derivation in order to attack it offline.

**!!! IMPORTANT !!! This is NOT what makes your hash safe, it just makes it slightly harder to attack offline.**


## Examples 

### Password Hashing (public parameters):

create a password hashing object with *Argon2* default profile:   

**`p, err := passwd.New(passwd.Argon2idDefault)`**


Hash your password:   

**`hashed, err := p.Hash( []byte("my1337p4ssw0rd!") )`**


done, that's it, now **`hashed`** contain the hashed password:   

**`$2id$GlQX3F.KSYw1JLVv.LKDT.$1$65536$8$32$97DO7W9m/I8CTEQFKDa.VvEBTX1WepVv4qaWlt0OqH6`**


### Password Compare :

check a hash against a password:   

**`err := passwd.Compare(hashed, []byte("password"))`**  

done, `err` will be nil if the password matches the hash.


### Password Hashing (**masked parameters**):

create a password hashing profile:   

**`p, err := passwd.NewMasked(passwd.Argon2idDefault)`**


Hash your password:   

**`hashed, err := p.Hash( []byte("mypassword") )`**  

done, that's it, now you store `hashed`

**`$2id$ihFFCGUfBHTqUfvUIos6X.$AmClxc.3uj6LsxjVGqpOZggyqIL.wQJ9zjY23ztsETK`**



## Password Compare (**masked parameters**) :

check a hash against a password:

	p, err := passwd.NewMasked(passwd.Argon2idDefault)
	
	if err != nil {
		panic(err)
	}
	
	err := p.Compare(hashedpassword, []byte("password"))
	
	if err != nil {
		panic(err)
	}
	

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


# Resources

[Send patches](https://git-send-email.io) and questions to
[~eau/passwd@lists.sr.ht](https://lists.sr.ht/~eau/passwd).

Subscribe to release announcements on
[~eau/passwd-announce](https://lists.sr.ht/~eau/passwd-announce)

Bugs & todo here: [~eau/passwd](https://todo.sr.ht/~eau/passwd)
