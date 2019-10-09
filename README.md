[![Documentation](https://godoc.org/git.sr.ht/~eau/passwd?status.svg)](http://godoc.org/git.sr.ht/~eau/passwd)
[![License](https://img.shields.io/badge/License-BSD%203--Clause-blue.svg)](https://opensource.org/licenses/BSD-3-Clause)
[![builds.sr.ht status](https://builds.sr.ht/~eau/passwd.svg)](https://builds.sr.ht/~eau/passwd?)

passwd
======

A simple golang password hashing package.

Description
===========

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
    



How to Use the package
======================

### **About Hashing Profiles**
It is an attempt to dimension crypto parameters to common use cases (interactive/web auth/blabla) vs file storage

- Default  : ~interactive.
- Paranoid : file storage.

Custom profiles allow a user to define its own hashing parameters if those default don't fit. 
      


### **Public vs Masked parameters**

Commonly password hashing includes hashing parameters in order to provide interoperability.

if no interoperability is needed (outside your authentication needs) and to make things slightly more annoying for a regular 
attacker, you might "mask" your parameters (instead of embedding them in the resulting hash).
      

### **Public parameters (common practice)**

Public parameters will embbed the derivation parameters in the resulting hash.
This allows you to simply use the **`passwd.Compare()`** function against a hash without
the need of a profile object.      



### **Masked parameters**

Masked parameters will remove the derivation parameters from the resulting hash.
This requires you to **`passwd.NewMasked()`** before calling the profile **`Compare()`**
method.

An attacker would have to not only grab the stored password, but also to guess the parameters you use
with your key derivation in order to attack it offline.

**!!! IMPORTANT !!! This is NOT what makes your hash safe, it just makes it slightly harder to attack offline.**     


### **Key'ed Hash**


Key'd hashes makes it impossible to bruteforce (unless collision in hashes of course or the secret leaks), 
key'd hashes try to guarantee that leaked password cannot be attacked offline.

We used the method described [here](https://bristolcrypto.blogspot.com/2015/01/password-hashing-according-to-facebook.html).

This requires you to **`<profile>.SetKey()`** before call the **`Hash()`** or **`Compare()`** function.     



# Examples 
## Password Hashing (public parameters):

create a password hashing object with *Argon2* default profile:   

	p, err := passwd.New(passwd.Argon2idDefault)
	if err != nil {
		// handle error
	}
	hashed, err := p.Hash( []byte("my1337p4ssw0rd!") )
	if err != nil {
		// handle error
	}
	// hashed value: $2id$GlQX3F.KSYw1JLVv.LKDT.$1$65536$8$32$97DO7W9m/I8CTEQFKDa.VvEBTX1WepVv4qaWlt0OqH6


## Password Compare (non-masked parameters / non-key'ed / bcrypt) :

check a hash against a password:   

	err := passwd.Compare(hashed, []byte("password"))
	if err != nil {
		// handle error
	}


## Password Hashing (**masked parameters**):

	p, err := passwd.NewMasked(passwd.Argon2idDefault)
	if err != nil {
		// handle error
	}
	
	hashed, err := p.Hash( []byte("my1337p4ssw0rd!") )
	if err != nil {
		// handle error
	}
	// hashed value: $2id$ihFFCGUfBHTqUfvUIos6X.$AmClxc.3uj6LsxjVGqpOZggyqIL.wQJ9zjY23ztsETK

## Password Hashing (**key'ed hashing** + **masked parameters**)
	p, err := passwd.NewMasked(passwd.Argon2idDefault)
	if err != nil {
		// handle error
	}
	
	// set the hashing key.
	err = p.SetKey([]byte("myhashingsecret")
	if err != nil {
		// handle error
	}
	
	hashed, err := p.Hash( []byte("my1337p4ssw0rd!") )
	if err != nil {
		// handle error
	}
	// hashed value: $2id$ihFFCGUfBHTqUfvUIos6X.$AmClxc.3uj6LsxjVGqpOZggyqIL.wQJ9zjY23ztsETK

## Password Compare :

check a hash against a password, use the profile you defined to compare:  

	err := p.Compare(hashed, []byte("password"))
	if err != nil {
		// handle error
	}




Status
======

This package exclusively uses crypto algorithm implementations shipped in go extended crypto packages (located in `x/crypto/`)

This is a work in progress and the default are still being worked out/verified (feedback is welcome).

An example tool is provided in this repository:  

<strike>**`go get -u git.sr.ht/~eau/passwd/cmd/pcrypt`**</strike>

Note: small issue with git.sr.ht that prevents for now to go get subpackages inside a module, i'm trying untangle the cause and provide a patch..

hopefully this helps understanding how to use this package.      


Changelog
=========

* v0.2.0: (MASTER BRANCH / NOT RELEASED/TAGGED THIS IS JUST MASTER).
	* added key'd hash ability (using sha3-256/384 instead sha1/sha256) based on facebook key'd hmac salt/hash using 
	  SetKey() on the profile before any operation.
	  more [understanding](https://bristolcrypto.blogspot.com/2015/01/password-hashing-according-to-facebook.html)
	* fixed the build.
	* added some tests for key'd hashes.
	* minor code rearrangement.
	* can be used concurrently lock-free.
	* bugfixes and code cleaning.
	* write key'd hash tests & concurrency tests. (ON GOING)

* v0.1.3: 
	* fix a salted+masked+custom profile comparison issue.
	* NewCustom example+tests (issue #3)
	* NewMasked tests (issue #1)
	* bcrypt is NOT supported in masked params mode.
	* minor cleanups.
* v0.1.2: fix hash parsing.
* v0.1.1: fix /issues/1
* v0.1.0: initial release


Important Notes
===============

bcrypt is just a wrapper to `x/crypto/bcrypt`, only scrypt and argon support masked parameters.

bcrypt is implemented for migration purposes, **`passwd.Compare()`** will works perfectly with `x/crypto/bcrypt` hashed passwords while 
using a modern profile to store new passwords.      



Featuring (because there is always a star in your production..)
===============================================================

* [Argon2](https://en.wikipedia.org/wiki/Argon2) for today key stretching.
* [Scrypt](http://en.wikipedia.org/wiki/Scrypt) for key stretching.
* [Go](http://golang.org) because it works.


Resources
---------

* [password hashing intro](https://www.win.tue.nl/applied_crypto/2016/20161215_pwd.pdf)
* [key'd hashes](https://bristolcrypto.blogspot.com/2015/01/password-hashing-according-to-facebook.html)

Project resources
-----------------

[Send patches](https://git-send-email.io) and questions to
[~eau/passwd@lists.sr.ht](https://lists.sr.ht/~eau/passwd).

Subscribe to release announcements on
[~eau/passwd-announce](https://lists.sr.ht/~eau/passwd-announce)

Bugs & todo here: [~eau/passwd](https://todo.sr.ht/~eau/passwd)
