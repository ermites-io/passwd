[![Documentation](https://godoc.org/github.com/ermites-io/passwd?status.svg)](http://godoc.org/github.com/ermites-io/passwd)
[![License](https://img.shields.io/badge/License-BSD%203--Clause-blue.svg)](https://opensource.org/licenses/BSD-3-Clause)
[![Go Report Card](https://goreportcard.com/badge/github.com/ermites-io/passwd)](https://goreportcard.com/report/github.com/ermites-io/passwd)


passwd/reset
============

stateless password reset helpers function 

Description
===========

the passwd package is mainly about creating password to be stored offline.
subpackage passwd/reset allows coders to create a stateless password reset in their app.

the idea is simple, provide the following:
- generate a password reset codes
- the code expires after time.Duration
- the reset code should be used only ONCE after the password reset.


How to Use the package
======================
 
### **Prerequisite: 

You are already hashing / storing your password properly, with passwd package or another package.


### **Create Password Reset Code**

Commonly password hashing includes hashing parameters in order to provide interoperability.

if no interoperability is needed (outside your authentication needs) and to make things slightly more annoying for a regular 
attacker, you might "mask" your parameters (instead of embedding them in the resulting hash).
      

### **Validate the reset code**

Public parameters will embbed the derivation parameters in the resulting hash.
This allows you to simply use the **`passwd.Compare()`** function against a hash without
the need of a profile object.      



# Examples 

