# APDU dictionaries

Collection of specified or used APDU commands, sorted by source.

## Sources
* ISO/IEC 7816-4 specification
* EMV specifications for payment systems (books 1 to 3)
* "APDU interpreter and vendor specific commands" from Springcard
* "Smart Cards: The Developer's Toolkit" by Timothy M. Jurgensen, Scott B. Guthery

## Format

Each line where the first non-space or non-tab character is a __#__ is a comment.

The collected APDU commands may be written:
* explicitly, as in *smc\_devkit.md*
* with regular expressions

If so, the used format has a lot in common with the POSIX one:
* __(__ and __)__ are delimiters to oser operators
* __|__ allows the choice between 2 or more options
* __?__ matches the preceding element zero or one time
* __{n}__ matches the preceding element exactly _n_ times

In addition, the characters __<__ and __>__ are also used as delimiters (like 
__(__ and __)__ characters) but they also define a temporary variable __L__.

For example, the regex:
```
<4>(a){L}
```
only matches _4aaaa_.

The regular expression:
```
<01-04>(a){L}
```
matches _01a_, _02aa_, _03aaa_ and _04aaaa_.

For now, the __<__ and __>__ delimiters are only used to define the length of the
APDU's data field conditionnally to the previous Lc field, as in the following 
regex representing the *Select* command from the ISO 7816-4 specification:

```
# Select
(00-1f|80-9f|40-7f|c0-ff)a4(00-04|08|09)(00-0f)(<01-ff>(00-ff){L})?(01-ff)?
```

This regex matches the APDU command: "c0 a4 08 00 04 11223344 23" (without spaces).