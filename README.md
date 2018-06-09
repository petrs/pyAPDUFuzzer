# APDUFuzzer
A fuzzer for APDU-based smartcard interfaces

A tool for configurable black-box fuzzing of applications running on smartcard. 

Usable for:
- Discovery of standard bugs (e.g., out-of-bounds array access)
- Reverse engineering of unknown interface 

APDU stands for Application Protocol Data Unit by ISO7816 standard and is simple packet structure with header (first 5 bytes) and optional custom data (up to 256 bytes). 

## Usage
See SimpleAPDU.java for example. Fuzzer takes a template APDU command (e.g., 00 a4 04 00 00) together with specificaton which bytes of template shall be modified and which not. The specified bytes are then modified, resulting APDU is send to smartcard and evaluated based on the return data and resulting error code. The results are processed for subsequent human inspection.

Typical output:


```java
########################
CaseName = INS_TEST
TemplateValue = 0000000000

########################
########################

Offset = 0x00 (0)
  [00]		= ISOException 0x6d00 (SW_INS_NOT_SUPPORTED) @ORIGINAL VALUE
  [01]-[FF]	= ISOException 0x6d00 (SW_INS_NOT_SUPPORTED)

Offset = 0x01 (1)
  [00]		= ISOException 0x6d00 (SW_INS_NOT_SUPPORTED) @ORIGINAL VALUE
  [01]-[13]	= ISOException 0x6d00 (SW_INS_NOT_SUPPORTED)
  [14]		= ISOException 0x6b00 (SW_WRONG_P1P2)
  [15]		= ISOException 0x6d00 (SW_INS_NOT_SUPPORTED)
  [16]		= ISOException 0x6b00 (SW_WRONG_P1P2)
  [17]-[1F]	= ISOException 0x6d00 (SW_INS_NOT_SUPPORTED)
  [20]		= ISOException 0x6700 (SW_WRONG_LENGTH)
  [21]-[23]	= ISOException 0x6d00 (SW_INS_NOT_SUPPORTED)
  [24]		= ISOException 0x6700 (SW_WRONG_LENGTH)

...
```

## TODO, plans
- proper readme description
- specification for multibyte changes
- adaptive testing (not only exhaustive brute-force)



