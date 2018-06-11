# APDUFuzzer
A tool for configurable black-box fuzzing of application running on the smartcard and using APDU-based interfaces. APDU stands for Application Protocol Data Unit by ISO7816 standard and is simple packet structure with header (first 5 bytes) and optional custom data (up to 256 bytes). 

Usable for:
- Discovery of standard bugs (e.g., out-of-bounds array access)
- Reverse engineering of unknown interface 
- Verification of expected behavior against known template during an integration testing 


## Usage
See SimpleAPDU.java for example. Fuzzer takes a template APDU command (e.g., 00 a4 04 00 00) together with specification which bytes of template shall be modified and which not. The specified bytes are then modified, resulting APDU is sent to the smartcard and evaluated based on the return data and resulting error code. The results are processed for subsequent human inspection.

The output is of following types:
- Full execution trace will meta information printed on standard input
- JSON file with complete input/output results list 
- TXT file with complete input/output results list 
- TXT file with results in compact form (human readable)

Typical output of compat form:

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



