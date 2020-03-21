# pyAPDUFuzzer
A fuzzer for `APDU`-based smartcard interfaces
## Prerequisites
If you want to install `pyAPDUFuzzer`, you will need the following dependencies:
- GCC
- Python 3
- Python 3 devel
- pip3
- SWIG
- PCSC lite
- PCSC lite devel
- American fuzzy lop

You will also need a modified version of `python-afl`:
``` shell
pip3 install --user git+https://github.com/ph4r05/python-afl
```
### Installation script
If you are using `Fedora`, `Ubuntu`, `Arch Linux`, or `macOS`, you can use our script to
install all required dependencies. Just run following line in your terminal:
``` shell
curl -fsSL https://github.com/petrs/pyAPDUFuzzer/raw/master/install-dependencies.sh | sh
```
## Installation
You can install the latest version of `pyAPDUFuzzer` from GitHub (recommended):
``` shell
pip3 install --user git+https://github.com/petrs/pyAPDUFuzzer
```
Or use version from PyPI:
``` shell
pip3 install --user apdu-fuzzer
```
### Local development
For local development, clone this repository to your current working directory:
``` shell
git clone https://github.com/petrs/pyAPDUFuzzer.git
```
Then install `pyAPDUFuzzer` in **editable** mode:
``` shell
cd pyAPDUFuzzer && pip3 install --user -e . && cd ..
```
### PC/SC Smart Card Daemon
Before you can start using `pyAPDUFuzzer`, you need to start `pcscd`. If you are using `systemd`,
you can run the following command:
``` shell
systemctl start pcscd.service
```
## Usage
`pyAPDUFuzzer` is divided into three parts — prefix fuzzing, AFL fuzzing, and grammar synthesis.
### Prefix fuzzing
The main aim of prefix fuzzer is to discover available methods on the card and
supported lengths of valid payload. This method tries all
combinations of `APDU` headers using brute-force (also, some optimizations are used
to speed up the process).

You can run prefix fuzzer as follows:
``` shell
apdu-prefix-fuzz
```
You can also pass `--start_ins` and `--end_ins` parameters to specify which instructions
should be tested:
``` shell
# test instructions between 0x0a and 0x28
apdu-prefix-fuzz --start_ins 10 --end_ins 40
```
Prefix fuzzer often produces huge amounts of data; Therefore,
we provide a script that reduces the count of lines and makes
files more readable.
``` shell
cat results.json | apdu-prefix-reduce > reduced_results.json
```
### AFL fuzzing
AFL fuzzing is used to discover inputs that trigger new, interesting behavior.
AFL fuzzer is divided into two parts — client and server.
#### Server
In order to use AFL fuzzing, you must start a server:
``` shell
apdu-fuzz --server
```
If you have multiple card readers connected to your computer, you can specify which one
you want to use by passing `--card_reader ID` to the server. `ID` starts from zero.

If you want to run multiple instances of `pyAPDUFuzzer` simultaneously, you need
to specify a port for the server and its corresponding client by passing `--port PORT`
parameter to both of them.
#### Client
Before you can start fuzzing, you need to create a directory with seed input:
``` shell
mkdir inputs
echo -n '000000000000' > inputs/seed1
```
To start the AFL fuzzer, run the following command:
``` shell
PYTHON_AFL_PERSISTENT=1 py-afl-fuzz -m 500 -t 5000 -o result/ -i inputs/ -- \
    apdu-fuzz --afl --mask 00000000 --tpl 0be00100 --payload-len-b 12 --payload-len-s 31
```
- To make AFL work without additional configuration of your system,
  it may also be necessary to set these environment variables:
  `AFL_I_DONT_CARE_ABOUT_MISSING_CRASHES=1` and `AFL_SKIP_CPUFREQ=1`.
- The above command uses fixed APDU prefix `0be00100` as the mask is zero on those bytes.
- AFL generates a payload of lengths between `0x0c` and `0x1f`.
### Grammar synthesis using GLADE
GLADE is a tool that is able to synthesize input grammar of smartcard commands.
It only needs some seed inputs (examples of valid inputs).

In order to use GLADE, you will need to install it from here: https://github.com/kuhy/glade

Before you can start fuzzing, you need to start the server (`apdu-fuzz --server`).

Then create a directory with seed inputs:
``` shell
mkdir inputs
echo '0002380000007f33cbca3637' | xxd -r -p > inputs/seed1
```
Finally, start the GLADE:
``` shell
glade learn --alphabet BYTE --length 12-31 --input inputs \
    'apdu-afl-fuzz --glade --mask 00000000 --tpl 0be00100 --payload-len-b 12 --payload-len-s 31 --response_status 6982'
```
- Fixed APDU prefix `0be00100` is used as the mask is zero on those bytes.
- GLADE generates a payload of lengths between `0x0c` and `0x1f`.
- We are generating grammar of inputs which triggers `SECURITY_STATUS_NOT_SATISFIED` (`6982`).
- When seed input (`0002380000007f33cbca3637`) is sended to the card, it also returns `6982`.
## Architecture
```
AFL <-> Client <-> Server <-> Card

+----------------------------------+
|  AFL                             |
|  | |                             |                                   +-------------------+
|  | |          +----------------+ |         +------------------+      |                   |
|  | |   stdin  |                | |  socket |                  |      | +---+             |
|  | +----------|     Client     |------------      Server      -------- |-|-|    Card     |
|  |            |                | |         |                  |      | +---+             |
|  | +------+   +--------|-------+ |         +------------------+      |                   |
|  +-| SHM  |------------+         |                                   +-------------------+
|    +------+                      |
|                                  |
+----------------------------------+
```
(ascii by https://textik.com/)

Notes:

- Server is started first, connects to the card and listens on the socket for
  raw data to send to the card.  Does not process input data in any way.
- Server stores raw responses from the card to the data files.
- Server is able to reconnect to the card if something goes wrong.
- Client is started by AFL. AFL sends input data via STDIN, forking the client
  with each new fuzz input. PCSC does not like forking with AFL this
  server/client architecture was required.
- Client is forked by the AFL after python is initialized. Socket can be opened
  either before fork or after the fork.  After fork is safer as each fuzz input
  has a new connection but a bit slower. Opening socket before fork also works
  but special care needs to be done on broken pipe exception - reconnect logic
  is needed. This is not implemented now.
- Client post-processes input data generated by the AFL, e.g., generates length
  fields, can do TLV, etc.

Communication between server/client:
- Client sends `[0, buffer]`. Buffer is raw data structure to be sent to the
  card. `0` is the type / status
- Server responds with: `status 1B | SW1 1B | SW2 1B | timing 2B | data 0-NB`
```
+----+----+----+--------+------------------------+
|    |    |    |        |                        |
| 0  | SW | SW | timing |     response data      |
|    |  1 |  2 |        |                        |
+----+----+----+--------+------------------------+
```
Client then takes response from the socket, and uses modified [python-afl-ph4] to add trace to the shared memory segment
that is later analyzed by AFL to determine whether this fuzz input lead to different execution trace than the previous one.

Currently the trace bitmap is done in the following way:
``` python
afl.trace_offset(hashxx(bytes([sw1, sw2])))
afl.trace_offset(hashxx(timing))
afl.trace_offset(hashxx(bytes(data)))
```
Fowler-Noll-Vo (FNV) hash function used in `afl.trace_buff` is not very good with respect to the zero buffers. The timing
was usually not affecting the bitmap so we switched to very fast hash function `hashxx` for the offset computation.
### FNV collisions
FNV is inappropriate for this use case as it returns the same hash for all buffers of the following format:
`p | 0 | x` where `p` is a fixed prefix, `x` is random suffix.
``` python
afl.hash32(bytes([0,1]))
afl.hash32(bytes([0,2]))
afl.hash32(bytes([0,255]))
afl.hash32(bytes([0,255,255,255]))
# 2166136261
```
