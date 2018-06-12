# Installation
## Installation on Debian based Linux
For the fuzzer to work we need https://github.com/mit-ll/LL-Smartcard and its dependencies:

```
git clone https://github.com/mit-ll/LL-Smartcard
cd LL-Smartcard
./install_dependencies.sh
python2 setup.py install
```

## Installation on MacOS

For the fuzzer to work we need https://github.com/mit-ll/LL-Smartcard and its dependencies:
```
brew install swig
pip2 install pyDES
pip2 install pyscard
brew install pcsc-lite

git clone https://github.com/mit-ll/LL-Smartcard
cd LL-Smartcard
python2 setup.py install
```
