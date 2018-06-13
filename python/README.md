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
brew install pcsc-lite
pip install llsmartcard-ph4
```

## Experimental installation with pip

```
# Create virtual environment
python -m venv --upgrade venv
cd python

# Install all project dependencies
../venv/bin/pip install --find-links=. --no-cache .

# Install AFL deps (cython required)
../venv/bin/pip install --find-links=. --no-cache .[dev]
```

