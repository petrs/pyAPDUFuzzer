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
# Mac:
brew install afl-fuzz

# Others:
cd /tmp
wget http://lcamtuf.coredump.cx/afl/releases/afl-latest.tgz
tar -xzvf afl-latest.tgz
cd afl-*
make
sudo make install

# Install python dependencies
../venv/bin/pip install --find-links=. --no-cache .[afl]
```

## AFL fuzzing

Start server sitting on the card:

```
python main_afl.py --server
```


Testing if the client works:

```
echo -n '0000' | ../venv/bin/python main_afl.py --client --output ydat.json --log ylog.txt
cat yres.json
```

TCP IP forking:

```
../venv/bin/py-afl-fuzz -m 500 -t 5000 -o result/ -i inputs/ -- ../venv/bin/python main_afl.py --client --output ydat.json --log ylog.txt
```

