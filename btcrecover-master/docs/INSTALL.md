# Installing BTCRecover #

There are a few basic steps to installing BTCRecover.

1) Download and unzip the BTCRecover script

2) Download and install Python3

3) Install required packages via Python PIP

4) (Optional) Install PyOpenCL module for GPU Acceleration

5) Test your installation (Optional, but a good idea)

These steps are also covered in Videos below for each supported Operating System.

**Note: Depending on your operating system and python environment, you may need to replace the `python` command with `python3`. (By default, the command to use will be `python` in Windows and `python3` in Linux) Most non-technical users are on Windows, so all example commands will use `python` to match the defaults for this platform** 

**Video Tutorials**

Windows: <https://youtu.be/8q65eqpf4gE>

Ubuntu Linux: <https://youtu.be/Met3NbxcZTU>

MacOS: <https://youtu.be/Qzc3oHzbcAo>


## 1) Downloading *btcrecover* ##

Just download the latest version from <https://github.com/3rdIteration/btcrecover/archive/master.zip> and unzip it to a location of your choice. There’s no installation procedure for *btcrecover* itself, however there are additional requirements below depending on your operating system and the wallet type you’re trying to recover.


## 2) Install Python ##

**Note:** Only Python 3.8 and later are officially supported... BTCRecover is automatically tested with all supported Python versions (3.8, 3.9, 3.10, 3.11) on all supported environments (Windows, Linux, Mac), so you can be sure that both BTCRecover and all required packages will work correctly. Some features of BTCRecover may work on earlier versions of Python, your best bet is to use run-all-tests.py to see what works and what doesn't...

### Windows ###
Video Demo of Installing BTCRecover in Windows: <https://youtu.be/8q65eqpf4gE>

Visit the Python download page here: <https://www.python.org/downloads/windows/>, and click the link for the latest **Python 3.10** release (Python 3.11, etc, will work, but Python 3.10 has simpler installation of required modules) release near the top of the page under the heading *Python Releases for Windows*. Download and run either the `Windows x86 MSI installer` for the 32-bit version of Python, or the `Windows x86-64 MSI installer` for the 64-bit one. Modern PCs should use the 64-bit version, however if you're unsure which one is compatible with your PC, choose the 32-bit one.

_**When installing Python in Windows, be sure to select to "Add Python to PATH" on the first screen of the installer...**_

**Note for Large Multi-CPU Systems:** Windows limits the number of possible threads to 64. If your system has more logical/physical cores than this, your best bet is to run the tool in Linux. (Ubuntu is an easy place to start)

### Linux ###
Video Demo of Installing BTCRecover in Ubuntu Live USB: <https://youtu.be/Met3NbxcZTU>

Most modern distributions include Python 3 pre-installed. Older Linux distributions will include Python2, so you will need to install python3.

If you are using SeedRecover, you will also need to install tkinter (python3-tk) if you want to use the default GUI popups for seedrecover. (Command line use will work find without this package)

Some distributions of Linux will bundle this with Python3, but for others like Ubuntu, you will need to manually install the tkinter module.

You can install this with the command: `sudo apt install python3-tk`

If any of the "pip3" commands below fail, you may also need to install PIP via the command: `sudo apt install python3-pip`

If you get a message that there is no installation candidate for Python3-pip, you will need to enable the "universe" repository with the command: `sudo add-apt-repository universe`

You can then re-run the command to install python3-pip from above.

#### Enabling Native RIPEMD160 Support
As of OpenSSL v3 (Late 2021), ripemd160 is no longer enabled by default and is now part of the "Legacy" set of hash functions. In Linux/MacOS environments, the hashlib module in Python relies on OpenSSL for ripemd160, so if you want full performance in these environments, you may need modify your OpenSSL settings to enable the legacy provider.

As of July 2022, BTCRecover does include a "pure Python" implementation of RIPEMD160, but this only offers about 1/3 of the performance when compared to a native implementation via hashlib.

Video Demo of this applying fix can be found here: <https://youtu.be/S3DWKp0i4i0>

An example of the modified configuration file can be found here: <https://github.com/3rdIteration/btcrecover/blob/master/docs/example_openssl.cnf>

For more information, see the relevant issue on the OpenSSL Github repository: <https://github.com/openssl/openssl/issues/16994>

### MacOS ###

Video Demo of Installing BTCRecover in MacOS: <https://youtu.be/Qzc3oHzbcAo>

1) [Install brew via instructions at brew.sh](https://brew.sh)
   
The Install command is:  

    /bin/bash -c "$(curl -fsSL https://raw.githubusercontent.com/Homebrew/install/HEAD/install.sh)"

_Be sure to follow the instructions and add brew to your path..._
   
2) [Install coincurve build requirements](https://ofek.dev/coincurve/install/) 
   
The Install command is:

    brew install autoconf automake libffi libtool pkg-config python

_If you want to use the graphical interface, be sure to follow the instructions to install tkinter as well._

**Once you have installed Python via Brew, you will need to run both Python and PIP with commands that include the full version numnber. (eg: python3.9 and pip3.9)**

## 3) Install requirements via Python Pip ##

Once both Python3 and PIP have been installed, you can install the requirements for BTCRecover.

### Essential Requirements
You will first want to install the basic packages required for BTCRecover with the command:

`pip3 install -r requirements.txt`

This will give you the functionality needed recovery of Bitcoin/Ethereum wallets (And clones of these chains)

### Packages for Extended Wallet Support
Depending on your wallet type, you may also want to install the packages required for full wallet support. This is a much larger download and may also require that you install additional software on your PC for these packages to build and install.

`pip3 install -r requirements-full.txt`

### Installing individual packages
If you are an advanced user, you may choose to install only those additional packages that are required for the specific recovery you are attempting. More information about which wallets require which packages is at the bottom of this guide.*

## 4) Install PyOpenCL for GPU Acceleration ##

GPU Support will require additional OpenCL libraries to be installed that aren't covered by the above commands... 

For more information and instructions, [see the GPU acceleration page here](./GPU_Acceleration.md)

## 5) Testing your Installation ##

Once you have downloaded and unzipped BTCRecover, installed Python and all required libraries, you can test the program with the command:

`python run-all-tests.py -vv`

This command will take a few minutes to run and should complete without errors, indicating that your system is ready to use all features of BTCRecover.

## Wallet Python Package Requirements ##

**If you want to install all requirements for all wallet types, you can simply use the command `pip3 install -r requirements-full.txt`**

Locate your wallet type in the list below, and follow the instructions for only the sections listed next to your wallet.

 * Bitcoin Core - optional: [PyCryptoDome](#pycryptodome)
 * MultiBit Classic - recommended: [PyCryptoDome](#pycryptodome)
 * MultiBit HD - optional: [PyCryptoDome](#pycryptodome)
 * Electrum (1.x or 2.x) - recommended: [PyCryptoDome](#pycryptodome)
 * Electrum 2.8+ fully encrypted wallets - [coincurve](Seedrecover_Quick_Start_Guide.md#installation), optional: [PyCryptoDome](#pycryptodome)
 * BIP-39 Bitcoin passphrases (e.g. TREZOR) - [coincurve](Seedrecover_Quick_Start_Guide.md#installation)
 * BIP-39 Ethereum passphrases (e.g. TREZOR) - [PyCryptoDome](#pycryptodome) [coincurve](Seedrecover_Quick_Start_Guide.md#installation)
 * Hive for OS X - [Google protobuf](#google-protocol-buffers), optional: [PyCryptoDome](#pycryptodome)
 * mSIGNA (CoinVault) - recommended: [PyCryptoDome](#pycryptodome)
 * Blockchain.info - recommended: [PyCryptoDome](#pycryptodome)
 * Bitcoin Wallet for Android/BlackBerry backup - recommended: [PyCryptoDome](#pycryptodome)
 * Bitcoin Wallet for Android/BlackBerry spending PIN - [scrypt](#scrypt), [Google protobuf](#google-protocol-buffers), optional: [PyCryptoDome](#pycryptodome)
 * KnC Wallet for Android backup - recommended: [PyCryptoDome](#pycryptodome)
 * Bither - [coincurve](Seedrecover_Quick_Start_Guide.md#installation), optional: [PyCryptoDome](#pycryptodome)
 * Litecoin-Qt -  optional: [PyCryptoDome](#pycryptodome)
 * Electrum-LTC - recommended: [PyCryptoDome](#pycryptodome)
 * Litecoin Wallet for Android - recommended: [PyCryptoDome](#pycryptodome)
 * Dogecoin Core -  optional: [PyCryptoDome](#pycryptodome)
 * MultiDoge - recommended: [PyCryptoDome](#pycryptodome)
 * Dogecoin Wallet for Android - recommended: [PyCryptoDome](#pycryptodome)
 * SLIP39 Wallets: [shamir-mnemonic](#shamir-mnemonic)
 * Py_Crypto_HD_Wallet Based BIP39 Wallets: [py_crypto_hd_wallet](#py_crypto_hd_wallet)
    * Avalanche
    * Cosmos (Atom)
    * Polkadot
    * Secret Network
    * Solana
    * Stellar
    * Tezos
    * Tron
 * Helium BIP39 Wallets: [pynacl](https://pypi.org/project/PyNaCl/) and [bitstring](https://pypi.org/project/bitstring/)
 * Eth Keystore Files: [eth-keyfile](https://pypi.org/project/eth-keyfile/)
 * Eth2 Validator Seed Recovery: [staking-deposit](#staking-deposit)
 * Groestlecoin BIP39 Wallets: [groestlcoin_hash](https://pypi.org/project/groestlcoin-hash/)
 * BIP38 Encrypted Private Keys: [ecdsa](https://pypi.org/project/ecdsa/)

----------

### PyCryptoDome ###

With the exception of Ethereum wallets, PyCryptoDome is not strictly required for any wallet, however it offers a 20x speed improvement for wallets that tag it as recommended in the list above.

### Py_Crypto_HD_Wallet ###

This module is required for a number of different wallet types.

For Windows Users, you will also need to install the Microsoft Visual C++ Build Tools befor you will be able to successfully install the module. 

A video tutorial that covers this can be found here: <https://youtu.be/0LMUf0R9Pi4>

For MacOS and Linux users, the module should build/install just fine if you follow the installation instructions on this page for your platform.

### Staking-Deposit ###

This module isn't available as a pre-compiled package and must be downloaded and built from source.

It is installed as part of the collection of modules installed by `requirements-full.txt`.

Alternately, you can attempt to download, build and install it via pip3 with the following command:
   
`pip3 install git+https://github.com/ethereum/staking-deposit-cli.git@v2.5.0`

This module also requires the `py_ecc` module which can be installed with the command:

`pip3 install py_ecc`

[More information can be found at its repository](https://github.com/ethereum/staking-deposit-cli/)

Note: Some dependencies for this module won't always build if you are running the latest version of Python, if you run into build errors, you should try the previous major Python Versions until you find one that works on your system (eg: Something like 3.9)
