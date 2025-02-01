URL: https://3rditeration.github.io/btc-extended-key-converter/
---
# Bitcoin Extended Public & Private Key Converter

* * *

You can enter any version of a valid Bitcoin extended public/private key and convert it to another version of the same extended key. (For example, exporting an xpub/ypub/zpub from Ledger Live to use in some other wallet or tool.)

For more info see [SLIP-0132](https://github.com/satoshilabs/slips/blob/master/slip-0132.md).


**The online version of this tool should only ever be used for working with extended public keys (xpub, etc) or for testing/education purposes...**

You should normally never need to convert or handle xprv keys except in VERY SPECIFIC recovery situations... Working with extended private keys (xprv/yprv/zprv, etc) should only ever be done in an offline (all networking disconnected), amnesic environment like TAILS Linux... [Click here to download a zip file containing this tool to run offline](https://github.com/3rdIteration/btc-extended-key-converter/archive/master.zip)

Paste your extended key to be converted here:

What version do you want to convert the extended key into?

xpub 'Legacy' (mainnet P2PKH or P2SH)ypub 'Segwit' (mainnet P2WPKH in P2SH)zpub 'Native Segwit' (mainnet P2WPKH)Ypub 'Multisig Segwit' (mainnet P2WSH in P2SH)Zpub 'Multisig Native Segwit' (mainnet P2WSH)tpub 'Legacy' (testnet P2PKH or P2SH)upub 'Segwit' (testnet P2WPKH in P2SH)vpub 'Native Segwit' (testnet P2WPKH)Upub 'Multisig Segwit' (testnet P2WSH in P2SH)Vpub 'Multisig Native Segwit' (testnet P2WSH)xprv 'Legacy' (mainnet P2PKH or P2SH)yprv 'Segwit' (mainnet P2WPKH in P2SH)zprv 'Native Segwit' (mainnet P2WPKH)Yprv 'Multisig Segwit' (mainnet P2WSH in P2SH)Zprv 'Multisig Native Segwit' (mainnet P2WSH)tprv 'Legacy' (testnet P2PKH or P2SH)uprv, 'Segwit' (testnet P2WPKH in P2SH)vprv, 'Native Segwit' (testnet P2WPKH)Uprv, 'Multisig Segwit' (testnet P2WSH in P2SH)Vprv, 'Multisig Native Segwit' (testnet P2WSH)

Convert

**Converted extended key:**

Fingerprint:

Parent Fingerprint:

**Extended Key QR Code:**

_Scan this QR code with a Bitcoin wallet like Blue Wallet or Electrum_

* * *

## This tool is 100% open source code

The Bitcoin Extended Public & Private Key Converter repository can be found at [https://github.com/3rdIteration/btc-extended-key-converter](https://github.com/3rdIteration/btc-extended-key-converter)

This tool expands on the original tool found here: [https://github.com/jlopp/xpub-converter/](https://github.com/jlopp/xpub-converter/)

### Libraries

bs58check: [https://github.com/bitcoinjs/bs58check](https://github.com/bitcoinjs/bs58check)

Twitter Bootstrap: [http://getbootstrap.com/](http://getbootstrap.com/)