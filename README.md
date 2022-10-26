# bitcoin-keys-analysis

A set of tools for extraction and analysis of Bitcoin ECDSA and Schnorr keys.

(!) Please note that currently ***only extraction part*** is implemented and fully working.

## Navigation
1. [Basic Usage Demonstration](#basic-usage-demonstration)
2. [Getting Started](#getting-started)
3. [For Developers](#for-developers)
## Basic Usage Demonstration

### [parse.py](src/parse.py)
##### Parser.process_transaction(self, txid: str)

``` python
$ python3 -i parse.py
>>> parser.process_transaction("37777defed8717c581b4c0509329550e344bdc14ac38f71fc050096887e535c8")
True
>>> parser.show_dict(parser.schnorr_data)
```
``` JSON
{
  "5f4237bd7dae576b34abc8a9c6fa4f0e4787c04234ca963e9e96c8f9b67b56d1": [
    {
      "ID": "37777defed8717c581b4c0509329550e344bdc14ac38f71fc050096887e535c8",
      "vin/vout": "vin 0",
      "signature": "134896c42cd95680b048845847c8054756861ffab7d4abab72f6508d67d1ec0c590287ec2161dd7884983286e1cd56ce65c08a24ee0476ede92678a93b1b180c"
    }
  ],
  "d9dfdf0fe3c83e9870095d67fff59a8056dad28c6dfb944bb71cf64b90ace9a7": [
    {
      "ID": "37777defed8717c581b4c0509329550e344bdc14ac38f71fc050096887e535c8",
      "vin/vout": "vin 1",
      "signature": "NaN"
    }
  ],
  "f5b059b9a72298ccbefff59d9b943f7e0fc91d8a3b944a95e7b6390cc99eb5f4": [
    {
      "ID": "37777defed8717c581b4c0509329550e344bdc14ac38f71fc050096887e535c8",
      "vin/vout": "vin 1",
      "signature": "7b5d614a4610bf9196775791fcc589597ca066dcd10048e004cd4c7341bb4bb90cee4705192f3f7db524e8067a5222c7f09baf29ef6b805b8327ecd1e5ab83ca"
    }
  ]
}
```
#### Parser.process_blocks(self, start: int, end: int)

``` python
$ python3 -i parse.py
>>> parser.process_blocks(739000, 739001)

==================================================================================================================================================
Gathered  4867  keys:  4839  ECDSA keys,  28  Schnorr Signature keys; in  5.632800183999279  seconds.
Failed to parse  0  inputs ( 0.00 %) and  0  outputs ( 0.00 %).
==================================================================================================================================================
```
``` bash
$ head gathered-data/ecdsa_data_739000.txt
```
``` JSON
{
  "02018eb32174d67f3d247101d2ee3f9558dff7a5ea035ce9440f2dbb4b455ec5e9": [
    {
      "ID": "13cd6e3ae96a85bb567a681fbb339719d030cf7d8936cdfc6803069b42774052",
      "vin/vout": "vin 0",
      "signature": "3045022100e4a220aa4d951c3d94af03adc9b5cd2e41d2bc96747c11b00ee817b79526f0ca02200f1bb4ac9c3c4a8beb4ac271efa946e02f226c5d14283a17fac686072bded2f401"
    }
  ],
  "03e77710452b490c0e0bddbe1aa06d4f373bfceb1c7fb4797430739ec965a49faf": [
    {
```
``` bash
$ head gathered-data/unmatched_ecdsa_data_739000.txt
```
``` JSON
{
  "0375e00eb72e29da82b89367947f29ef34afb75e8654f6ea368e0acdfd92976b7c": [
    {
      "ID": "cbcb20d5e883a3b4590d024c9b722313f0686813ecd3999cdc633af11ab7e197",
      "vin/vout": "vin 0",
      "signatures": [
        "304402207e7181c972e85e786e7dbdb7f26767fd5f46e1d2ab8f7054ff63231fc371c15202201abcded110359062a5a6154883965bd5395aa2437b53e1464280f41fc10ad67701",
        "30440220785586b83592e6f4766b487bcf784804c0cbf3186e668827f52f47c662df95510220254876aa0bf800275e78720cdd6e06b9ca9d444a29cf69959d97798556878c0801"
      ]
    },
```
``` bash 
$ head gathered-data/schnorr_data_739000.txt
```
``` JSON
{
  "188d3a331f7683314047e5159b7d43df12d692ae957841d1d23c13a31732504d": [
    {
      "ID": "ef2dc75126f1a3a1a08b8630b0a1ef6de10742db9db96573d294423da926bb82",
      "vin/vout": "vin 0",
      "signature": "NaN"
    }
  ],
  "6ea0037df9f8708723834c93b9f0b1cc558be0e394aa22be9e841ae8e871f890": [
    {
```
If you feel interested at this point, look through [parse.py](src/parse.py) file to see, what other functions are there.

## Getting Started
### Prerequisites
- ##### [python3](https://www.python.org/downloads/)
- ##### [Bitcoin Core Daemon](https://bitcoin.org/en/download)

  Please read the [guide](https://bitcoin.org/en/full-node) ***in full***. You need *Bitcoin Core Daemon* (not Bitcoin Core GUI)! 

- ##### [python-bitcoinlib](https://pypi.org/project/python-bitcoinlib/)

  `pip3 install python-bitcoinlib`

### Info about the blockchain
To use the extraction part of our project ([parse.py](src/parse.py)) a one must download corresponding part of the Bitcoin blockchain. If you want to give a quick try, you can download only first ~100 blocks really quick and this won't take a lot of disk space. However, if you want to parse the whole blockchain, you'll need about 430GB (as for 09.2022) of free space, the process takes 2-5 days of time. The downloading automatically starts, when you launch `bitcoind` daemon. To stop the downloading (and verification) of the blockchain, stop the daemon (`bitcoin-cli stop`) or block it's access to the internet. Because Bitcoin Core is a [full-node](https://bitcoin.org/en/full-node#what-is-a-full-node) Bitcoin client, it downloads the blockchain from the genesis block. Meaning that if a one wants to parse only the last block, they still have to download and validate the whole blockchain. However, in that case a one can delete unnecessary parts of the blockchain after the validation or use ["pruned mode"](https://bitcoin.org/en/full-node#reduce-storage) during the download.

### Actually starting
1. Install the [prerequisites](#prerequisites)
2. Clone this repository

    `git clone https://github.com/crocs-muni/bitcoin-keys-analysis.git`
    
    `cd bitcoin-keys-analysis/`

3. Do the instructions from [block_internet.md](other/block_internet.md) to be able to block Bitcoin Core's access to the internet, when you need to.

4. Enable RPC server in bitcoin.conf:

   `cd ~`
   
   `mkdir .bitcoin`
   
   `cd .bitcoin`
   
   `echo "server=1" >> bitcoin.conf`
   
   `echo "txindex=1" >> bitcoin.conf`
   
   `echo "rpcuser=user" >> bitcoin.conf`
   
   `echo "rpcpassword=password" >> bitcoin.conf`


5. Run a Bitcoin Core daemon.
    Now there are some options in what way you get Bitcoin blocks:
  
    1. Run `bitcoind -daemon` command. This will start [Initial Block Download](https://bitcoin.org/en/full-node#initial-block-downloadibd) process and the daemon will continuously download blocks. The downloading will carry on while daemon runs (use `bitcoin-cli stop` to stop it) and while it has access to the internet. This is the way Bitcoin Core developers expect you to get blocks, but be careful, because you might run out of disk space really quick or use more network traffic that you'd want to. To avoid this take a look at the second option.

    2. Use "pre-downloaded" blocks from us:

        `unzip examples/bitcoin_blocks.zip`
        
        `mv .bitcoin ~`
    
        And after that run Bitcoin Core without internet access.
    
        `./other/enable_no-internet.sh`

        `no-internet "bitcoind -daemon"`

        Now you are able to try some basic functionality of [parse.py](src/parse.py) without dowloading much stuff. This option is good for those, who just want to give a quick try of your project, but is not really suitable for those, who want to analyse the whole blockchain / who really care about data authentity.

    3. As a third option, you might also normally run `bitcoind` (with no `-daemon` to see progress) and when enough blocks will be downloaded stop it and then re-run it without internet access.

6. **Check-list**:

    - python3
    - python-bitcoinlib (installed python3 module)
    - Bitcoin Core Daemon (you are able to run `bitcoind` in terminal)
    - Some amount of blocks downloaded (in `~/.bitcoin` directry) 
    - Enabled RPC server (corresponding `~/.bitcoin/bitcoin.conf` file)
    - Completed instructions from [block_internet.md](other/block_internet.md) (optional, but strongly recommended)

7. You are ready to go! Try to run `./demo.py` in the project's src directory.

## For Developers
To run tests a one will need to install [pytest](https://docs.pytest.org/en/7.1.x/getting-started.html) python3 module.

 `pip3 install -U pytest`

If you feel like contributing, please contact [Petr Svenda](https://github.com/petrs) first.
