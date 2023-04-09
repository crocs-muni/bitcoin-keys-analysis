# bitcoin-keys-analysis

A set of tools for extraction and analysis of Bitcoin ECDSA and Schnorr keys.

You can see achieved results in the [results repo](https://github.com/crocs-muni/bitcoin-keys-analysis-results-).

(!) Please note that currently ***only extraction part*** is implemented and fully working.

## Navigation
1. [Basic Usage Demonstration](#basic-usage-demonstration)
2. [Getting Started](#getting-started)
3. [For Developers](#for-developers)
## Basic Usage Demonstration

### [bitcoin_public_key_parser.py](src/bitcoin_public_key_parser.py)
##### BitcoinPublicKeyParser.process_transaction(self, txid: str)

``` python
$ python3 -i src/bitcoin_public_key_parser.py
>>> parser.show_dict(parser.schnorr_data)
>>> parser.process_transaction("37777defed8717c581b4c0509329550e344bdc14ac38f71fc050096887e535c8")
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
#### BitcoinPublicKeyParser.process_block_range(self, range_to_parse: range)

###### Verbosity set to `False`

``` python
$ python3 -i src/bitcoin_public_key_parser.py
>>> parser.process_block_range(range(739000, 739010))

==================================================================================================================================================
Gathered  62032  keys:  61861  ECDSA keys,  171  Schnorr Signature keys; in  68.78719115257263  seconds.
Failed to parse  1  inputs ( 0.00 %) and  0  outputs ( 0.00 %).
==================================================================================================================================================
```
``` bash
$ head gathered-data/ecdsa_data_739009.json
```
``` JSON
{
  "739000": [
    "029f19fe3201234ea81fb0db2459ad78f86971668f7118c1ee70a12ec49bb21915",
    "0351aa078f904d05cfbf8f6a6d5b77e080b81af5ff14300828741af23849e11a8c",
    "022b3d369293d1c9ca5653b60dea0aeb6ef28f4cf485d09ec25b55822aaa610b28",
    "034b550906409eda781e79003279f1594d34919c92faafb9a47f3fcc519c989bbb",
    "03aade021abde36ef17d001533c5a8cd9dd21356f79329a1bc0cd40c9d8d5a390d",
    "024662046ed73f537c4494260f4936345aac50bfd76294e2a55bba1ea3e8e16860",
    "027df847463af80a068ff276d5216369b7976d196ed0c264639b8833b2e8322fbd",
    "0280e00bfdc1cee0b876deb9239db081f2b97920d97ed48462bc051ff4d5b8485f",
```

###### Verbosity set to `True`

``` python
$ python3 -i src/bitcoin_public_key_parser.py
>>> parser.set_verbosity(True)
>>> parser.process_block_range(range(739000, 739010))

==================================================================================================================================================
Gathered  60756  keys:  60593  ECDSA keys,  163  Schnorr Signature keys; in  65.47546219825745  seconds.
Failed to parse  1  inputs ( 0.00 %) and  0  outputs ( 0.00 %).
==================================================================================================================================================
```
``` bash
$ head gathered-data/ecdsa_data_739009.json
```
``` JSON
{
  "02f0f594ad1df6c82ea1daf34fe1d979acb10430120a16a8021b5f6b0c2ae7edb0": [
    {
      "ID": "210fcdcfd6c1115716a0ac0f8a0d889f1c2e8360636f001b051081d067cfe2f0",
      "vin/vout": "vin 0",
      "signature": "30440220099c34e83b91334882eb3871d2dd68e94a97e845a42893a14a45bb730120b9e502202b11dba6dc8a62f2ec14d4bdfb0ca06461ee5f0814ba020b5b0bf278b5c7e33301"
    }
  ],
  "037381cb6c6a7c5bf7d9576055c4ad4401d609f8a1ebd1837e9d6a685b0bd98b4b": [
    {
```
``` bash
$ cat gathered-data/tx_types_739009.json
```
``` JSON
{
  "2022.06": {
    "nonstandard": 0,
    "pubkey": 0,
    "pubkeyhash": 21843,
    "scripthash": 35993,
    "multisig": 0,
    "nulldata": 123,
    "witness_v0_scripthash": 3534,
    "witness_v0_keyhash": 38032,
    "witness_v1_taproot": 92,
    "witness_unknown": 0
  }
}
```


If you feel interested at this point, have a look at [demo.txt](other/demo.txt) or look through [bitcoin_public_key_parser.py](src/bitcoin_public_key_parser.py) file to see, what other functions are there (most useful ones are at the end).

## Getting Started
### Prerequisites
- ##### [python3](https://www.python.org/downloads/)
- ##### [Bitcoin Core Daemon](https://bitcoin.org/en/download)

  Please read the [guide](https://bitcoin.org/en/full-node) ***in full***. You need *Bitcoin Core Daemon* (not Bitcoin Core GUI)! 

- ##### [python-bitcoinlib](https://pypi.org/project/python-bitcoinlib/)

  `pip3 install python-bitcoinlib`

### Info about the blockchain
To use the extraction part of our project ([bitcoin_public_key_parser.py](src/bitcoin_public_key_parser.py)) a one must download corresponding part of the Bitcoin blockchain. If you want to give a quick try, you can download only first ~100 blocks really quick and this won't take a lot of disk space. However, if you want to parse the whole blockchain, you'll need about 430GB (as for 09.2022) of free space, the process takes 2-5 days of time. The downloading automatically starts, when you launch `bitcoind` daemon. To stop the downloading (and verification) of the blockchain, stop the daemon (`bitcoin-cli stop`) or block it's access to the internet. Because Bitcoin Core is a [full-node](https://bitcoin.org/en/full-node#what-is-a-full-node) Bitcoin client, it downloads the blockchain from the genesis block. Meaning that if a one wants to parse only the last block, they still have to download and validate the whole blockchain. However, in that case a one can delete unnecessary parts of the blockchain after the validation or use ["pruned mode"](https://bitcoin.org/en/full-node#reduce-storage) during the download.

### Actually starting
1. Install the [prerequisites](#prerequisites)
2. Clone this repository

    `git clone https://github.com/crocs-muni/bitcoin-keys-analysis.git`
    
    `cd bitcoin-keys-analysis/`

3. Set up a config file

    1. Copy default config to your `~/.config` directory.

        `cp other/bitcoin_public_key_parser.ini ~/.config`

    2. Change `project_dir` value (4th line) to an actual absolute path to the project's directory.

        `nano ~/.config/bitcoin_public_key_parser.ini`

    **Note**: later you might need to adjust values in `[RAM_USAGE]` section, but for now, you do not need to care about it. 

4. Create directories for gathered data and logs.

     1. If you *did not* change any values in the config file except of `project_dir` inside of `[PATHS]` section, run the following commands in the project directory:

        `mkdir gathered-data`

        `mkdir logs`

     2. If you *did* change paths to gathered data and log directories in the config file, you should ensure that this paths are valid (specified directories must exist).

5. Do the instructions from [block_internet.md](other/block_internet.md) to be able to block Bitcoin Core's access to the internet, when you need to.

6. Enable RPC server in bitcoin.conf:

   `cd ~`
   
   `mkdir .bitcoin`
   
   `cd .bitcoin`
   
   `echo "server=1" >> bitcoin.conf`
   
   `echo "txindex=1" >> bitcoin.conf`
   
   `echo "rpcuser=user" >> bitcoin.conf`
   
   `echo "rpcpassword=password" >> bitcoin.conf`


7. Run a Bitcoin Core daemon.
    Now there are some options in what way you get Bitcoin blocks:
  
    1. Run `bitcoind -daemon` command. This will start [Initial Block Download](https://bitcoin.org/en/full-node#initial-block-downloadibd) process and the daemon will continuously download blocks. The downloading will carry on while daemon runs (use `bitcoin-cli stop` to stop it) and while it has access to the internet. This is the way Bitcoin Core developers expect you to get blocks, but be careful, because you might run out of disk space really quick or use more network traffic that you'd want to. To avoid this take a look at the second option.

    2. Use "pre-downloaded" blocks from us:

        `unzip examples/bitcoin_blocks.zip`
        
        `mv .bitcoin ~`
    
        And after that run Bitcoin Core without internet access.
    
        `./other/enable_no-internet.sh`

        `no-internet "bitcoind -daemon"`

        Now you are able to try some basic functionality of [bitcoin_public_key_parser.py](src/bitcoin_public_key_parser.py) without dowloading much stuff. This option is good for those, who just want to give a quick try of your project, but is not really suitable for those, who want to analyse the whole blockchain / who really care about data authentity.

    3. As a third option, you might also normally run `bitcoind` (with no `-daemon` to see progress) and when enough blocks will be downloaded stop it and then re-run it without internet access.

8. **Check-list**:

    - python3
    - python-bitcoinlib (installed python3 module)
    - Config file in `~/.config` directory
    - Directories for gathered data and logs exist.
    - Bitcoin Core Daemon (you are able to run `bitcoind` in terminal)
    - Some amount of blocks downloaded (in `~/.bitcoin` directry) 
    - Enabled RPC server (corresponding `~/.bitcoin/bitcoin.conf` file)
    - Completed instructions from [block_internet.md](other/block_internet.md) (optional, but recommended)

9. You are ready to go! Try to run `./demo.py` in the project's src directory.

## For Developers
To run tests a one will need to install [pytest](https://docs.pytest.org/en/7.1.x/getting-started.html) python3 module.

 `pip3 install -U pytest`

If you feel like contributing, please contact [Petr Svenda](https://github.com/petrs) first.
