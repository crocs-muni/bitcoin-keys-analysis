#!/bin/python3
import sys, os
sys.path.append("/home/xyakimo1/crocs/src") # add here path to the project's source directory
from bitcoin_public_key_parser import BitcoinPublicKeyParser, BitcoinRPC
import pytest
import json, copy, shutil

rpc = BitcoinRPC()
parser = BitcoinPublicKeyParser(rpc)
parser.set_verbosity(True)

def set_state(parser: BitcoinPublicKeyParser, txid, vin_vout, n):
    parser.state["txid"] = txid
    parser.state["vin/vout"] = vin_vout
    parser.state["n"] = n

@pytest.mark.parametrize("suspected_key, expected_result",
                         [("03bc7a18a65c8468994f75a87e7407a82ffabbc44656417491b2649fb5ee5bfdac", True), # real ECDSA public key
                          ("02018eb32174d67f3d247101d2ee3f9558dff7a5ea035ce9440f2dbb4b455ec5e9", True),
                          ("3045022100fe7d601f17d3334b669ce55d068b3420434766846e14509fc1ddb539bf3a71f70220556ae2fd9919420a9505a07e7243a3259375955156f1875ba84b58abdc7b1f0101", False), # ECDSA signature
                          ("b2739443fa914fdbcedbcb1672c991dd6359afc1", False), # OP_HASH160 hash
                          ("159914d19974d9d2c8e658ff822f09e5f0e8a439ca5b4490d39df13f71843350", False), # Schnorr's public key
                          ("5e231b860b6fe188e2b7ec4a0c9f10e907f1edba19a9a1877da75efafc2527279a634eda6fedc5ff7ec22271f1e76cfbca69b335f544754f5d35f7b57524b77c", False), # Schnorr's signature
                          ("ad5fb1f095dac7c7c3adff095dff973aed868f88fff8fa1ca3f248a6a6864acf", False) # TXID
                         ])
def test_correct_ecdsa_key(suspected_key: str, expected_result: bool):
    assert parser.correct_ecdsa_key(suspected_key) == expected_result


@pytest.mark.parametrize("suspected_key, expected_result",
                         [("03bc7a18a65c8468994f75a87e7407a82ffabbc44656417491b2649fb5ee5bfdac", False), # ECDSA public key
                          ("3045022100fe7d601f17d3334b669ce55d068b3420434766846e14509fc1ddb539bf3a71f70220556ae2fd9919420a9505a07e7243a3259375955156f1875ba84b58abdc7b1f0101", False), # ECDSA signature
                          ("b2739443fa914fdbcedbcb1672c991dd6359afc1", False), # OP_HASH160 hash
                          ("159914d19974d9d2c8e658ff822f09e5f0e8a439ca5b4490d39df13f71843350", True), # Real Schnorr's public key
                          ("6c986f26fc5c3b883fd1617b2a65e161d5414862378712bd62c5cb9722005d43", True),
                          ("5e231b860b6fe188e2b7ec4a0c9f10e907f1edba19a9a1877da75efafc2527279a634eda6fedc5ff7ec22271f1e76cfbca69b335f544754f5d35f7b57524b77c", False), # Schnorr's signature
                          ("ad5fb1f095dac7c7c3adff095dff973aed868f88fff8fa1ca3f248a6a6864acf", True) # TXID, supposed to be false, but the length is same - 32 bytes, so should return true.
                         ])
def test_correct_schnorr_key(suspected_key: str, expected_result: bool):
    assert parser.correct_schnorr_key(suspected_key) == expected_result


@pytest.mark.parametrize("suspected_key, expected_ecdsa, expected_schnorr, expected_keys",
                         [("03bc7a18a65c8468994f75a87e7407a82ffabbc44656417491b2649fb5ee5bfdac", 1, 0, 1),
                          ("159914d19974d9d2c8e658ff822f09e5f0e8a439ca5b4490d39df13f71843350", 1, 1, 2)])
def test_increment_key_count(suspected_key: str, expected_ecdsa: int, expected_schnorr: int, expected_keys: int):
    parser.increment_key_count(suspected_key)
    assert parser.statistics["ecdsa"] == expected_ecdsa
    assert parser.statistics["schnorr"] == expected_schnorr
    assert parser.statistics["keys"] == expected_keys


@pytest.mark.parametrize("txid, vin_n, expected_signature", [
    ("ad511d71762f4123df227e2e048672c4df8cc2ac056ee37f52ff33085b2a2c47", 0, "304502200f55222e27f6b6aff33e314339e569b54e80df76f628daa2c76ef56558bc650c022100c989ec3a0fad6b1aff1087378c219091de70bac9d7bf3ebfa7718a6c4fa7aeb701"), # P2PK
    ("ce6fb9e782df2f5dbd4190069c3ec31ccf1ea2429b890da3c2b12ef37037a5be", 0, "304402207ebfd1151a2bb59336bb66b58164a8c17ea99b4a3c70f30056048d94d4532c11022070d4b82892bb2d809e6ec34adefd6669bbfdd50751e2ade7ab494a62a9e8d04401"), # P2PKH
    ("00e07f279dd05b9b68c40f21b43c57847e75c35cd3bbc2d80921eb037ef0c9a8", 1, "NaN") # P2SH
                                                           ])
def test_extract_signature_p2pk_p2pkh(txid: str, vin_n: int, expected_signature: str):
    vin = parser.rpc.getrawtransaction(txid, True)["vin"][vin_n]
    assert parser.extract_signature_p2pk_p2pkh(vin) == expected_signature


@pytest.mark.parametrize("txid, vin_n, expected_signature", [
    ("c0d210f7b6db4047f5852f98003ac46665ed17f6987f0b21af56998ed7a52c9a", 0, "NaN"), # P2SH
    ("c0d210f7b6db4047f5852f98003ac46665ed17f6987f0b21af56998ed7a52c9a", 2, "NaN"), # P2WSH
    ("9989bb6dd74ceeb6751502b728b948c6967d61a75f66c6d28de77b4d7d8b4cde", 0, "304402204f908d4c0aa09ad447cb224ff274e76d3b4dfa5ebf224cc38a84f91a13ac11c4022020c559bea114643b0d54086e0faa3bdf76ba14a2bc28a8ee8697ee0c6106fdbc01"), # P2WPKH
    ("ef21739d35f3d032edbbc6bb479ab67379f3b038a636472e313ca6ecda4b5b33", 7, "304502210097dfdc2d5db6bb15686f5858a6113e26354d51b1c5272a008a8398b6b9bea09d022052f9f9bf47ea4b17c7a2de6641aec15223d773301831448f5227c112383bc91f01")
                                                            ])
def test_extract_signature_p2wpkh(txid: str, vin_n: int, expected_signature: str):
    vin = parser.rpc.getrawtransaction(txid, True)["vin"][vin_n]
    assert parser.extract_signature_p2wpkh(vin) == expected_signature


@pytest.mark.parametrize("txid, vin_n, i, expected_signature", [
    ("c0d210f7b6db4047f5852f98003ac46665ed17f6987f0b21af56998ed7a52c9a", 0, 0, "NaN"), # P2SH
    ("c0d210f7b6db4047f5852f98003ac46665ed17f6987f0b21af56998ed7a52c9a", 2, 1, "NaN"), # P2WSH
    ("37777defed8717c581b4c0509329550e344bdc14ac38f71fc050096887e535c8", 0, 0, "134896c42cd95680b048845847c8054756861ffab7d4abab72f6508d67d1ec0c590287ec2161dd7884983286e1cd56ce65c08a24ee0476ede92678a93b1b180c") # P2TR KeyPath
    # TODO P2TR ScriptPath
                                                            ])
def test_extract_signature_p2tr(txid: str, vin_n: int, i: int, expected_signature: str):
    vin = parser.rpc.getrawtransaction(txid, True)["vin"][vin_n]
    assert parser.extract_signature_p2tr(vin, i) == expected_signature


@pytest.mark.parametrize("txid, vin_n, expected_result, expected_dict", [
    ("ce6fb9e782df2f5dbd4190069c3ec31ccf1ea2429b890da3c2b12ef37037a5be", 0, True,
        {
            "0337108c8c782b2dac8dafbab92a3a76871587c67f93e5ebd3f7c40ca3d4050472":
            [
                {
                    "ID": "ce6fb9e782df2f5dbd4190069c3ec31ccf1ea2429b890da3c2b12ef37037a5be",
                    "vin/vout": "vin 0",
                    "signature": "304402207ebfd1151a2bb59336bb66b58164a8c17ea99b4a3c70f30056048d94d4532c11022070d4b82892bb2d809e6ec34adefd6669bbfdd50751e2ade7ab494a62a9e8d04401"
                }
            ]
        }
    ),
    ("c0d210f7b6db4047f5852f98003ac46665ed17f6987f0b21af56998ed7a52c9a", 2, False, {})
                                                         ])
def test_process_input_p2pkh(txid: str, vin_n: int, expected_result: bool, expected_dict: dict):
    parser.ecdsa_data = {}
    transaction = parser.rpc.getrawtransaction(txid, True)
    vin = transaction["vin"][vin_n]
    set_state(parser, txid, "vin", vin_n)

    assert parser.process_input_p2pkh(vin) == expected_result
    assert parser.ecdsa_data == expected_dict


@pytest.mark.parametrize("txid, vin_n, expected_result, expected_dict", [
    ("ad511d71762f4123df227e2e048672c4df8cc2ac056ee37f52ff33085b2a2c47", 0, True,
        {
            "04c7a78b9a39471563ee652a5d9e71f788c2c2923c04341059d8a803f773b60071bf2919cc5f6de23932fddce3da8c6e80f92a38fd63c54ded9860c61f0817f971":
            [
                {
                    "ID": "ad511d71762f4123df227e2e048672c4df8cc2ac056ee37f52ff33085b2a2c47",
                    "vin/vout": "vin 0",
                    "signature": "304502200f55222e27f6b6aff33e314339e569b54e80df76f628daa2c76ef56558bc650c022100c989ec3a0fad6b1aff1087378c219091de70bac9d7bf3ebfa7718a6c4fa7aeb701"
                }

            ]
        }
    ),
    ("c0d210f7b6db4047f5852f98003ac46665ed17f6987f0b21af56998ed7a52c9a", 2, False, {})
                                                         ])
def test_process_input_p2pk(txid: str, vin_n: int, expected_result: bool, expected_dict: dict):
    parser.ecdsa_data = {}
    transaction = parser.rpc.getrawtransaction(txid, True)
    vin = transaction["vin"][vin_n]
    set_state(parser, txid, "vin", vin_n)

    assert parser.process_input_p2pk(vin) == expected_result
    assert parser.ecdsa_data == expected_dict


@pytest.mark.parametrize("txid, vout_n, expected_result, expected_dict", [
    ("1e3c85f59802e3907a254766fd466e308888bf3fcaa0723a9599b8ff41028503", 0, True,
        {
            "04c7a78b9a39471563ee652a5d9e71f788c2c2923c04341059d8a803f773b60071bf2919cc5f6de23932fddce3da8c6e80f92a38fd63c54ded9860c61f0817f971":
            [
                {
                    "ID": "1e3c85f59802e3907a254766fd466e308888bf3fcaa0723a9599b8ff41028503",
                    "vin/vout": "vout 0",
                    "signature": "NaN"
                }

            ]
        }
    ),
    ("e700b7b330e4b56c5883d760f9cbe4fa47e0f62b350e108f1767bc07a4bbc07b", 0, False, {})
                                                         ])
def test_process_output_p2pk(txid: str, vout_n: int, expected_result: bool, expected_dict: dict):
    parser.ecdsa_data = {}
    transaction = parser.rpc.getrawtransaction(txid, True)
    vout = transaction["vout"][vout_n]
    set_state(parser, txid, "vout", vout_n)

    assert parser.process_output_p2pk(vout) == expected_result
    assert parser.ecdsa_data == expected_dict


@pytest.mark.parametrize("txid, vin_n, expected_result, expected_dict", [
    ("00e07f279dd05b9b68c40f21b43c57847e75c35cd3bbc2d80921eb037ef0c9a8", 0, True,
        {
            "036c3735b2bf370501c3b872498de54b39ab5afa83d8ce7f6aec43f63a812265b4":
            [
                {
                    "ID": "00e07f279dd05b9b68c40f21b43c57847e75c35cd3bbc2d80921eb037ef0c9a8",
                    "vin/vout": "vin 0",
                    "signatures": [
                        "3045022100e40fbdec298b1fd267e43561e5d43822f0156c47772df2c1e955efe0f1f0a307022018946e8b11b7e1fb02f5c8ac6832991655dc44229a018aa19b9fc9a3daa66bf601",
                        "304402203137f3f5b00460854577cc8cc233030896e4bf464d06a4ec8b6ae768637e182602204a215cbe3ef950452964f248d84951e7646283c6cdbefd6dbd90613ecd2524e501"
                                  ]
                }
            ],
            "032b03a42faf387dd5c604435cd48d26b8827fa28a5d4d0f9a18b5cefe443bb410":
            [
                {
                    "ID": "00e07f279dd05b9b68c40f21b43c57847e75c35cd3bbc2d80921eb037ef0c9a8",
                    "vin/vout": "vin 0",
                    "signatures": [
                        "3045022100e40fbdec298b1fd267e43561e5d43822f0156c47772df2c1e955efe0f1f0a307022018946e8b11b7e1fb02f5c8ac6832991655dc44229a018aa19b9fc9a3daa66bf601",
                        "304402203137f3f5b00460854577cc8cc233030896e4bf464d06a4ec8b6ae768637e182602204a215cbe3ef950452964f248d84951e7646283c6cdbefd6dbd90613ecd2524e501"
                                  ]
                }
            ],
            "02ebbd4ecea67dd980fc4854cc13b1f10cefafdafe8b1eb8e5ce73939b59a0477c":
            [
                {
                    "ID": "00e07f279dd05b9b68c40f21b43c57847e75c35cd3bbc2d80921eb037ef0c9a8",
                    "vin/vout": "vin 0",
                    "signatures": [
                        "3045022100e40fbdec298b1fd267e43561e5d43822f0156c47772df2c1e955efe0f1f0a307022018946e8b11b7e1fb02f5c8ac6832991655dc44229a018aa19b9fc9a3daa66bf601",
                        "304402203137f3f5b00460854577cc8cc233030896e4bf464d06a4ec8b6ae768637e182602204a215cbe3ef950452964f248d84951e7646283c6cdbefd6dbd90613ecd2524e501"
                                  ]
                }
            ]
        }
    ),
    ("ce6fb9e782df2f5dbd4190069c3ec31ccf1ea2429b890da3c2b12ef37037a5be", 0, False, {})
                                                         ])
def test_process_input_p2sh(txid: str, vin_n: int, expected_result: bool, expected_dict: dict):
    parser.unmatched_ecdsa_data = {}
    transaction = parser.rpc.getrawtransaction(txid, True)
    vin = transaction["vin"][vin_n]
    set_state(parser, txid, "vin", vin_n)

    assert parser.process_input_p2sh(vin) == expected_result
    assert parser.unmatched_ecdsa_data == expected_dict


@pytest.mark.parametrize("txid, vin_n, expected_result, expected_dict", [
    ("9989bb6dd74ceeb6751502b728b948c6967d61a75f66c6d28de77b4d7d8b4cde", 0, True,
        {
            "03893037c89087a95351d74cb8419beca4680c02bdbb83808988d80368886ec043":
            [
                {
                    "ID": "9989bb6dd74ceeb6751502b728b948c6967d61a75f66c6d28de77b4d7d8b4cde",
                    "vin/vout": "vin 0",
                    "signature": "304402204f908d4c0aa09ad447cb224ff274e76d3b4dfa5ebf224cc38a84f91a13ac11c4022020c559bea114643b0d54086e0faa3bdf76ba14a2bc28a8ee8697ee0c6106fdbc01"
                }
            ]
        }
    ),
    ("00e07f279dd05b9b68c40f21b43c57847e75c35cd3bbc2d80921eb037ef0c9a8", 0, False, {})
                                                         ])
def test_process_input_p2wpkh(txid: str, vin_n: int, expected_result: bool, expected_dict: dict):
    parser.ecdsa_data = {}
    transaction = parser.rpc.getrawtransaction(txid, True)
    vin = transaction["vin"][vin_n]
    set_state(parser, txid, "vin", vin_n)

    assert parser.process_input_p2wpkh(vin) == expected_result
    assert parser.ecdsa_data == expected_dict


@pytest.mark.parametrize("txid, vin_n, expected_result, expected_dict", [
    ("c0d210f7b6db4047f5852f98003ac46665ed17f6987f0b21af56998ed7a52c9a", 2, True,
        {
            "03e1fc3528a3ee616ed38cfc525cb4c9b94517f165334f8269c8e31068bdf0468a":
            [
                {
                    "ID": "c0d210f7b6db4047f5852f98003ac46665ed17f6987f0b21af56998ed7a52c9a",
                    "vin/vout": "vin 2",
                    "signatures": [
                        "3045022100bed582633b971c9786720c325472b0808727b72280de798a995939f91c13cb3c0220216fb5dfdfb2914e71f54f1a1c2f54f65fb22e083d1c843b8d9487120f238d0a01",
                        "3045022100a28f052fbdb37dba174652ff30ce128f68f8fbfbe8a7d286d417cd7f79c79ad70220373412b7f0c9a1f85e693addb57c11a5598ef2b380764910fc843702471db35e01"
                                  ]
                }
            ],
            "0202708bae7a5f3b25fbef5406627166fff4ab6b2d4e779dcdb477f56fc64dce01":
            [
                {
                    "ID": "c0d210f7b6db4047f5852f98003ac46665ed17f6987f0b21af56998ed7a52c9a",
                    "vin/vout": "vin 2",
                    "signatures": [
                        "3045022100bed582633b971c9786720c325472b0808727b72280de798a995939f91c13cb3c0220216fb5dfdfb2914e71f54f1a1c2f54f65fb22e083d1c843b8d9487120f238d0a01",
                        "3045022100a28f052fbdb37dba174652ff30ce128f68f8fbfbe8a7d286d417cd7f79c79ad70220373412b7f0c9a1f85e693addb57c11a5598ef2b380764910fc843702471db35e01"
                                  ]
                }
            ],
            "030f0e8ebbfc107ebc29cb200b9d52a99868363ea9e334bed523cd85fc22b2adf3":
            [
                {
                    "ID": "c0d210f7b6db4047f5852f98003ac46665ed17f6987f0b21af56998ed7a52c9a",
                    "vin/vout": "vin 2",
                    "signatures": [
                        "3045022100bed582633b971c9786720c325472b0808727b72280de798a995939f91c13cb3c0220216fb5dfdfb2914e71f54f1a1c2f54f65fb22e083d1c843b8d9487120f238d0a01",
                        "3045022100a28f052fbdb37dba174652ff30ce128f68f8fbfbe8a7d286d417cd7f79c79ad70220373412b7f0c9a1f85e693addb57c11a5598ef2b380764910fc843702471db35e01"
                                  ]
                }
            ]
        }
    ),
    ("37777defed8717c581b4c0509329550e344bdc14ac38f71fc050096887e535c8", 1, False, {})
                                                         ])
def test_process_input_p2wsh(txid: str, vin_n: int, expected_result: bool, expected_dict: dict):
    parser.unmatched_ecdsa_data = {}
    transaction = parser.rpc.getrawtransaction(txid, True)
    vin = transaction["vin"][vin_n]
    set_state(parser, txid, "vin", vin_n)

    assert parser.process_input_p2wsh(vin) == expected_result
    assert parser.unmatched_ecdsa_data == expected_dict


@pytest.mark.parametrize("txid, vin_n, expected_result, expected_dict", [
    ("37777defed8717c581b4c0509329550e344bdc14ac38f71fc050096887e535c8", 0, True,
        {
            "5f4237bd7dae576b34abc8a9c6fa4f0e4787c04234ca963e9e96c8f9b67b56d1":
            [
                {
                    "ID": "37777defed8717c581b4c0509329550e344bdc14ac38f71fc050096887e535c8",
                    "vin/vout": "vin 0",
                    "signature": "134896c42cd95680b048845847c8054756861ffab7d4abab72f6508d67d1ec0c590287ec2161dd7884983286e1cd56ce65c08a24ee0476ede92678a93b1b180c"
                }
            ]
        }
    ),
    ("ad511d71762f4123df227e2e048672c4df8cc2ac056ee37f52ff33085b2a2c47", 0, False, {})
                                                         ])
def test_process_input_p2tr_keypath(txid: str, vin_n: int, expected_result: bool, expected_dict: dict):
    parser.schnorr_data = {}
    transaction = parser.rpc.getrawtransaction(txid, True)
    vin = transaction["vin"][vin_n]
    set_state(parser, txid, "vin", vin_n)

    assert parser.process_input_p2tr(vin) == expected_result
    assert parser.schnorr_data == expected_dict


@pytest.mark.parametrize("txid, vin_n, expected_result, expected_dict", [
    ("37777defed8717c581b4c0509329550e344bdc14ac38f71fc050096887e535c8", 1, True,
        {
            "d9dfdf0fe3c83e9870095d67fff59a8056dad28c6dfb944bb71cf64b90ace9a7":
            [
                {
                    "ID": "37777defed8717c581b4c0509329550e344bdc14ac38f71fc050096887e535c8",
                    "vin/vout": "vin 1",
                    "signature": "NaN"
                }
            ],
            "f5b059b9a72298ccbefff59d9b943f7e0fc91d8a3b944a95e7b6390cc99eb5f4":
            [
                {
                    "ID": "37777defed8717c581b4c0509329550e344bdc14ac38f71fc050096887e535c8",
                    "vin/vout": "vin 1",
                    "signature": "7b5d614a4610bf9196775791fcc589597ca066dcd10048e004cd4c7341bb4bb90cee4705192f3f7db524e8067a5222c7f09baf29ef6b805b8327ecd1e5ab83ca"
                }
            ]
        }
    ),
    ("ad511d71762f4123df227e2e048672c4df8cc2ac056ee37f52ff33085b2a2c47", 0, False, {})
                                                                        ])
def test_process_input_p2tr_scriptpath(txid: str, vin_n: int, expected_result: bool, expected_dict: dict):
    parser.schnorr_data = {}
    transaction = parser.rpc.getrawtransaction(txid, True)
    vin = transaction["vin"][vin_n]
    set_state(parser, txid, "vin", vin_n)

    assert parser.process_input_p2tr(vin) == expected_result
    assert parser.schnorr_data == expected_dict


@pytest.mark.parametrize("txid, vout_n, expected_result, expected_dict", [
    ("e700b7b330e4b56c5883d760f9cbe4fa47e0f62b350e108f1767bc07a4bbc07b", 0, True,
        {
            "5f4237bd7dae576b34abc8a9c6fa4f0e4787c04234ca963e9e96c8f9b67b56d1":
            [
                {
                    "ID": "e700b7b330e4b56c5883d760f9cbe4fa47e0f62b350e108f1767bc07a4bbc07b",
                    "vin/vout": "vout 0",
                    "signature": "NaN"
                }

            ]
        }
    ),
    ("ad511d71762f4123df227e2e048672c4df8cc2ac056ee37f52ff33085b2a2c47", 0, False, {})
                                                         ])
def test_process_output_p2tr(txid: str, vout_n: int, expected_result: bool, expected_dict: dict):
    parser.schnorr_data = {}
    transaction = parser.rpc.getrawtransaction(txid, True)
    vout = transaction["vout"][vout_n]
    set_state(parser, txid, "vout", vout_n)

    assert parser.process_output_p2tr(vout) == expected_result
    assert parser.schnorr_data == expected_dict


@pytest.mark.parametrize("script, inputs, expected_stack", [
    ("5221036c3735b2bf370501c3b872498de54b39ab5afa83d8ce7f6aec43f63a812265b421032b03a42faf387dd5c604435cd48d26b8827fa28a5d4d0f9a18b5cefe443bb4102102ebbd4ecea67dd980fc4854cc13b1f10cefafdafe8b1eb8e5ce73939b59a0477c53ae",
        ["3045022100e40fbdec298b1fd267e43561e5d43822f0156c47772df2c1e955efe0f1f0a307022018946e8b11b7e1fb02f5c8ac6832991655dc44229a018aa19b9fc9a3daa66bf601",
         "304402203137f3f5b00460854577cc8cc233030896e4bf464d06a4ec8b6ae768637e182602204a215cbe3ef950452964f248d84951e7646283c6cdbefd6dbd90613ecd2524e501"],
        ["3045022100e40fbdec298b1fd267e43561e5d43822f0156c47772df2c1e955efe0f1f0a307022018946e8b11b7e1fb02f5c8ac6832991655dc44229a018aa19b9fc9a3daa66bf601",
         "304402203137f3f5b00460854577cc8cc233030896e4bf464d06a4ec8b6ae768637e182602204a215cbe3ef950452964f248d84951e7646283c6cdbefd6dbd90613ecd2524e501",
         "OP_2",
         "036c3735b2bf370501c3b872498de54b39ab5afa83d8ce7f6aec43f63a812265b4",
         "032b03a42faf387dd5c604435cd48d26b8827fa28a5d4d0f9a18b5cefe443bb410",
         "02ebbd4ecea67dd980fc4854cc13b1f10cefafdafe8b1eb8e5ce73939b59a0477c",
         "OP_3",
         "OP_CHECKMULTISIG"]),
    ("20f5b059b9a72298ccbefff59d9b943f7e0fc91d8a3b944a95e7b6390cc99eb5f4ac",
        ["7b5d614a4610bf9196775791fcc589597ca066dcd10048e004cd4c7341bb4bb90cee4705192f3f7db524e8067a5222c7f09baf29ef6b805b8327ecd1e5ab83ca"],
        ["7b5d614a4610bf9196775791fcc589597ca066dcd10048e004cd4c7341bb4bb90cee4705192f3f7db524e8067a5222c7f09baf29ef6b805b8327ecd1e5ab83ca",
         "f5b059b9a72298ccbefff59d9b943f7e0fc91d8a3b944a95e7b6390cc99eb5f4",
         "OP_CHECKSIG"]),
    ("21039c7a814e68ca713e41e70fb63b1db752be1290501925349d597517e8d21b531aad2103fcf27a3caa82bc0eeba16856c12b42158331f5d11aaef0ec6b0f9a6ef1921d5dac73640380ca00b268",
        ["304402205fcdf37304778276f380b60429049f9ae32543f1719bfba02dd46541e501b0ac022024afdbf368f0772510f9a8a6689546e5456c91556eab36960ce3f12a914b541401",
         "30440220598dea760ffe62f0dbed37cb0a270d14aa97ff5e2c5f67a6c2df0daba540a93202203ca9ef1c97ba9f7c449b51abcd573828e3726ae69038c90b658c0f5b0967a92201"],
        ["304402205fcdf37304778276f380b60429049f9ae32543f1719bfba02dd46541e501b0ac022024afdbf368f0772510f9a8a6689546e5456c91556eab36960ce3f12a914b541401",
         "30440220598dea760ffe62f0dbed37cb0a270d14aa97ff5e2c5f67a6c2df0daba540a93202203ca9ef1c97ba9f7c449b51abcd573828e3726ae69038c90b658c0f5b0967a92201",
         "039c7a814e68ca713e41e70fb63b1db752be1290501925349d597517e8d21b531a",
         "OP_CHECKSIGVERIFY",
         "03fcf27a3caa82bc0eeba16856c12b42158331f5d11aaef0ec6b0f9a6ef1921d5d",
         "OP_CHECKSIG",
         "OP_IFDUP",
         "OP_NOTIF",
         "80ca00",
         "OP_CHECKSEQUENCEVERIFY",
         "OP_ENDIF"]),
    ("632103462a938cb554f8d5e717273f59e6c3d20a5c64b1f1228645e24794673437366c67020801b275210311fa1e2edfd0c1d48f7b1a304af8ace5b40b002b218d3c12419747c8bdf0da5568ac",
        ["3045022100962c406eb33e33201a872156660bfa55507bbda650ec7655b8b8229e7d33c81e02202b83321d4f17d65f8118078d9a2debe0dd3a7026e61319c3a3635aa07dce07a001"],
        ["3045022100962c406eb33e33201a872156660bfa55507bbda650ec7655b8b8229e7d33c81e02202b83321d4f17d65f8118078d9a2debe0dd3a7026e61319c3a3635aa07dce07a001",
         "OP_IF",
         "03462a938cb554f8d5e717273f59e6c3d20a5c64b1f1228645e24794673437366c",
         "OP_ELSE",
         "0801",
         "OP_CHECKSEQUENCEVERIFY",
         "OP_DROP",
         "0311fa1e2edfd0c1d48f7b1a304af8ace5b40b002b218d3c12419747c8bdf0da55",
         "OP_ENDIF",
         "OP_CHECKSIG"]),
    ("foo bar",
     ["foo", "bar", "42"],
     []),
    ("0047304402204273b0f1a044f26f4654192dc13400f0d90b6950b49b17d66545f03a2c2c243802200687c723a832c275a8425077ed8c0480873f67a02912d619375e061c9905136801483045022100e62bbb39974c77628cd46fd3f5e6f735b7b0b9e92a5ab8a6468008292f8f88be022039060ef2d7459ebad458e9cd5e51115f38e0bd9ed49e7079fb7be327a734deb7014c6952210313efa7c496f2340a7b7d76653d4cf69761b608e2ff96503e64e1883713324cac2103c19c2ca7e27fad1516831248668eb5bcd58807c2bafce6c96263630eec4b99f7210254714b57ab31707d76f07ef1fc43619f70e6cb680d7eaab19cc331d1b5d9e62753ae", [],
     ["OP_0",
      "304402204273b0f1a044f26f4654192dc13400f0d90b6950b49b17d66545f03a2c2c243802200687c723a832c275a8425077ed8c0480873f67a02912d619375e061c9905136801",
      "3045022100e62bbb39974c77628cd46fd3f5e6f735b7b0b9e92a5ab8a6468008292f8f88be022039060ef2d7459ebad458e9cd5e51115f38e0bd9ed49e7079fb7be327a734deb701",
      "52210313efa7c496f2340a7b7d76653d4cf69761b608e2ff96503e64e1883713324cac2103c19c2ca7e27fad1516831248668eb5bcd58807c2bafce6c96263630eec4b99f7210254714b57ab31707d76f07ef1fc43619f70e6cb680d7eaab19cc331d1b5d9e62753ae"
      ])
                                                    ])
def test_load_stack(script: str, inputs: list, expected_stack: list):
    expected_stack.reverse()
    assert parser.load_stack(script, inputs) == expected_stack


@pytest.mark.parametrize("signature, expected_result",
        [("30440220738cbcb0aea8c1744888aea81e1079c39366691147367c71ef545afddb02dd460220628d9aa550175bde3a959d608036f1a856986a9ccbc44971e7c7776728095d5a01", True), # real ECDSA signature
         ("30450221008ca7c251b8d11eb86331ecad6a97fe0484c38c256457e4191a36977e06394a1b02201d93199fb9a2e3bc5366bf73254b785b5f068d36c098b45183dee361d25e4ec401", True),
         ("3043021f0bd31c384cba64fc6a92606e511945fe0da6171850079bfe8355252660d72e02207466baaee5546c6f66b070565b138b4d85b4acc753e5b5d9211b0ebf4eddaa2d01", True),
         ("304202205bad496a16e1838ea1e6ed17ecc92254a3c3f7d0e235fe2cc48f7142455a4634021e2727a2c11180e55be460a33c2ea1d00bcaab31736b1287842dc5f434dd6d01", True),
         ("30450221008ca7c251b8d11eb86331ecad6a97fe0484c38c256457e4191a36977e06394a1b02201d93199fb9a2e3bc5366bf73254b785b5f068d36c098b45183dee361d25e4ec4[ALL]", False),
         ("134896c42cd95680b048845847c8054756861ffab7d4abab72f6508d67d1ec0c590287ec2161dd7884983286e1cd56ce65c08a24ee0476ede92678a93b1b180c", False), # Schnorr's signature
         ("0313efa7c496f2340a7b7d76653d4cf69761b608e2ff96503e64e1883713324cac", False), # ECDSA public key
         ("5f4237bd7dae576b34abc8a9c6fa4f0e4787c04234ca963e9e96c8f9b67b56d1", False) # Schnorr's key
                         ])
def test_correct_ecdsa_signature(signature: str, expected_result: bool):
    assert parser.correct_ecdsa_signature(signature) == expected_result


@pytest.mark.parametrize("signature, expected_result",
        [("134896c42cd95680b048845847c8054756861ffab7d4abab72f6508d67d1ec0c590287ec2161dd7884983286e1cd56ce65c08a24ee0476ede92678a93b1b180c", True), # Real Schnorr's signature
         ("d97a5bf08e49c8c667efea45dea868d392ee3e10a6f425846e9231c12402a86b791b6701379a9a66ee8b41f46e81ca4d1c484c304664a64f7ad1e79c0840828201", True),
         ("d97a5bf08e49c8c667efea45dea868d392ee3e10a6f425846e9231c12402a86b791b6701379a9a66ee8b41f46e81ca4d1c484c304664a64f7ad1e79c0840828281", True),
         ("d97a5bf08e49c8c667efea45dea868d392ee3e10a6f425846e9231c12402a86b791b6701379a9a66ee8b41f46e81ca4d1c484c304664a64f7ad1e79c0840828251", False),
         ("d97a5bf08e49c8c667efea45dea868d392ee3e10a6f425846e9231c12402a86b791b6701379a9a66ee8b41f46e81ca4d1c484c304664a64f7ad1e79c0840828205", False),
         ("30450221008ca7c251b8d11eb86331ecad6a97fe0484c38c256457e4191a36977e06394a1b02201d93199fb9a2e3bc5366bf73254b785b5f068d36c098b45183dee361d25e4ec401", False), # ECDSA signature
         ("30450221008ca7c251b8d11eb86331ecad6a97fe0484c38c256457e4191a36977e06394a1b02201d93199fb9a2e3bc5366bf73254b785b5f068d36c098b45183dee361d25e4ec4[ALL]", False),
         ("0313efa7c496f2340a7b7d76653d4cf69761b608e2ff96503e64e1883713324cac", False), # ECDSA public key
         ("5f4237bd7dae576b34abc8a9c6fa4f0e4787c04234ca963e9e96c8f9b67b56d1", False) # Schnorr's key
                         ])
def test_correct_schnorr_signature(signature: str, expected_result: bool):
    assert parser.correct_schnorr_signature(signature) == expected_result


@pytest.mark.parametrize("stack, expected_tuple", [
        (
            ['OP_CHECKMULTISIG', 'OP_3', '02ebbd4ecea67dd980fc4854cc13b1f10cefafdafe8b1eb8e5ce73939b59a0477c', '032b03a42faf387dd5c604435cd48d26b8827fa28a5d4d0f9a18b5cefe443bb410', '036c3735b2bf370501c3b872498de54b39ab5afa83d8ce7f6aec43f63a812265b4', 'OP_2', "3044022073e7d12cb72f25ef79d4dd2fd5973d0362f882dc996e441634f5837627afe78b02203849685e1fb6749833202f934339262e678d96654f93c294d80006d02ac2c96601", "304402203c7a05b7cc49daa7c05fcf213d196d2530f4ce7e07fe9551084081e0f108870502207fcb1574cf1f2386ed68dd275e56b9290ccb25b9cc48fe1df151049d4ca638ea01"],
            (
                ['036c3735b2bf370501c3b872498de54b39ab5afa83d8ce7f6aec43f63a812265b4', '032b03a42faf387dd5c604435cd48d26b8827fa28a5d4d0f9a18b5cefe443bb410', '02ebbd4ecea67dd980fc4854cc13b1f10cefafdafe8b1eb8e5ce73939b59a0477c'], # ECDSA keys
                ["304402203c7a05b7cc49daa7c05fcf213d196d2530f4ce7e07fe9551084081e0f108870502207fcb1574cf1f2386ed68dd275e56b9290ccb25b9cc48fe1df151049d4ca638ea01", "3044022073e7d12cb72f25ef79d4dd2fd5973d0362f882dc996e441634f5837627afe78b02203849685e1fb6749833202f934339262e678d96654f93c294d80006d02ac2c96601"], # ECDSA signatures
                [], # Schnorr keys
                [] # Schnorr signatures
            )
        ),
        (
            ['OP_CHECKSIG', 'f5b059b9a72298ccbefff59d9b943f7e0fc91d8a3b944a95e7b6390cc99eb5f4', '7b5d614a4610bf9196775791fcc589597ca066dcd10048e004cd4c7341bb4bb90cee4705192f3f7db524e8067a5222c7f09baf29ef6b805b8327ecd1e5ab83ca'],
            (
                [], # ECDSA keys
                [], # ECDSA signatures
                ['f5b059b9a72298ccbefff59d9b943f7e0fc91d8a3b944a95e7b6390cc99eb5f4'], # Schnorr keys
                ['7b5d614a4610bf9196775791fcc589597ca066dcd10048e004cd4c7341bb4bb90cee4705192f3f7db524e8067a5222c7f09baf29ef6b805b8327ecd1e5ab83ca'] # Schnorr signatures
            )
        ),
        (
            ['foo', 'bar', '42'],
            (
                [], # ECDSA keys
                [], # ECDSA signatures
                [], # Schnorr keys
                [] # Schnorr signatures
            )
        )
    ])
def test_length_based_parse(stack: list, expected_tuple: tuple):
    assert parser.length_based_parse(stack) == expected_tuple

@pytest.mark.parametrize("txid, vin_n, script, inputs, expected_result, expected_tuple", [
    ( # P2SH
        "00e07f279dd05b9b68c40f21b43c57847e75c35cd3bbc2d80921eb037ef0c9a8",
        0,
        "5221036c3735b2bf370501c3b872498de54b39ab5afa83d8ce7f6aec43f63a812265b421032b03a42faf387dd5c604435cd48d26b8827fa28a5d4d0f9a18b5cefe443bb4102102ebbd4ecea67dd980fc4854cc13b1f10cefafdafe8b1eb8e5ce73939b59a0477c53ae",
        ["3045022100e40fbdec298b1fd267e43561e5d43822f0156c47772df2c1e955efe0f1f0a307022018946e8b11b7e1fb02f5c8ac6832991655dc44229a018aa19b9fc9a3daa66bf601", "304402203137f3f5b00460854577cc8cc233030896e4bf464d06a4ec8b6ae768637e182602204a215cbe3ef950452964f248d84951e7646283c6cdbefd6dbd90613ecd2524e501"],
        True,
        (
            {}, # ecdsa_data
            {   # ecdsa_unmathced_data
                "036c3735b2bf370501c3b872498de54b39ab5afa83d8ce7f6aec43f63a812265b4": [
                    {
                    "ID": "00e07f279dd05b9b68c40f21b43c57847e75c35cd3bbc2d80921eb037ef0c9a8",
                    "vin/vout": "vin 0",
                    "signatures": [
                        "3045022100e40fbdec298b1fd267e43561e5d43822f0156c47772df2c1e955efe0f1f0a307022018946e8b11b7e1fb02f5c8ac6832991655dc44229a018aa19b9fc9a3daa66bf601",
                        "304402203137f3f5b00460854577cc8cc233030896e4bf464d06a4ec8b6ae768637e182602204a215cbe3ef950452964f248d84951e7646283c6cdbefd6dbd90613ecd2524e501"
                                ]
                    }],
                "032b03a42faf387dd5c604435cd48d26b8827fa28a5d4d0f9a18b5cefe443bb410": [
                    {
                    "ID": "00e07f279dd05b9b68c40f21b43c57847e75c35cd3bbc2d80921eb037ef0c9a8",
                    "vin/vout": "vin 0",
                    "signatures": [
                        "3045022100e40fbdec298b1fd267e43561e5d43822f0156c47772df2c1e955efe0f1f0a307022018946e8b11b7e1fb02f5c8ac6832991655dc44229a018aa19b9fc9a3daa66bf601",
                        "304402203137f3f5b00460854577cc8cc233030896e4bf464d06a4ec8b6ae768637e182602204a215cbe3ef950452964f248d84951e7646283c6cdbefd6dbd90613ecd2524e501"
                                ]
                    }],
                "02ebbd4ecea67dd980fc4854cc13b1f10cefafdafe8b1eb8e5ce73939b59a0477c": [
                    {
                    "ID": "00e07f279dd05b9b68c40f21b43c57847e75c35cd3bbc2d80921eb037ef0c9a8",
                    "vin/vout": "vin 0",
                    "signatures": [
                        "3045022100e40fbdec298b1fd267e43561e5d43822f0156c47772df2c1e955efe0f1f0a307022018946e8b11b7e1fb02f5c8ac6832991655dc44229a018aa19b9fc9a3daa66bf601",
                        "304402203137f3f5b00460854577cc8cc233030896e4bf464d06a4ec8b6ae768637e182602204a215cbe3ef950452964f248d84951e7646283c6cdbefd6dbd90613ecd2524e501"
                                ]
                    }]
            },
            {}, # schnorr_data
            {}  # schnorr_unmatched_data
        )
    ),
    ( # P2WSH
        "208a95aff0c4243fdc7c610b700e1eb6a19bb786f3d96d79ecd410183f067687",
        0,
        "21039c7a814e68ca713e41e70fb63b1db752be1290501925349d597517e8d21b531aad2103fcf27a3caa82bc0eeba16856c12b42158331f5d11aaef0ec6b0f9a6ef1921d5dac73640380ca00b268",
        ["304402205fcdf37304778276f380b60429049f9ae32543f1719bfba02dd46541e501b0ac022024afdbf368f0772510f9a8a6689546e5456c91556eab36960ce3f12a914b541401",
         "30440220598dea760ffe62f0dbed37cb0a270d14aa97ff5e2c5f67a6c2df0daba540a93202203ca9ef1c97ba9f7c449b51abcd573828e3726ae69038c90b658c0f5b0967a92201"],
        True,
        (
            {}, # ecdsa_data
            {   # ecdsa_unmathced_data
                "039c7a814e68ca713e41e70fb63b1db752be1290501925349d597517e8d21b531a": [
                    {
                    "ID": "208a95aff0c4243fdc7c610b700e1eb6a19bb786f3d96d79ecd410183f067687",
                    "vin/vout": "vin 0",
                    "signatures" : [
                        "304402205fcdf37304778276f380b60429049f9ae32543f1719bfba02dd46541e501b0ac022024afdbf368f0772510f9a8a6689546e5456c91556eab36960ce3f12a914b541401",
                        "30440220598dea760ffe62f0dbed37cb0a270d14aa97ff5e2c5f67a6c2df0daba540a93202203ca9ef1c97ba9f7c449b51abcd573828e3726ae69038c90b658c0f5b0967a92201" 
                                    ]
                    }],
                "03fcf27a3caa82bc0eeba16856c12b42158331f5d11aaef0ec6b0f9a6ef1921d5d": [
                    {
                    "ID": "208a95aff0c4243fdc7c610b700e1eb6a19bb786f3d96d79ecd410183f067687",
                    "vin/vout": "vin 0",
                    "signatures" : [
                        "304402205fcdf37304778276f380b60429049f9ae32543f1719bfba02dd46541e501b0ac022024afdbf368f0772510f9a8a6689546e5456c91556eab36960ce3f12a914b541401",
                        "30440220598dea760ffe62f0dbed37cb0a270d14aa97ff5e2c5f67a6c2df0daba540a93202203ca9ef1c97ba9f7c449b51abcd573828e3726ae69038c90b658c0f5b0967a92201" 
                                    ]
                    }]
            },
            {}, # schnorr_data
            {}  # schnorr_unmatched_data
        )
    ),
    ( # P2TR
        "37777defed8717c581b4c0509329550e344bdc14ac38f71fc050096887e535c8",
        1,
        "20f5b059b9a72298ccbefff59d9b943f7e0fc91d8a3b944a95e7b6390cc99eb5f4ac",
        ["7b5d614a4610bf9196775791fcc589597ca066dcd10048e004cd4c7341bb4bb90cee4705192f3f7db524e8067a5222c7f09baf29ef6b805b8327ecd1e5ab83ca"],
        True,
        (
            {}, # ecdsa_data
            {}, # unmatched_ecdsa_data
            {   # schnorr_data
                "f5b059b9a72298ccbefff59d9b943f7e0fc91d8a3b944a95e7b6390cc99eb5f4": [
                {
                    "ID": "37777defed8717c581b4c0509329550e344bdc14ac38f71fc050096887e535c8",
                    "vin/vout": "vin 1",
                    "signature": "7b5d614a4610bf9196775791fcc589597ca066dcd10048e004cd4c7341bb4bb90cee4705192f3f7db524e8067a5222c7f09baf29ef6b805b8327ecd1e5ab83ca"
                }]
            },
            {}  # unmathced_schnorr_data
        )
    ),
    ( # P2PKH
        "ce6fb9e782df2f5dbd4190069c3ec31ccf1ea2429b890da3c2b12ef37037a5be",
        0,
        "foo bar",
        [],
        False,
        (
            {}, # ecdsa_data
            {}, # unmatched_ecdsa_data
            {}, # schnorr_data
            {}  # unmatched_schnorr_data 
        )
    )
                             ])
def test_parse_serialized_script(txid: str, vin_n: int, script: str, inputs: list, expected_result: bool, expected_tuple: tuple):
    parser.ecdsa_data = {}
    parser.unmatched_ecdsa_data = {}
    parser.schnorr_data = {}
    parser.unmatched_schnorr_data = {}
    set_state(parser, txid, "vin", vin_n)

    assert parser.parse_serialized_script(script, inputs) == expected_result
    assert (parser.ecdsa_data, parser.unmatched_ecdsa_data, parser.schnorr_data, parser.unmatched_schnorr_data) == expected_tuple


@pytest.mark.parametrize("fake_tx, expected_failed_inputs, expected_failed_outputs", [
        [{
          "txid": "37777defed8717c581b4c0509329550e344bdc14ac38f71fc050096887e535c8",
          "vin": [
            {
              "txid": "e700b7b330e4b56c5883d760f9cbe4fa47e0f62b350e108f1767bc07a4bbc07b",
              "vout": 0,
              "scriptSig": {
                "asm": "",
                "hex": ""
              },
              "txinwitness": [],
              "sequence": 4294967294
            },
            {
              "txid": "e700b7b330e4b56c5883d760f9cbe4fa47e0f62b350e108f1767bc07a4bbc07b",
              "vout": 1,
              "scriptSig": {
                "asm": "",
                "hex": ""
              },
              "txinwitness": [],
              "sequence": 4294967294
            }
          ],
          "vout": [
            {
              "value": 0.00965300,
              "n": 0,
              "scriptPubKey": {
                "asm": "",
                "hex": "",
                "address": "",
                "type": "witness_v1_taproot"
              }
            }
          ],
          "time": 1636868413
        },
        ["37777defed8717c581b4c0509329550e344bdc14ac38f71fc050096887e535c8:0", # failed_inputs
         "37777defed8717c581b4c0509329550e344bdc14ac38f71fc050096887e535c8:1"],
        ["37777defed8717c581b4c0509329550e344bdc14ac38f71fc050096887e535c8:0"]] # failed_outputs
    ])
def test_failed_dict(fake_tx: dict, expected_failed_inputs: list, expected_failed_outputs: list):
    parser.state["txid"] = fake_tx["txid"]
    parser.process_inputs(fake_tx)
    parser.process_outputs(fake_tx)

    assert parser.failed_inputs_list == expected_failed_inputs
    assert parser.failed_outputs_list == expected_failed_outputs


@pytest.mark.parametrize("txid, expected_types", [
        [
            "1e3c85f59802e3907a254766fd466e308888bf3fcaa0723a9599b8ff41028503",
            {"2009.04":
                {
                'nonstandard': 0,
                'pubkey': 1,
                'pubkeyhash': 0,
                'scripthash': 0,
                'multisig': 0,
                'nulldata': 0,
                'witness_v0_scripthash': 0,
                'witness_v0_keyhash': 0,
                'witness_v1_taproot': 0,
                'witness_unknown': 0
                }
            }
        ],
        [
            "c0d210f7b6db4047f5852f98003ac46665ed17f6987f0b21af56998ed7a52c9a",
            {"2021.09":
                {
                'nonstandard': 0,
                'pubkey': 0,
                'pubkeyhash': 1,
                'scripthash': 2,
                'multisig': 0,
                'nulldata': 0,
                'witness_v0_scripthash': 1,
                'witness_v0_keyhash': 0,
                'witness_v1_taproot': 0,
                'witness_unknown': 0
                }
            }
        ],
        [
            "33e794d097969002ee05d336686fc03c9e15a597c1b9827669460fac98799036",
            {"2021.11":
                {
                'nonstandard': 0,
                'pubkey': 0,
                'pubkeyhash': 0,
                'scripthash': 0,
                'multisig': 0,
                'nulldata': 1,
                'witness_v0_scripthash': 0,
                'witness_v0_keyhash': 0,
                'witness_v1_taproot': 1,
                'witness_unknown': 0
                }
            }
        ],
        [
            "6dfb6970fff536ae05a7e7bf1c828d5315350501bd392a9304e61c138bca3db7",
            {"2021.11":
                {
                'nonstandard': 0,
                'pubkey': 0,
                'pubkeyhash': 0,
                'scripthash': 0,
                'multisig': 0,
                'nulldata': 0,
                'witness_v0_scripthash': 0,
                'witness_v0_keyhash': 1,
                'witness_v1_taproot': 0,
                'witness_unknown': 1
                }
            }
        ],
        [
            "c16fab844429f1f741d4d1c9c021a2c79c9496186bb65d0fd6422b8798483842",
            {"2015.02":
                {
                'nonstandard': 0,
                'pubkey': 0,
                'pubkeyhash': 1,
                'scripthash': 0,
                'multisig': 1,
                'nulldata': 0,
                'witness_v0_scripthash': 0,
                'witness_v0_keyhash': 0,
                'witness_v1_taproot': 0,
                'witness_unknown': 0
                }
            }
        ],
        [
            "03acfae47d1e0b7674f1193237099d1553d3d8a93ecc85c18c4bec37544fe386",
            {"2011.10":
                {
                'nonstandard': 1,
                'pubkey': 0,
                'pubkeyhash': 1,
                'scripthash': 0,
                'multisig': 0,
                'nulldata': 0,
                'witness_v0_scripthash': 0,
                'witness_v0_keyhash': 0,
                'witness_v1_taproot': 0,
                'witness_unknown': 0
                }
            }
        ]
    ])
def test_tx_types_process_outputs(txid: str, expected_types: dict):
    parser.types = {}
    transaction = parser.rpc.getrawtransaction(txid, True)
    parser.process_outputs(transaction)
    assert parser.types == expected_types


def test_not_verbose():
    block_n = parser.rpc.getblockcount() // 4
    assert block_n > 0
    parser.set_verbosity(True)
    parser.process_block(block_n)


    expected_ecdsa_data = {block_n: set()} if parser.ecdsa_data != {} else {}
    expected_unmatched_ecdsa_data = {block_n: set()} if parser.unmatched_ecdsa_data != {} else {}
    expected_schnorr_data = {block_n: set()} if parser.schnorr_data != {} else {}
    expected_unmatched_schnorr_data = {block_n: set()} if parser.unmatched_schnorr_data != {} else {}

    for key in parser.ecdsa_data.keys():
        expected_ecdsa_data[block_n].add(key)
    for key in parser.unmatched_ecdsa_data.keys():
        expected_unmatched_ecdsa_data[block_n].add(key)
    for key in parser.schnorr_data.keys():
        expected_schnorr_data[block_n].add(key)
    for key in parser.unmatched_schnorr_data.keys():
        expected_unmatched_schnorr_data[block_n].add(key)


    parser.set_verbosity(False)
    parser.process_block(block_n)

    assert parser.ecdsa_data == expected_ecdsa_data
    assert parser.unmatched_ecdsa_data == expected_unmatched_ecdsa_data
    assert parser.schnorr_data == expected_schnorr_data
    assert parser.unmatched_schnorr_data == expected_unmatched_schnorr_data

    parser.set_verbosity(True)

def chdir_to_tmp() -> None:
    os.chdir("/tmp")
    if os.path.isdir("pytest_test_bitcoin_public_key_parser"):
        shutil.rmtree("pytest_test_bitcoin_public_key_parser")

    os.mkdir("pytest_test_bitcoin_public_key_parser")
    os.chdir("pytest_test_bitcoin_public_key_parser")
    os.mkdir("gathered-data")
    os.mkdir("logs")
    os.mkdir("state")

def compare_dicts_to_disk(verbosity: bool, prev_dicts: list, n: int, pid: int = 0) -> bool:
    for data_dict, dict_name in prev_dicts:
        file_name = f"gathered-data/{dict_name}_{str(n)}_{str(pid)}.json"

        try:
            with open(file_name, 'r') as f:
                disk_dict = json.load(f)
        except Exception as e:
            print(f"Couldn't open a file or a JSON-parsing error ({file_name}).", file=sys.stderr)
            print(e, file=sys.stderr)
            return False

        if not verbosity:
            for block, key_list in disk_dict.items():
                disk_dict[block] = set(key_list)

        for block, data_keys in data_dict.items():
            assert type(disk_dict[str(block)]) == type(data_keys)
            if disk_dict[str(block)] != data_keys:
                print(f"Dictionaries are not equal!\nSymmetric difference: {disk_dict[str(block)].symmetric_difference(data_keys)}", file=sys.stderr)
                return False

    return True

def compare_lists_to_disk(prev_lists: list, n: int, pid: int = 0) -> bool:
    for data_list, list_name in prev_lists:
        file_name = f"gathered-data/{list_name}_{str(n)}_{pid}.json"
        disk_list = []

        try:
            with open(file_name, 'r') as f:
                for line in f:
                    disk_list.append(line.rstrip())
        except Exception as e:
            print(f"Couldn't open a file or a reading error ({file_name}).", file=sys.stderr)
            print(e, file=sys.stderr)
            return False

        if disk_list != data_list:
            print(f"Lists are not equal!\nDisk_list: {disk_list}.\nData_list: {data_list}", file=sys.stderr)
            return False

    return True


@pytest.mark.parametrize("verbosity, n", [(False, 20), (True, 10)])
def test_flush_to_disk(verbosity: bool, n: int):
    parser.set_verbosity(verbosity)

    block_n = parser.rpc.getblockcount() - n
    assert block_n > 0

    for i in range(block_n, block_n + n):
        parser.process_block(i)

        temp_dicts = [(copy.deepcopy(data_dict), dict_name) for data_dict, dict_name in parser.DICTS if data_dict != {}]
        temp_lists = [(copy.deepcopy(data_list), list_name) for data_list, list_name in parser.LISTS if data_list != []]
        chdir_to_tmp()
        parser.flush_if_needed(i, True)

        assert compare_dicts_to_disk(verbosity, temp_dicts, i)
        assert compare_lists_to_disk(temp_lists, i)
