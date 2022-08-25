#!/bin/python3
import sys
sys.path.append("/home/xyakimo1/crocs/")
from parse import Parser
import pytest

parser = Parser()

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
    assert parser.ecdsa == expected_ecdsa
    assert parser.schnorr == expected_schnorr
    assert parser.keys == expected_keys

#def test_add_key_to_data_dict(transaction, suspected_key, signature, data_dict, expected_dict):
    # TODO

#def test_add_key_to_unmatched_data_dict(transaction, suspected_key, sigs, data_dict, expected_dict):
    # TODO

@pytest.mark.parametrize("txid, vin_n, expected_signature", [
    ("ad511d71762f4123df227e2e048672c4df8cc2ac056ee37f52ff33085b2a2c47", 0, "304502200f55222e27f6b6aff33e314339e569b54e80df76f628daa2c76ef56558bc650c022100c989ec3a0fad6b1aff1087378c219091de70bac9d7bf3ebfa7718a6c4fa7aeb701"), # P2PK
    ("ce6fb9e782df2f5dbd4190069c3ec31ccf1ea2429b890da3c2b12ef37037a5be", 0, "304402207ebfd1151a2bb59336bb66b58164a8c17ea99b4a3c70f30056048d94d4532c11022070d4b82892bb2d809e6ec34adefd6669bbfdd50751e2ade7ab494a62a9e8d04401"), # P2PKH
    ("00e07f279dd05b9b68c40f21b43c57847e75c35cd3bbc2d80921eb037ef0c9a8", 1, "NaN") # P2SH
                                                           ])
def test_extract_signature_p2pk_p2pkh(txid: str, vin_n: int, expected_signature: str):
    vin = parser.rpc.getrawtransaction(txid, True)["vin"][vin_n]
    assert parser.extract_signature_p2pk_p2pkh(vin) == expected_signature


@pytest.mark.parametrize("txid, vin_n, i, expected_signature", [
    ("00e07f279dd05b9b68c40f21b43c57847e75c35cd3bbc2d80921eb037ef0c9a8", 0, 0, "3045022100e40fbdec298b1fd267e43561e5d43822f0156c47772df2c1e955efe0f1f0a307022018946e8b11b7e1fb02f5c8ac6832991655dc44229a018aa19b9fc9a3daa66bf601"), # P2SH
    ("00e07f279dd05b9b68c40f21b43c57847e75c35cd3bbc2d80921eb037ef0c9a8", 0, 1, "304402203137f3f5b00460854577cc8cc233030896e4bf464d06a4ec8b6ae768637e182602204a215cbe3ef950452964f248d84951e7646283c6cdbefd6dbd90613ecd2524e501"),
    ("00e07f279dd05b9b68c40f21b43c57847e75c35cd3bbc2d80921eb037ef0c9a8", 1, 2, "NaN")
                                                            ])
def test_extract_signature_p2sh(txid: str, vin_n: int, i: int, expected_signature: str):
    vin = parser.rpc.getrawtransaction(txid, True)["vin"][vin_n]
    assert parser.extract_signature_p2sh(vin, i) == expected_signature


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
    ("c0d210f7b6db4047f5852f98003ac46665ed17f6987f0b21af56998ed7a52c9a", 2, 0, "3045022100bed582633b971c9786720c325472b0808727b72280de798a995939f91c13cb3c0220216fb5dfdfb2914e71f54f1a1c2f54f65fb22e083d1c843b8d9487120f238d0a01"), # P2WSH
    ("c0d210f7b6db4047f5852f98003ac46665ed17f6987f0b21af56998ed7a52c9a", 2, 1, "3045022100a28f052fbdb37dba174652ff30ce128f68f8fbfbe8a7d286d417cd7f79c79ad70220373412b7f0c9a1f85e693addb57c11a5598ef2b380764910fc843702471db35e01"),
    ("c0d210f7b6db4047f5852f98003ac46665ed17f6987f0b21af56998ed7a52c9a", 2, 2, "NaN")
                                                            ])
def test_extract_signature_p2wsh(txid: str, vin_n: int, i: int, expected_signature: str):
    vin = parser.rpc.getrawtransaction(txid, True)["vin"][vin_n]
    assert parser.extract_signature_p2wsh(vin, i) == expected_signature


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
                    "time": 1632990364,
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
    assert parser.process_input_p2pkh(transaction, vin) == expected_result
    assert parser.ecdsa_data == expected_dict


@pytest.mark.parametrize("txid, vin_n, expected_result, expected_dict", [
    ("ad511d71762f4123df227e2e048672c4df8cc2ac056ee37f52ff33085b2a2c47", 0, True,
        {
            "04c7a78b9a39471563ee652a5d9e71f788c2c2923c04341059d8a803f773b60071bf2919cc5f6de23932fddce3da8c6e80f92a38fd63c54ded9860c61f0817f971":
            [
                {
                    "ID": "ad511d71762f4123df227e2e048672c4df8cc2ac056ee37f52ff33085b2a2c47",
                    "time": 1239621855,
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
    assert parser.process_input_p2pk(transaction, vin) == expected_result
    assert parser.ecdsa_data == expected_dict


@pytest.mark.parametrize("txid, vout_n, expected_result, expected_dict", [
    ("1e3c85f59802e3907a254766fd466e308888bf3fcaa0723a9599b8ff41028503", 0, True,
        {
            "04c7a78b9a39471563ee652a5d9e71f788c2c2923c04341059d8a803f773b60071bf2919cc5f6de23932fddce3da8c6e80f92a38fd63c54ded9860c61f0817f971":
            [
                {
                    "ID": "1e3c85f59802e3907a254766fd466e308888bf3fcaa0723a9599b8ff41028503",
                    "time": 1239529193,
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
    assert parser.process_output_p2pk(transaction, vout) == expected_result
    assert parser.ecdsa_data == expected_dict


@pytest.mark.parametrize("txid, vin_n, expected_result, expected_dict", [
    ("00e07f279dd05b9b68c40f21b43c57847e75c35cd3bbc2d80921eb037ef0c9a8", 0, True,
        {
            "036c3735b2bf370501c3b872498de54b39ab5afa83d8ce7f6aec43f63a812265b4":
            [
                {
                    "ID": "00e07f279dd05b9b68c40f21b43c57847e75c35cd3bbc2d80921eb037ef0c9a8",
                    "time": 1459929415,
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
                    "time": 1459929415,
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
                    "time": 1459929415,
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
    assert parser.process_input_p2sh(transaction, vin) == expected_result
    assert parser.unmatched_ecdsa_data == expected_dict
