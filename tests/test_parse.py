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

@pytest.mark.parametrize("vin, expected_signature", [
    ({ # P2PK
      "txid": "1e3c85f59802e3907a254766fd466e308888bf3fcaa0723a9599b8ff41028503",
      "vout": 0,
      "scriptSig": {
        "asm": "304502200f55222e27f6b6aff33e314339e569b54e80df76f628daa2c76ef56558bc650c022100c989ec3a0fad6b1aff1087378c219091de70bac9d7bf3ebfa7718a6c4fa7aeb7[ALL]",
        "hex": "48304502200f55222e27f6b6aff33e314339e569b54e80df76f628daa2c76ef56558bc650c022100c989ec3a0fad6b1aff1087378c219091de70bac9d7bf3ebfa7718a6c4fa7aeb701"
      },
      "sequence": 4294967295
    }, "304502200f55222e27f6b6aff33e314339e569b54e80df76f628daa2c76ef56558bc650c022100c989ec3a0fad6b1aff1087378c219091de70bac9d7bf3ebfa7718a6c4fa7aeb701"),
    ({ # P2PKH
      "txid": "4034c53ceacbfd109c592dec286f4a967725a58bfdb29992c18805e2c8b76078",
      "vout": 0,
      "scriptSig": {
        "asm": "304402207ebfd1151a2bb59336bb66b58164a8c17ea99b4a3c70f30056048d94d4532c11022070d4b82892bb2d809e6ec34adefd6669bbfdd50751e2ade7ab494a62a9e8d044[ALL] 0337108c8c782b2dac8dafbab92a3a76871587c67f93e5ebd3f7c40ca3d4050472",
        "hex": "47304402207ebfd1151a2bb59336bb66b58164a8c17ea99b4a3c70f30056048d94d4532c11022070d4b82892bb2d809e6ec34adefd6669bbfdd50751e2ade7ab494a62a9e8d04401210337108c8c782b2dac8dafbab92a3a76871587c67f93e5ebd3f7c40ca3d4050472"
      },
      "sequence": 4294967293
    }, "304402207ebfd1151a2bb59336bb66b58164a8c17ea99b4a3c70f30056048d94d4532c11022070d4b82892bb2d809e6ec34adefd6669bbfdd50751e2ade7ab494a62a9e8d04401"),
    ({ # P2PKH
      "txid": "5e53ab072fac5245c9b18e3b6a558ebd3ca4df1dcc65404cbfd084b934353697",
      "vout": 47,
      "scriptSig": {
        "asm": "30440220053348c0b792c46b1250acc0b7e7476e2f9e4d489b55c274d80bc34139d6e82302200c1e70036af4c7f68ba26de20d798708bcd9d332c8cd0516467ba2a91ca6ea94[ALL] 02ff00d6dd528ef21acceaa96b3f9c4148f744482452ab5ce3e64defb75a19cf57",
        "hex": "4730440220053348c0b792c46b1250acc0b7e7476e2f9e4d489b55c274d80bc34139d6e82302200c1e70036af4c7f68ba26de20d798708bcd9d332c8cd0516467ba2a91ca6ea94012102ff00d6dd528ef21acceaa96b3f9c4148f744482452ab5ce3e64defb75a19cf57"
      },
      "sequence": 4294967293
    }, "30440220053348c0b792c46b1250acc0b7e7476e2f9e4d489b55c274d80bc34139d6e82302200c1e70036af4c7f68ba26de20d798708bcd9d332c8cd0516467ba2a91ca6ea9401"),
    ({ # P2SH
      "txid": "ef524a24b9323169a8c46c414ca462cd04e6af01d494404d04165086f7d6fc53",
      "vout": 1,
      "scriptSig": {
        "asm": "0 3045022100e40fbdec298b1fd267e43561e5d43822f0156c47772df2c1e955efe0f1f0a307022018946e8b11b7e1fb02f5c8ac6832991655dc44229a018aa19b9fc9a3daa66bf6[ALL] 304402203137f3f5b00460854577cc8cc233030896e4bf464d06a4ec8b6ae768637e182602204a215cbe3ef950452964f248d84951e7646283c6cdbefd6dbd90613ecd2524e5[ALL] 5221036c3735b2bf370501c3b872498de54b39ab5afa83d8ce7f6aec43f63a812265b421032b03a42faf387dd5c604435cd48d26b8827fa28a5d4d0f9a18b5cefe443bb4102102ebbd4ecea67dd980fc4854cc13b1f10cefafdafe8b1eb8e5ce73939b59a0477c53ae",
        "hex": "00483045022100e40fbdec298b1fd267e43561e5d43822f0156c47772df2c1e955efe0f1f0a307022018946e8b11b7e1fb02f5c8ac6832991655dc44229a018aa19b9fc9a3daa66bf60147304402203137f3f5b00460854577cc8cc233030896e4bf464d06a4ec8b6ae768637e182602204a215cbe3ef950452964f248d84951e7646283c6cdbefd6dbd90613ecd2524e5014c695221036c3735b2bf370501c3b872498de54b39ab5afa83d8ce7f6aec43f63a812265b421032b03a42faf387dd5c604435cd48d26b8827fa28a5d4d0f9a18b5cefe443bb4102102ebbd4ecea67dd980fc4854cc13b1f10cefafdafe8b1eb8e5ce73939b59a0477c53ae"
      },
      "sequence": 4294967295
    }, "NaN")
                ])
def test_extract_signature_p2pk_p2pkh(vin, expected_signature):
    assert parser.extract_signature_p2pk_p2pkh(vin) == expected_signature
