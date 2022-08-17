#!/bin/python3
import sys
sys.path.append("/home/xyakimo1/crocs/")
from parse import Parser
import pytest

parser = Parser()

@pytest.mark.parametrize("suspected_key, expected_result",
                         [("03bc7a18a65c8468994f75a87e7407a82ffabbc44656417491b2649fb5ee5bfdac", True),             # real ECDSA public key
                          ("02018eb32174d67f3d247101d2ee3f9558dff7a5ea035ce9440f2dbb4b455ec5e9", True),
                          ("3045022100fe7d601f17d3334b669ce55d068b3420434766846e14509fc1ddb539bf3a71f70220556ae2fd9919420a9505a07e7243a3259375955156f1875ba84b58abdc7b1f0101", False),                                                                                # ECDSA signature
                          ("b2739443fa914fdbcedbcb1672c991dd6359afc1", False),                                      # OP_HASH160 hash
                          ("159914d19974d9d2c8e658ff822f09e5f0e8a439ca5b4490d39df13f71843350", False),              # Schnorr's key
                          ("5e231b860b6fe188e2b7ec4a0c9f10e907f1edba19a9a1877da75efafc2527279a634eda6fedc5ff7ec22271f1e76cfbca69b335f544754f5d35f7b57524b77c", False),                                                                                                 # Schnorr's signature
                          ("ad5fb1f095dac7c7c3adff095dff973aed868f88fff8fa1ca3f248a6a6864acf", False)                # TXID
                         ])
def test_correct_ecdsa_key(suspected_key: str, expected_result: bool):
    assert parser.correct_ecdsa_key(suspected_key) == expected_result
