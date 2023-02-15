import sys, os, shutil
sys.path.append("/home/xyakimo1/crocs/src") # add here path to the project's source directory
from bitcoin_public_key_parser import BitcoinPublicKeyParser, BitcoinRPC
from parser_manager import BitcoinParserManager
import pytest
import json
from typing import Tuple

rpc = BitcoinRPC()
parser = BitcoinPublicKeyParser(rpc)
pm = BitcoinParserManager()

def create_dicts_to_compare_verbosity_false(dir_one: str, dir_multi: str) -> Tuple[dict, dict]:

    dict1 = {}
    dict2 = {}
    for key_dict, dir_path in ((dict1, dir_one), (dict2, dir_multi)):
        os.chdir(dir_path)
        for f in os.listdir():

            if not os.path.isfile(f):
                continue

            temp_dict = json.load(f)
            for block, keys_list in temp_dict.items():
                if block not in key_dict.keys():
                    key_dict[block] = set()
                key_dict[block] += set(keys_list)

    return dict1, dict2

@pytest.mark.parametrize("range_to_parse",
                         [
                             range(1, 10)
                         ])
def test_parse_range_verbosity_false(range_to_parse: range):
    parser.set_verbosity(False)
    os.chdir("/tmp")
    if os.path.isdir("pytest_test_parser_manager"):
        shutil.rmtree("pytest_test_parser_manager")
    os.mkdir("pytest_test_parser_manager")
    os.chdir("pytest_test_parser_manager")
    os.mkdir("one_process")
    os.mkdir("one_process/gathered_data")
    os.mkdir("multiprocessing")
    os.mkdir("multiprocessing/gathered_data")

    os.chdir("one_process")
    parser.process_block_range(range_to_parse)
    os.chdir("../multiprocessing")
    pm.parse_range(range_to_parse)

    dict1, dict2 = create_dicts_to_compare_verbosity_false("/tmp/pytest_test_parser_manager/one_process/gathered_data",\
                                                           "/tmp/pytest_test_parser_manager/multiprocessing/gathered_data")

    assert dict1.keys() == dict2.keys()
    for block_n in dict1.keys():
        assert dict1[block_n] == dict2[block_n]
