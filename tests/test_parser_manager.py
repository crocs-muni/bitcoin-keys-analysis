import sys, os, shutil
sys.path.append("/home/xyakimo1/crocs/src") # add here path to the project's source directory
from bitcoin_public_key_parser import BitcoinPublicKeyParser, BitcoinRPC
from parser_manager import BitcoinParserManager
import pytest
import json, logging
from typing import Tuple

logger = logging.getLogger(__name__)

file_handler = logging.FileHandler("logs/test_parser_manager.log")
file_handler.setLevel(logging.DEBUG)
formatter = logging.Formatter("%(asctime)s | %(levelname)s | %(name)s | %(message)s | %(funcName)s | %(lineno)d")
file_handler.setFormatter(formatter)

logger.addHandler(file_handler)
logger.setLevel(logging.DEBUG)

rpc = BitcoinRPC()
parser = BitcoinPublicKeyParser(rpc)
pm = BitcoinParserManager()

def create_directory_tree() -> None:
    assert os.getcwd() == "/tmp"

    if os.path.isdir("pytest_test_parser_manager"):
        shutil.rmtree("pytest_test_parser_manager")
    os.mkdir("pytest_test_parser_manager")
    os.chdir("pytest_test_parser_manager")

    for dir_name in ("one_process", "multiprocessing"):
        os.mkdir(dir_name)
        os.chdir(dir_name)
        os.mkdir("gathered-data")
        os.mkdir("logs")
        os.mkdir("state")
        os.chdir("..")

    os.chdir("/tmp")
    assert os.getcwd() == "/tmp"


def create_dicts_to_compare_verbosity_false(dir_one: str, dir_multi: str) -> Tuple[dict, dict]:

    dict1 = {}
    dict2 = {}
    for key_dict, dir_path in ((dict1, dir_one), (dict2, dir_multi)):
        os.chdir(dir_path)
        for file_name in os.listdir():

            if not os.path.isfile(file_name):
                continue

            try:
                with open(file_name, 'r') as f:
                    temp_dict = json.load(f)
            except:
                logger.exception("Couldn't open a file.")

            for block, keys_list in temp_dict.items():
                if block not in key_dict.keys():
                    key_dict[block] = set()
                key_dict[block].update(set(keys_list))

    return dict1, dict2


@pytest.mark.parametrize("range_to_parse",
                         [
                             range(1, 10)
                         ])
def test_parse_range_verbosity_false(range_to_parse: range):
    parser.set_verbosity(False)
    os.chdir("/tmp")
    create_directory_tree()
    os.chdir("pytest_test_parser_manager")

    os.chdir("one_process")
    parser.process_block_range(range_to_parse)
    os.chdir("../multiprocessing")
    pm.parse_range(range_to_parse)

    dict1, dict2 = create_dicts_to_compare_verbosity_false("/tmp/pytest_test_parser_manager/one_process/gathered-data",\
                                                           "/tmp/pytest_test_parser_manager/multiprocessing/gathered-data")

    assert dict1.keys() == dict2.keys()
    assert len(dict1) > 0
    for block_n in dict1.keys():
        assert dict1[block_n] == dict2[block_n]
    logger.debug(f"Dictionary from one process: {dict1}; Dictionary from multiprocessing: {dict2}")
