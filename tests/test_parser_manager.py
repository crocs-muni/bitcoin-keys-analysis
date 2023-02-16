import sys, os, shutil
sys.path.append("/home/xyakimo1/crocs/src") # add here path to the project's source directory
from bitcoin_public_key_parser import BitcoinPublicKeyParser, BitcoinRPC
from parser_manager import BitcoinParserManager
import pytest
import json, logging, time
from typing import Tuple

logger = logging.getLogger(__name__)

file_handler = logging.FileHandler("logs/test_parser_manager.log")
file_handler.setLevel(logging.DEBUG)
formatter = logging.Formatter("%(asctime)s | %(levelname)s | %(name)s | %(message)s | %(funcName)s | %(lineno)d")
file_handler.setFormatter(formatter)

logger.addHandler(file_handler)
logger.setLevel(logging.INFO)

rpc = BitcoinRPC()
parser = BitcoinPublicKeyParser(rpc)
parser.TESTING = True   # This is to compensate P2PK and P2TR's get_previous_vout.
                        # In real parsing (like range(1, 800000)) there would be no difference,
                        # but when hopping (like range(1, 800000, 50000)) multiprocess version collects a little less keys than one-process.
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

            if not os.path.isfile(file_name) or "failed" in file_name:
                continue

            try:
                with open(file_name, 'r') as f:
                    temp_dict = json.load(f)
            except:
                logger.exception(f"Couldn't open a file or a JSON-parsing error ({file_name}).")
                continue

            for block, keys_list in temp_dict.items():
                if block not in key_dict.keys():
                    key_dict[block] = set()
                key_dict[block].update(set(keys_list))

    return dict1, dict2


os.chdir("/tmp")
create_directory_tree() ## create_directory_tree() must be called before the tests, because it removes the directories, if they already exist.

@pytest.mark.parametrize("range_to_parse",
                         [
                             range(1, 10),
                             range(1, 750000, 100000)
                             #range(775000, 775150)
                         ])
def test_parse_range_verbosity_false(range_to_parse: range):
    parser.set_verbosity(False)
    os.chdir("/tmp/pytest_test_parser_manager") ## Do not forget to call create_directory_tree() beforehand.

    os.chdir("one_process")
    one_process_start_timestamp = time.perf_counter()
    parser.process_block_range(range_to_parse)
    one_process_finish_timestamp = time.perf_counter()

    os.chdir("../multiprocessing")
    multiprocessing_start_timestamp = time.perf_counter()
    pm.parse_range(range_to_parse)
    multiprocessing_finish_timestamp = time.perf_counter()

    one_process_parsing_time = one_process_finish_timestamp - one_process_start_timestamp
    multiprocessing_parsing_time = multiprocessing_finish_timestamp - multiprocessing_start_timestamp

    dict1, dict2 = create_dicts_to_compare_verbosity_false("/tmp/pytest_test_parser_manager/one_process/gathered-data",\
                                                           "/tmp/pytest_test_parser_manager/multiprocessing/gathered-data")

    try:
        assert set(dict1.keys()) == set(dict2.keys())
    except:
        logger.critical(f"Dict1.keys(): {dict1.keys()}, dict2.keys(): {dict2.keys()}.")
        raise AssertionError

    assert len(dict1) > 0
    for block_n in dict1.keys():
        try:
            assert set(dict1[block_n]) == set(dict2[block_n])
        except:
            logger.critical(f"Block_n: {block_n}, symmetric_difference: {set(dict1[block_n]).symmetric_difference(set(dict2[block_n]))}.")
            raise AssertionError

    logger.debug(f"Dictionary from one process: {dict1}; Dictionary from multiprocessing: {dict2}")

    try:
        assert multiprocessing_parsing_time < one_process_parsing_time()
    except:
        logger.warning(f"One-process parsing was faster than multiprocessing! One: {one_process_parsing_time}s / Multi: {multiprocessing_parsing_time}s. {multiprocessing_parsing_time / one_process_parsing_time} times faster on {len(range_to_parse)} blocks ({range_to_parse}).")
    else:
        logger.info(f"Multi-process parsing was faster than one-process. One: {one_process_parsing_time}s / Multi: {multiprocessing_parsing_time}s. {one_process_parsing_time / multiprocessing_parsing_time} times faster on {len(range_to_parse)} blocks ({range_to_parse}).")
