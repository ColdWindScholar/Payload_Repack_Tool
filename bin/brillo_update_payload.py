#!/bin/env python3
import hashlib
import os.path
import re
import shutil
import subprocess
import sys
from os import system
from platform import uname
from random import randint, choice
from tempfile import mkdtemp, mkstemp
from zipfile import ZipFile

EX_UNSUPPORTED_DELTA = 100
warn = lambda *args: print("brillo_update_payload: warning:", *args)
strings = {}

def call(exe, extra_path:str=None):
    if isinstance(exe, list):
        cmd = exe
        if extra_path:
            cmd[0] = f"{extra_path}{exe[0]}"
        cmd = [i for i in cmd if i]
    else:
        raise TypeError
    try:
        ret = subprocess.Popen(cmd, stdin=subprocess.PIPE, stdout=subprocess.PIPE,
                               stderr=subprocess.STDOUT)
        for i in iter(ret.stdout.readline, b""):
                try:
                    out_put = i.decode("utf-8").strip()
                except (Exception, BaseException):
                    out_put = i.decode("gbk").strip()
                print(out_put)
    except subprocess.CalledProcessError as e:
        for i in iter(e.stdout.readline, b""):
                try:
                    out_put = i.decode("utf-8").strip()
                except (Exception, BaseException):
                    out_put = i.decode("gbk").strip()
                print(out_put)
        return 2
    except FileNotFoundError:
        return 2
    ret.wait()
    return ret.returncode

def die(*args):
    print("brillo_update_payload: error:", *args)
    sys.exit(1)

class Options:
    FLAGS_force_minor_version = ''
    FLAGS_source_image = ''
    FLAGS_target_image = ''
    FLAGS_full_boot = ''
    FLAGS_disable_fec_computation = ''
    FLAGS_is_partial_update = ''
    FLAGS_payload = ''
    FLAGS_payload_signature_file = ''
    FLAGS_properties_file = '-'
    FLAGS_disable_verity_computation = ''
    FLAGS_metadata_signature_file = ''
    FLAGS_metadata_hash_file = ''
    FLAGS_unsigned_payload = ''
    FLAGS_compressor_types =''
    FLAGS_enable_vabc_xor = ''
    FLAGS_disable_vabc = ''
    FLAGS_max_timestamp = ''
    FLAGS_signature_size = ''
    FLAGS_partition_timestamps = ''
    FLAGS_payload_hash_file = ''
    FLAGS_metadata_size_file = ''
options = Options()
# Yes We can change it by importing strings
strings['work_dir'] = '/tmp'
TMPDIR = strings['work_dir']
SRC_PARTITIONS = {}
DST_PARTITIONS = {}
SRC_PARTITIONS_MAP = {}
DST_PARTITIONS_MAP = {}
PARTITIONS_ORDER = []
EXTRACT_IMAGE_PIDS = []
CLEANUP_FILES = []
FORCE_MAJOR_VERSION = ""
FORCE_MINOR_VERSION = ""
arch= uname().machine

GENERATOR=f"./bin/delta_generator_{arch}"
# Path to the postinstall config file in target image if exists.
POSTINSTALL_CONFIG_FILE = ""

# Path to the dynamic partition info file in target image if exists.
DYNAMIC_PARTITION_INFO_FILE = ""

# Path to the META/apex_info.pb found in target build
APEX_INFO_FILE = ""


# read_option_int <file.txt> <option_key> [default_value]
def read_option_uint(file_txt, option_key, default_value, *args):
    with open(file_txt, encoding='utf-8', newline='\n') as f:
        for i in f.readlines():
            if f"{option_key}=" in i:
                _, v = i.split('=')
                if v.strip().isdigit():
                    return v.strip()
                else:
                    break
    return default_value

def truncate_file(file_path, file_size:int):
    open(file_path, 'a').truncate(file_size)

def v_code(num=6) -> str:
    """
    Get Random Str in Number and words
    :param num: number of Random Str
    :return:
    """
    ret = ""
    for i in range(num):
        num = randint(0, i)
        # num = chr(random.randint(48,57))#ASCII表示数字
        letter = chr(randint(97, 122))  # 取小写字母
        letter_ = chr(randint(65, 90))  # 取大写字母
        s = str(choice([num, letter, letter_]))
        ret += s
    return ret


create_tempfile = lambda pattern:mkstemp(prefix=pattern if pattern else 'tempfile.', dir=TMPDIR)[1]
create_tempdir = lambda pattern:mkdtemp(prefix=pattern if pattern else 'tempdir.', dir=TMPDIR)[1]
def cleanup():
    try:
        for i in CLEANUP_FILES:
            if os.path.isfile(i):
                os.remove(i)
            if os.path.isdir(i):
                shutil.rmtree(i)
    except:
        die("Cleanup encountered an error.")

#todo:cleanup_on_exit
#todo:cleanup_on_error


def hashlib_calculate(file_path, method: str):
    if not hasattr(hashlib, method):
        print(f"Warn, The algorithm {method} not exist in hashlib!")
        return 1
    if not os.path.exists(file_path) or not os.path.isfile(file_path):
        print(f"Warn, The file {file_path} not exist!")
        return 1
    algorithm = getattr(hashlib, method)()
    with open(file_path, "rb") as f:
        for chunk in iter(lambda: f.read(4096), b""):
            algorithm.update(chunk)
    return algorithm.hexdigest()

def extract_image_cros(*args):
    image, partitions_array, partitions_order, *_ = args
    kernel = create_tempfile('kernel.bin')
    CLEANUP_FILES.append(kernel)
    root = create_tempfile('root.bin')
    CLEANUP_FILES.append(root)
    call(['cros_generate_update_payload', '--extract', '--image', image, '--kern_path', kernel, '--root_path', root])
    global FORCE_MAJOR_VERSION
    FORCE_MAJOR_VERSION = "2"
    globals()[partitions_array]['kernel'] = kernel
    globals()[partitions_array]['root'] = root
    if not globals()[partitions_order]:
        globals()[partitions_order] = ['root', 'kernel']
    for part in ['kernel', 'root']:
        varname = globals()[partitions_array][part]
        print(f"md5sum of {varname}: ", hashlib_calculate(varname, 'md5'))

def extract_partition_brillo(image, partitions_array, part, part_file, part_map_file):
    path_in_zip = ''
    for path in ['IMAGES', 'RADIO']:
        with ZipFile(image, 'r') as f:
            if f"{path}/{part}.img" in f.namelist():
                path_in_zip = path
                break
    if not path_in_zip:
        die(f"Failed to find {part}.img")
    with ZipFile(image, 'r') as f:
        with open(part_file, 'wb') as pa:
            pa.write(f.read(f"{path_in_zip}/{part}.img"))
    with open(part_file, 'rb') as p:
        magic = p.read(4)
    if magic == b':\xff&\xed':
        print(f"Converting Android sparse image {part}.img to RAW.")
        call(['simg2img', part_file, f'{part_file}.raw'])
        os.remove(part_file)
        os.rename(f"{part_file}.raw", part_file)
    with ZipFile(image, 'r') as f:
        if f"{path_in_zip}/{part}.map" in f.namelist():
            with open(part_map_file, 'wb') as pa:
                pa.write(f.read(f"{path_in_zip}/{part}.map"))
    filesize = os.path.getsize(part_file)
    if filesize % 4096:
        if partitions_array == 'SRC_PARTITIONS':
            print(f'Rounding DOWN partition {part}.img to a multiple of 4 KiB.')
            filesize = filesize & -4096
        else:
            print(f"Rounding UP partition {part}.img to a multiple of 4 KiB.")
            filesize = (filesize + 4095) & -4096
        truncate_file(part_file, filesize)
    print(f"Extracted {partitions_array}[{part}]: {filesize} bytes")

def extract_image_brillo(*args):
    image, partitions_array, partitions_order, *_ = args
    partitions = ["boot" ,"system"]
    ab_partitions_list = create_tempfile("ab_partitions_list.")
    CLEANUP_FILES.append(ab_partitions_list)
    with ZipFile(image, 'r') as f:
        if "META/ab_partitions.txt" in f.namelist():
            with open(ab_partitions_list, 'wb') as ab:
                ab.write(f.read("META/ab_partitions.txt"))
        else:
            warn("No ab_partitions.txt found. Using default.")
    with open(ab_partitions_list, 'r', encoding='utf-8', newline='\n') as f:
        regex = re.compile(r'^[a-zA-Z0-9_-]*$')
        lines = f.readlines()
        # May bug
        if [line for line in lines if not regex.match(line)]:
            die("Invalid partition names found in the partition list.")
        lines = [i.strip() for i in lines]
        partitions = sorted(set(lines), key=lines.index)
        if not len(partitions):
            die("The list of partitions is empty. Can't generate a payload.")
    print(f"List of A/B partitions for {partitions_array}: {partitions}")
    if partitions_order:
        globals()[partitions_order] = partitions
    global FORCE_MAJOR_VERSION
    FORCE_MAJOR_VERSION="2"
    if partitions_array == 'SRC_PARTITIONS':
        ue_config = create_tempfile("ue_config.")
        CLEANUP_FILES.append(ue_config)
        with ZipFile(image, 'r') as f:
            if "META/update_engine_config.txt" in f.namelist():
                with open(ue_config, 'wb') as ue:
                    ue.write(f.read("META/update_engine_config.txt"))
            else:
                warn("No update_engine_config.txt found. Assuming pre-release image, using payload minor version 2")
        global FORCE_MINOR_VERSION
        FORCE_MINOR_VERSION = read_option_uint(ue_config ,"PAYLOAD_MINOR_VERSION", 2)
        if options.FLAGS_force_minor_version:
            FORCE_MINOR_VERSION = options.FLAGS_force_minor_version
        FORCE_MAJOR_VERSION = read_option_uint(ue_config,"PAYLOAD_MAJOR_VERSION", 2)
        if int(FORCE_MINOR_VERSION) <= 2:
            warn(f"No delta support from minor version {FORCE_MINOR_VERSION}.  Disabling deltas for this source version.")
            sys.exit(EX_UNSUPPORTED_DELTA)
    else:
        postinstall_config = create_tempfile("postinstall_config.")
        CLEANUP_FILES.append(postinstall_config)
        with ZipFile(image, 'r') as f:
            if "META/postinstall_config.txt" in f.namelist():
                with open(postinstall_config, 'wb') as po:
                    po.write(f.read("META/postinstall_config.txt"))
                global POSTINSTALL_CONFIG_FILE
                POSTINSTALL_CONFIG_FILE = postinstall_config
        dynamic_partitions_info = create_tempfile("dynamic_partitions_info.")
        CLEANUP_FILES.append(dynamic_partitions_info)
        with ZipFile(image, 'r') as f:
            if "META/dynamic_partitions_info.txt" in f.namelist():
                with open(dynamic_partitions_info, 'wb') as dy:
                    dy.write(f.read("META/dynamic_partitions_info.txt"))
                global DYNAMIC_PARTITION_INFO_FILE
                DYNAMIC_PARTITION_INFO_FILE = dynamic_partitions_info
        apex_info = create_tempfile("apex_info.")
        CLEANUP_FILES.append(apex_info)
        with ZipFile(image, 'r') as f:
            if "META/apex_info.pb" in f.namelist():
                with open(apex_info, 'wb') as ap:
                    ap.write(f.read("META/apex_info.pb"))
                global APEX_INFO_FILE
                APEX_INFO_FILE = apex_info
    for part in partitions:
        part_file = create_tempfile(f"{part}.img.")
        part_map_file =create_tempfile (f"{part}.map.")
        CLEANUP_FILES.append(part_file)
        CLEANUP_FILES.append(part_map_file)
        #todo:multitasks
        EXTRACT_IMAGE_PIDS.append('')
        globals()[partitions_array][part] = part_file
        globals()[partitions_array+'_MAP'][part] = part_map_file
        extract_partition_brillo(image, partitions_array, part, part_file, part_map_file)

def cleanup_partition_array(partitions_array):
    part_dict = globals()[partitions_array].copy()
    for part in part_dict:
        path = part_dict[part]
        if os.path.isfile(path):
            if not os.path.getsize(path):
                globals()[partitions_array].pop(part)
        else:
            globals()[partitions_array].pop(part)

def extract_payload_images(payload_type):
    print(f"Extracting images for {payload_type} update.")
    if payload_type == 'delta':
        extract_image(options.FLAGS_source_image, "SRC_PARTITIONS")
    extract_image(options.FLAGS_target_image, "DST_PARTITIONS" ,"PARTITIONS_ORDER")
    cleanup_partition_array("SRC_PARTITIONS")
    cleanup_partition_array("SRC_PARTITIONS_MAP")
    cleanup_partition_array("DST_PARTITIONS")
    cleanup_partition_array("DST_PARTITIONS_MAP")

def get_payload_type():
    return 'full' if not options.FLAGS_source_image else 'delta'

def validate_generate():
    if not options.FLAGS_payload:
        die("You must specify an output filename with --payload FILENAME")
    if not options.FLAGS_target_image:
        die("You must specify a target image with --target_image FILENAME")

def cmd_generate():
    payload_type = get_payload_type()
    extract_payload_images(payload_type)
    print(f"Generating {payload_type} update.")
    GENERATOR_ARGS = [f'--out_file={options.FLAGS_payload}', ]
    old_partitions = ""
    new_partitions = ""
    partition_names = ""
    old_mapfiles = ""
    new_mapfiles = ""
    for part in PARTITIONS_ORDER:
        if partition_names:
            partition_names += ":"
            new_partitions += ":"
            old_partitions += ":"
            new_mapfiles += ":"
            old_mapfiles += ":"
        partition_names += part
        new_partitions += DST_PARTITIONS.get(part)
        if options.FLAGS_full_boot == 'true' and part == 'boot':
            old_partitions += ""
        else:
            t = SRC_PARTITIONS.get(part)
            old_partitions += t if t else ''
        new_mapfiles += DST_PARTITIONS_MAP[part] if DST_PARTITIONS_MAP.get(part) else ''
        old_mapfiles += SRC_PARTITIONS_MAP[part] if SRC_PARTITIONS_MAP.get(part) else ''
    GENERATOR_ARGS.append(f'--partition_names={partition_names}')
    GENERATOR_ARGS.append(f'--new_partitions={new_partitions}')
    GENERATOR_ARGS.append(f'--new_mapfiles={new_mapfiles}')
    if options.FLAGS_is_partial_update == 'true':
        GENERATOR_ARGS.append('--is_partial_update="true"')
        if not globals()["FORCE_MINOR_VERSION"]:
            globals()["FORCE_MINOR_VERSION"]='7'
    if payload_type == 'delta':
        GENERATOR_ARGS.append(f"--old_partitions={old_partitions}")
        GENERATOR_ARGS.append(f'--old_mapfiles={old_mapfiles}')
        if options.FLAGS_disable_fec_computation:
            GENERATOR_ARGS.append(f'--disable_fec_computation={options.FLAGS_disable_fec_computation}')
        if options.FLAGS_disable_verity_computation:
            GENERATOR_ARGS.append(f'--disable_verity_computation={options.FLAGS_disable_verity_computation}')
        if options.FLAGS_compressor_types:
            GENERATOR_ARGS.append(f'--compressor_types={options.FLAGS_compressor_types}')
    if options.FLAGS_enable_vabc_xor:
        GENERATOR_ARGS.append(
            f'--enable_vabc_xor={options.FLAGS_enable_vabc_xor}'
        )
    if options.FLAGS_disable_vabc:
        GENERATOR_ARGS.append(f'--disable_vabc={options.FLAGS_disable_vabc}')
    if FORCE_MINOR_VERSION:
        GENERATOR_ARGS.append(f'--minor_version={FORCE_MINOR_VERSION}')
    if FORCE_MAJOR_VERSION:
        GENERATOR_ARGS.append(f'--major_version={FORCE_MAJOR_VERSION}')
    if options.FLAGS_metadata_size_file:
        GENERATOR_ARGS.append(f'--out_metadata_size_file={options.FLAGS_metadata_size_file}')
    if options.FLAGS_max_timestamp:
        GENERATOR_ARGS.append(f'--max_timestamp={options.FLAGS_max_timestamp}')
    if options.FLAGS_partition_timestamps:
        GENERATOR_ARGS.append(f'--partition_timestamps={options.FLAGS_partition_timestamps}')
    if POSTINSTALL_CONFIG_FILE:
        GENERATOR_ARGS.append(f'--new_postinstall_config_file={POSTINSTALL_CONFIG_FILE}')
    if DYNAMIC_PARTITION_INFO_FILE:
        GENERATOR_ARGS.append(f'--dynamic_partition_info_file={DYNAMIC_PARTITION_INFO_FILE}')
    if APEX_INFO_FILE:
        GENERATOR_ARGS.append(f'--apex_info_file={APEX_INFO_FILE}')
    print(f"Running delta_generator with args: {GENERATOR_ARGS}")
    call([GENERATOR, *GENERATOR_ARGS])
    print(f"Done generating {payload_type} update.")

def validate_hash():
    if not options.FLAGS_signature_size:
        die("You must specify signature size with --signature_size SIZES")
    if not options.FLAGS_unsigned_payload:
        die(f"You must specify the input unsigned payload with --unsigned_payload FILENAME")
    if not options.FLAGS_payload_hash_file:
        die(f'You must specify --payload_hash_file FILENAME')
    if not options.FLAGS_metadata_hash_file:
        die(f'You must specify --metadata_hash_file FILENAME')

def cmd_hash():
    call([
        GENERATOR, f'--in_file={options.FLAGS_unsigned_payload}',
        f'--signature_size={options.FLAGS_signature_size}',
        f'--out_hash_file={options.FLAGS_payload_hash_file}',
        f'--out_metadata_hash_file={options.FLAGS_metadata_hash_file}'
    ])
    print('Done generating hash.')

def validate_sign():
    if not options.FLAGS_signature_size:
        die("You must specify signature size with --signature_size SIZES")
    if not options.FLAGS_unsigned_payload:
        die("You must specify the input unsigned payload with \
--unsigned_payload FILENAME")
    if not options.FLAGS_payload:
        die("You must specify the output signed payload with --payload FILENAME")
    if not options.FLAGS_payload_signature_file:
        die("You must specify the payload signature file with \
--payload_signature_file SIGNATURES")
    if not options.FLAGS_metadata_signature_file:
        die("You must specify the metadata signature file with \
--metadata_signature_file SIGNATURES")

def cmd_sign():
    GENERATOR_ARGS = [
    f'--in_file={options.FLAGS_unsigned_payload}',
    f'--signature_size={options.FLAGS_signature_size}',
    f'--payload_signature_file={options.FLAGS_payload_signature_file}',
    f'--metadata_signature_file={options.FLAGS_metadata_signature_file}',
    f'--out_file={options.FLAGS_payload}'
    ]
    if options.FLAGS_metadata_size_file:
        GENERATOR_ARGS.append(f'--out_metadata_size_file="{options.FLAGS_metadata_size_file}"')
    call([GENERATOR, *GENERATOR_ARGS])
    print("Done signing payload.")

def validate_properties():
    if not options.FLAGS_payload:
        die("You must specify the payload file with --payload FILENAME")
    if not options.FLAGS_properties_file:
        die("You must specify a non empty --properties_file FILENAME")

def cmd_properties():
    call([GENERATOR, f'--in_file={options.FLAGS_payload}', f'--properties_file={options.FLAGS_properties_file}'])

def validate_verify_and_check():
    if not options.FLAGS_payload:
        die("Error: you must specify an input filename with --payload FILENAME")
    if not options.FLAGS_target_image:
        die('Error: you must specify a target image with --target_image FILENAME')


def cmp_files(file1, file2):
    with open(file1, 'rb') as f1, open(file2, 'rb') as f2:
        offset = 0
        while True:
            byte1 = f1.read(4)
            byte2 = f2.read(4)
            if not byte1 and not byte2:
                return 0

            if not byte1 or not byte2:
                return offset + 1

            if byte1 != byte2:
                return offset + 1

            offset += 1

def cmd_verify():
    payload_type = get_payload_type()
    extract_payload_images(payload_type)
    TMP_PARTITIONS = {}
    for part in PARTITIONS_ORDER:
        tmp_part = create_tempfile("tmp_part.bin.")
        print(f"Creating temporary target partition {tmp_part} for {part}")
        CLEANUP_FILES.append(tmp_part)
        TMP_PARTITIONS[part]=tmp_part
        FILESIZE = os.path.getsize(DST_PARTITIONS[part])
        print(f"Truncating {TMP_PARTITIONS[part]} to {FILESIZE}")
        truncate_file(TMP_PARTITIONS[part], FILESIZE)
    print(f"Verifying {payload_type} update.")
    GENERATOR_ARGS = [f'--in_file="{options.FLAGS_payload}"']
    old_partitions = ""
    new_partitions = ""
    partition_names = ""
    for part in PARTITIONS_ORDER:
        if partition_names:
            partition_names += ":"
            new_partitions += ":"
            old_partitions += ":"
        partition_names += part
        new_partitions += TMP_PARTITIONS[part]
        old_partitions += SRC_PARTITIONS[part] if SRC_PARTITIONS[part] else ''
    GENERATOR_ARGS.append(f'--partition_names="{partition_names}"')
    GENERATOR_ARGS.append(f'--new_partitions="{new_partitions}"')
    if payload_type == 'delta':
        GENERATOR_ARGS.append(f'--old_partitions="{old_partitions}"')
    if FORCE_MAJOR_VERSION:
        GENERATOR_ARGS.append(f'--major_version="{FORCE_MAJOR_VERSION}"')
    print(f"Running delta_generator to verify {payload_type} payload with args: {GENERATOR_ARGS}")
    call([GENERATOR, *GENERATOR_ARGS])
    print(f"Done applying {payload_type} update.")
    print("Checking the newly generated partitions against the target partitions")
    need_pause = False
    for part in PARTITIONS_ORDER:
        not_str = ""
        if cmp_files(TMP_PARTITIONS[part] ,DST_PARTITIONS[part]) != 0:
            not_str = "in"
            need_pause = True
        print(f"The new partition ({part}) is {not_str}valid.")
    if need_pause:
        input("Paused to investigate invalid partitions, press enter key to exit.")
        sys.exit(1)



def extract_image(*args):
    image = args[0]
    with open(image, 'rb') as f:
        magic = f.read(4)
    if magic == b'PK\x03\x04':
        print("Detected .zip file, extracting Brillo image.")
        extract_image_brillo(*args)
        return
    if system(f'cgpt show -q -n "{image}"') == 0:
        print("Detected GPT image, extracting Chrome OS image.")
        extract_image_cros(*args)
        return
    die(f"Couldn't detect the image format of {image}")


def generate(payload: str = '', target_image: str = '', source_image: str = '', metadata_size_file: str = '',
             max_timestamp: str = '',
             partition_timestamps: str = '', disable_fec_computation: str = '', disable_verity_computation: str = '',
             is_partial_update: str = '', full_boot: str = '', disable_vabc: str = '', enable_vabc_xor: str = '',
             force_minor_version: str = '', compressor_types: str = ''):
    options.FLAGS_payload = payload
    options.FLAGS_target_image = target_image
    options.FLAGS_source_image = source_image
    options.FLAGS_metadata_size_file = metadata_size_file
    options.FLAGS_max_timestamp = max_timestamp
    options.FLAGS_partition_timestamps = partition_timestamps
    options.FLAGS_disable_fec_computation = disable_fec_computation
    options.FLAGS_disable_verity_computation = disable_verity_computation
    options.FLAGS_is_partial_update = is_partial_update
    options.FLAGS_full_boot = full_boot
    options.FLAGS_disable_vabc = disable_vabc
    options.FLAGS_enable_vabc_xor = enable_vabc_xor
    options.FLAGS_force_minor_version = force_minor_version
    options.FLAGS_compressor_types = compressor_types
    validate_generate()
    cmd_generate()


def hash_(unsigned_payload: str = '', signature_size: str = '', metadata_hash_file: str = '',
          payload_hash_file: str = ''):
    options.FLAGS_unsigned_payload = unsigned_payload
    options.FLAGS_signature_size = signature_size
    options.FLAGS_metadata_hash_file = metadata_hash_file
    options.FLAGS_payload_hash_file = payload_hash_file
    validate_hash()
    cmd_hash()


def sign(unsigned_payload: str = '', signature_size: str = '', payload: str = '', metadata_signature_file: str = '',
         payload_signature_file: str = '', metadata_size_file: str = ''):
    options.FLAGS_unsigned_payload = unsigned_payload
    options.FLAGS_signature_size = signature_size
    options.FLAGS_payload = payload
    options.FLAGS_metadata_signature_file = metadata_signature_file
    options.FLAGS_payload_signature_file = payload_signature_file
    options.FLAGS_metadata_size_file = metadata_size_file
    validate_sign()
    cmd_sign()


def properties(payload: str = '', properties_file: str = '-'):
    options.FLAGS_payload = payload
    options.properties_file = properties_file
    validate_properties()
    cmd_properties()
