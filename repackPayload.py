#!/bin/env python3
import os.path

from platform import uname
from os import path, listdir, system
def main():
    arch = uname().machine
    print(f'Platform: {arch}')
    if arch not in ['x86_64', 'aarch64']:
        arch = 'x86_64'
    folder = "IMAGES"
    if not path.exists(folder):
        print(f"Floder not found：{folder}")
        exit(1)
    name_list = ':'.join([i[:-4] for i in listdir(folder) if i.endswith('.img')])
    file_list = ":".join([os.path.join(folder, i).replace('\\', '/') for i in listdir(folder) if i.endswith('.img')])
    system(f'./bin/delta_generator_{arch} -out_file=output/unsigned-payload.bin -partition_names={name_list} -new_partitions={file_list}')
    system(f'./bin/delta_generator_{arch} --in_file=output/unsigned-payload.bin -signature_size=256 -out_metadata_hash_file=output/sig_metadata.bin -out_hash_file=output/sig_hash.bin')
    system('openssl pkeyutl -sign -inkey key/testkey.key -pkeyopt digest:sha256 -in output/sig_hash.bin -out output/signed_hash.bin')
    system('openssl pkeyutl -sign -inkey key/testkey.key -pkeyopt digest:sha256 -in output/sig_metadata.bin -out output/signed_metadata.bin')
    system(f'./bin/delta_generator_{arch} --in_file=output/unsigned-payload.bin --out_file=output/payload.bin --signature_size=256 --metadata_signature_file=output/signed_metadata.bin --payload_signature_file=output/signed_hash.bin')
    system(f'./bin/delta_generator_{arch} --in_file=output/payload.bin --properties_file=output/payload_properties.txt')


if __name__ == '__main__':
    main()