#!/usr/bin/env python3
import json
import os
import subprocess
import sys


def inspect_image(hash):
    return subprocess.check_output(['docker', 'inspect', hash])

def get_layers(image_desc_json):
    desc = json.loads(image_desc_json)
    data = desc[0]['GraphDriver']['Data']
    lower = data['LowerDir']
    upper = data['UpperDir']
    return (lower, upper)

def get_mount(lower, upper, merged):
    with open('mount.sh', 'w') as f:
        index = 0
        f.write('mkdir -p $1\n')
        f.write('work=$(mktemp -d)\n')
        f.write('upper=$(mktemp -d)\n')        
        f.write('mount -t overlay overlay -o lowerdir=%s:%s,upperdir=$upper,workdir=$work %s\n'
                % ( upper, lower, merged))

if __name__ == "__main__":
    if len(sys.argv) != 3:
        print('usage: docker-image-mount hash target-dir')
        sys.exit(1)

    image_desc_json = inspect_image(sys.argv[1])
    (lower, upper) = get_layers(image_desc_json)
    get_mount(lower, upper, sys.argv[2])

    subprocess.check_output(['sudo', 'sh', 'mount.sh', sys.argv[2]])

    uid = int(os.environ.get('SUDO_UID', os.getuid()))
    subprocess.check_output(['sudo', 'chown', '%d:%d' % (uid,uid), sys.argv[2]])
