#!/bin/env python3

import os
import sys
import time
import argparse
import subprocess


ARCH32 = 32
ARCH64 = 64

if 'PIN_ROOT' not in os.environ:
    PIN_ROOT = 'pin-3.7'
else:
    PIN_ROOT = os.environ['PIN_ROOT']

if 'LEETAINT_ROOT' not in os.environ:
    LEETAINT_ROOT = 'pintool'
else:
    LEETAINT_ROOT = os.environ['LEETAINT_ROOT']


def check_binary(target_bin):
    arch = subprocess.check_output(['objdump', '-a', target_bin])
    if b'elf32' in arch:
        return 32
    elif b'elf64-x86-64' in arch:
        return 64
    else:
        return -1


def need_redirect_stdin(cmds):
    return '@@' not in ' '.join(cmds)


def leetaint(inputfile, outdir, cmds):
    pin_path = os.path.join(PIN_ROOT, 'pin')
    trace_out = os.path.join(outdir, 'trace.txt')
    trace_log = os.path.join(outdir, 'trace.log')
    if isinstance(cmds, str):
        target_cmd = cmds.replace('@@', inputfile)
        target_arch = check_binary(cmds.split()[0])
    else:
        target_cmd = ' '.join(cmds).replace('@@', inputfile)
        target_arch = check_binary(cmds[0])

    if target_arch == -1:
        print("ERROR: Target binary isn't executable", file=sys.stderr)
        return False

    os.makedirs(outdir, exist_ok=True)
    os.system("rm -rf {}/* 2> /dev/null".format(outdir))

    # pintool 插桩
    if target_arch == ARCH64:
        pintool = 'obj-intel64/leetaint.so'
    elif target_arch == ARCH32:
        pintool = 'obj-ia32/leetaint.so'
    pintool = os.path.join(LEETAINT_ROOT, pintool)

    redirect_stdin = ""
    if need_redirect_stdin(cmds):
        redirect_stdin = f"< {inputfile}"

    cmd = f"env PIN_ROOT={PIN_ROOT} {pin_path} -t {pintool} -i {inputfile} -o {trace_out} -l {trace_log} -- {target_cmd} {redirect_stdin} > /dev/null"
    print('[CMD]:', cmd, file=sys.stderr)
    start_time = time.time()
    os.system(cmd)
    print("leetaint takes {:.3f} seconds".format(time.time() - start_time), file=sys.stderr)
    return True



def parse_args():
    p = argparse.ArgumentParser(prog='leetaint', description='trace taint information from binary target')
    p.add_argument('-i', dest='input_file', help='An input file', required=True)
    p.add_argument('-o', dest='output_dir', help='An output directory', required=True)
    p.add_argument('cmd', nargs='+', help='cmd')
    return p.parse_args()

if __name__ == '__main__':
    args = parse_args()
    leetaint(args.input_file, args.output_dir, args.cmd)
