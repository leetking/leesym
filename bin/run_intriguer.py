#!/usr/bin/env python3
import argparse
import time
import os
import subprocess

ARCH32 = 32
ARCH64 = 64

def parse_args():
    p = argparse.ArgumentParser()
    p.add_argument('-i', dest='input_file', help='An input file', required=True)
    p.add_argument('-o', dest='output_dir', help='An output directory', required=True)
    p.add_argument('-t', dest='timeout', help='A timeout')
    p.add_argument('-s', dest='skip_testcase', help='Skip generating testcases')
    p.add_argument('cmd', nargs='+', help='cmd')
    return p.parse_args()

def exe_cat(cmd):
    fd = subprocess.Popen(cmd, shell=True,
          stdout=subprocess.PIPE,
          stderr=subprocess.PIPE)
    return fd.stdout, fd.stderr

def check_binary(target_bin):
    stdout, stderr = exe_cat('objdump -a ' + target_bin)

    arch = stdout.read()
    if arch.find(b'elf32') >= 0:
        return 32
    elif arch.find(b'elf64-x86-64') >= 0:
        return 64
    else:
        return -1

# 解析 field.out 输出并生成测试用例
# input_file: 种子文件
# field_file: 就是 traceAnalyzer 生成的 field.out
# outdir: 测试用例存放位置
def generate_testcase(input_file, field_file, outdir):
    input_data = ''
    with open(input_file, 'rb') as fp:
        input_data = fp.read()

    i = 0
    with open(field_file, 'r') as fp:
        for field in fp:
            f = field.split('\t')
            start = int(f[0])
            size = int(f[1])

            for field_token in f[2:]:
                field_marker = field_token[0]
                values = field_token[1:].split(',')

                for v in values:
                    if not v or v.isspace():
                        continue
                    i += 1
                    output_data = input_data
                    # multi values
                    if v[0] == ':':
                        multi_values = v.split(':')[1:]
                        for mv in multi_values:
                            start_, size_, value_ = mv.split('_')
                            if start_ == 'x': start_ = start
                            if size_ == 'x': size_ = size
                            if len(value_) % 2: value_ = '0' + value_
                            start_ = int(start_)
                            size_ = int(size_)
                            value_ = bytes.fromhex(value_)
                            output_data = output_data[:start_] + value_ + output_data[start_+size_:]

                        with open(os.path.join(outdir, f"{i:02}_{field_marker}_{start}_{size}_complex"), 'wb') as wfp:
                            wfp.write(output_data)

                    else:
                        # odd
                        if len(v) % 2: v = '0' + v
                        v = bytes.fromhex(v)
                        output_data = output_data[:start] + v + output_data[start+size:]
                        with open(os.path.join(outdir, f"{i:02}_{field_marker}_{start}_{size}"), 'wb') as wfp:
                            wfp.write(output_data)

    print('{} test cases are generated.'.format(i))

def need_redirect_stdin(cmds):
    return '@@' not in ' '.join(cmds)

def main():
    args = parse_args()

    os.environ['ASAN_OPTIONS'] = 'detect_leaks=0'
    if 'INTRIGUER_ROOT' not in os.environ:
        INTRIGUER_ROOT = '..'
    else:
        INTRIGUER_ROOT = os.environ['INTRIGUER_ROOT']
    PIN_ROOT = os.path.join(INTRIGUER_ROOT, 'pin-3.7')
    pin_path = os.path.join(PIN_ROOT, 'pin')
    analyzer_path = os.path.join(INTRIGUER_ROOT, 'traceAnalyzer/traceAnalyzer')
    testcase_dir = os.path.join(args.output_dir, 'testcases')
    trace_out = os.path.join(args.output_dir, 'trace.txt')
    trace_log = os.path.join(args.output_dir, 'trace.log')
    field_out = os.path.join(args.output_dir, 'field.txt')
    field_log = os.path.join(args.output_dir, 'field.log')
    target_cmd = ' '.join(args.cmd).replace('@@', args.input_file)

    target_arch = check_binary(args.cmd[0])
    if target_arch == -1:
        print("ERROR: Target binary isn't executable")
        return 2

    if not os.path.exists(args.output_dir):
        os.mkdir(args.output_dir)
    os.system("rm -rf {}/* 2> /dev/null".format(args.output_dir))

    intriguer_start = time.time()
    start_time = time.time()

    # pintool 插桩
    if target_arch == ARCH64:
        pintool = 'pintool/obj-intel64/executionMonitor.so'
    elif target_arch == ARCH32:
        pintool = 'pintool/obj-ia32/executionMonitor.so'
    pintool = os.path.join(INTRIGUER_ROOT, pintool)

    timeout_kill = ""
    if args.timeout:
        timeout_kill = "timeout -k 5 {}".format(int(args.timeout) * 20 / 90)
    redirect_stdin = ""
    if need_redirect_stdin(args.cmd):
        redirect_stdin = f"< {args.input_file}"

    cmd = f"env PIN_ROOT={PIN_ROOT} {timeout_kill} {pin_path} -t {pintool} -i {args.input_file} -o {trace_out} -l {trace_log} -- {target_cmd} {redirect_stdin} > /dev/null"
    print('[CMD]:', cmd)
    os.system(cmd)
    print('--- Execution Monitor takes {:.3f} seconds ---'.format(time.time() - start_time))

    # traceAnalyzer 求解
    start_time = time.time()
    timeout_kill = ""
    if args.timeout:
        timeout_kill = "timeout -k 5 {}".format(int(args.timeout) * 70 / 90)
    cmd = f"{timeout_kill} {analyzer_path} {trace_out} {args.input_file} {field_out} > {field_log}"
    print('[CMD]:', cmd)
    os.system(cmd)
    print('--- Trace Analyzer takes {:.3f} seconds ---'.format(time.time() - start_time))

    if not args.skip_testcase:
        os.makedirs(testcase_dir, exist_ok=True)
        generate_testcase(args.input_file, field_out, testcase_dir)

    # 记录总共花费多少时间
    with open(os.path.join(args.output_dir, 'time.txt'), 'w') as fp:
        print("{:.6f}".format(time.time() - intriguer_start), file=fp)

if __name__ == '__main__':
    main()
