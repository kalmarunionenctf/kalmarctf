#!/usr/bin/env python3

# script to use flatter from python
# by shalaamum

import subprocess

def reduce_flatter(lattice):
    data = '['
    data += '\n'.join('[' + ' '.join(str(c) for c in vector) + ']' for vector in lattice)
    data += ']\n'
    result = []
    print('starting flatter...')
    with subprocess.Popen(['flatter', '-v'], stdin=subprocess.PIPE, stdout=subprocess.PIPE, stderr=subprocess.STDOUT, bufsize=1, universal_newlines=True) as p:
        p.stdin.write(data)
        p.stdin.close()
        #stdout = p.communicate(input=data)
        #print(stdout)
        for line in p.stdout:
            if line[0] == '[':
                result.append([int(x) for x in line.strip().replace('[','').replace(']','').split(' ')])
            elif line[0] == ']':
                pass
            else:
                print(line.rstrip())
        p.wait()
    print(f'flatter finished!')
    return result
