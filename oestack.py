#!/usr/bin/env python

import gdb

from gdb_sgx_plugin import oe_debug_enclave_t

def parse_enclave_list():
    list_head = None
    enclave = None
    try:
        list_head = int(gdb.parse_and_eval('(uint64_t)oe_debug_enclaves_list'))
        enclave = oe_debug_enclave_t(list_head)
    except:
        pass
    enclaves = []
    while enclave:
        enclaves.append(enclave)
        next_addr = enclave.next
        if next_addr:
            enclave = oe_debug_enclave_t(next_addr)
        else:
            break
    return enclaves
    
def is_in_oe_stack(addr=None):
    name = 'addr'
    if addr is None:
        addr = int(gdb.parse_and_eval("$rsp"))
        name = 'RSP'
    try:
        addr = int(addr, 16)
        name = 'addr'
    except:
        pass
    print ('%s = 0x%x' % (name, addr))

    num_stack_pages = int(gdb.parse_and_eval('oe_enclave_properties_sgx.header.size_settings.num_stack_pages'))
    print('num stack pages = %d' % num_stack_pages)
    
    enclaves = parse_enclave_list()
    match = False
    closest_stack_start= 0
    closest_stack_end = 0
    closest_stack_distance = pow(2, 64)
    for debug_enclave in enclaves:
        for tcs in debug_enclave.tcs:
            stack_start = int(tcs) - 4096
            stack_end = stack_start - 4096 * num_stack_pages
            if addr <= stack_start and addr >= stack_end:
                match = True
                break
            else:
                distance = abs(stack_end - addr)
                if distance < closest_stack_distance:
                    closest_stack_start = stack_start
                    closest_stack_end = stack_end
                    closest_stack_distance = distance
                
    if match:
        print('%s lies in oe stack' % name)
    else:
        print('%s DOES NOT lie in oe stack' % name)
        print('closest stack end = 0x%x' % closest_stack_end)
        print('closest stack distance = %d' % closest_stack_distance)
        
            

