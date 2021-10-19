import gdb

def get_current_thread_ssa_gpr():
    threads = gdb.execute('info threads', False, True).split('\n')
    current_thread = [t for t in threads if t.startswith('*')][0]
    current_thread_id = int(current_thread.split()[3], 16)

    binding = gdb.parse_and_eval('oe_debug_thread_bindings_list')

    while binding:
        b = binding.dereference()
        if b['thread_id'] == current_thread_id:
            tcs = int(b['tcs'])
            print('tcs = 0x%x' % tcs)
            cssa = gdb.parse_and_eval('((sgx_tcs_t*)0x%x)->cssa' % tcs)

            # Based on debugger/ptraceLib/enclave_context.c
            PAGE_SIZE = 4096
            OSSA_FROM_TCS = PAGE_SIZE
            DEFAULT_SSA_FRAME_SIZE = 0x1
            SGX_GPR_BYTE_SIZE = 0xb8

            ssa_frame_size = DEFAULT_SSA_FRAME_SIZE
            ssa_base_address = tcs + OSSA_FROM_TCS + (cssa - 1)*ssa_frame_size * PAGE_SIZE
            frame_byte_size = ssa_frame_size * PAGE_SIZE
            gprsgx_offset = ssa_base_address + frame_byte_size - SGX_GPR_BYTE_SIZE
            ssa_gpr = gdb.parse_and_eval('(sgx_ssa_gpr_t*)(void*)0x%x' % gprsgx_offset)
            return ssa_gpr

        binding = b['next']


def print_ssa():
    ssa_gpr = get_current_thread_ssa_gpr()
    if not ssa_gpr:
        print('ssa not found for current thread')
        return
    
    enc_fs_base = ssa_gpr['fs_base']
    enc_gs_base = ssa_gpr['gs_base']
    try:
        ssa_info = gdb.execute('p/x $tcs = *(sgx_ssa_gpr_t*)0x%x' % int(ssa_gpr), True, True)
        ssa_info = ssa_info.split('=', 1)[1]
        print('ssa = %s' % ssa_info)
    except:
        print('Could not read ssa. Thread likely in ocall.')

command = """
define ssa
python print_ssa()
end
"""

if __name__ == "__main__":
    with tempfile.NamedTemporaryFile('w') as f:
        f.write(command)
        f.flush()
        gdb.execute('source %s' % f.name)
