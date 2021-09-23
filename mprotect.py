import gdb
import math
import tempfile

class myst_mprotect_tracker(gdb.Breakpoint):
    def __init__(self):
        #super(myst_mprotect_tracker, self).__init__('myst_mprotect_ocall', internal=True)
        #self.bp = gdb.Breakpoint.__init__(self,'exec.c:637', internal=True)
        #self.bp = gdb.Breakpoint.__init__(self,'_mprotect', internal=True)
        super(myst_mprotect_tracker, self).__init__('_mprotect', internal=False)
        self.calls = []
        self.bt_spec = []
        self.breaks = []

    def stop(self):
        addr = int(gdb.parse_and_eval('(uint64_t)addr'))
        length = int(gdb.parse_and_eval('(uint64_t)len'))
        prot = int(gdb.parse_and_eval('(int)prot'))
        thread = int(gdb.parse_and_eval('$_thread'))
        bt = None
        index = len(self.calls) + 1
        if self.bt_spec:
            frames = self.bt_spec[0]
            start_index = self.bt_spec[1]
            end_index = self.bt_spec[2]

            if index >= start_index and index <= end_index:
                bt = gdb.execute('bt %d' % frames, False, True)

        self.calls.append((addr, length, prot, bt, thread))
        if index in self.breaks:
            print("myst-prot: breaking at call %d" % index)
            return True

        return False

    def do_command(self, arg0, *args):
        if arg0 == "-bt":
            self.set_bt_spec(*args)
        elif arg0 == "-b":
            self.add_breaks(*args)
        else:
            self.get_prot(arg0, *args)

    def set_bt_spec(self, frames=1000, start_index=1, end_index=pow(2,32)):
        self.bt_spec = (frames, start_index, end_index)

    def add_breaks(self, *args):
        for a in args:
            self.breaks.append(int(a))

    def get_prot(self, addr_str, get_all=None):
        addr = int(gdb.parse_and_eval(addr_str))
        print('address %s = 0x%x' % (addr_str, addr))
        index = len(self.calls) + 1
        for c in reversed(self.calls):
            index -= 1
            start = c[0]
            length = c[1]
            end = start + length
            end = math.ceil(end/4096) * 4096
            prot = c[2]
            bt = c[3]
            thread = c[4]
            if addr >= start and addr < end:
                print('matching mprotect call %d : thread %d, start=0x%x, adjusted end=0x%x, prot=%d, length = %d' %
                      (index, thread, start, end, prot, length))
                if bt:
                    print(bt)
                if not get_all:
                    break

mprotect_tracker = None

command = """
define myst-prot
  if $argc == 4
      python mprotect_tracker.do_command("$arg0", $arg1, $arg2, $arg3)
  end
  if $argc == 3
      python mprotect_tracker.do_command("$arg0", $arg1, $arg2)
  end
  if $argc == 2
      python mprotect_tracker.do_command("$arg0", $arg1)
  end
  if $argc == 1
      python mprotect_tracker.do_command("$arg0")
  end
end
"""


if __name__ == "__main__":
    gdb.events.exited.connect(exit_handler)

    mprotect_tracker = myst_mprotect_tracker()

    with tempfile.NamedTemporaryFile('w') as f:
        f.write(command)
        f.flush()
        gdb.execute('source %s' % f.name)
    def exit_handler(event):
       global mprotect_tracker
       mprotect_tracker = None

