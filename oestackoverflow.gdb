# Break early enough in oe if RSP lies outside oe stack.
# oe stack starts 1 page below tcs.
# oe stack ends 2 pages below stack start since Mystikos
# uses 2 pages of oe stack.
b __oe_handle_main if !((uint64_t)$rsp > ((uint64_t)tcs - 4096 - 2*4096))

# Most likely this ought to get hit for an ocall return
