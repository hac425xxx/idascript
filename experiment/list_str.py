import imp
import idautils
import idaapi
import idc
import string



string_type_map = {
    0: "ASCSTR_C",  # C-string, zero terminated
    1: "ASCSTR_PASCAL",  # Pascal-style ASCII string (length byte)
    2: "ASCSTR_LEN2",  # Pascal-style, length is 2 bytes
    3: "ASCSTR_UNICODE",  # Unicode string
    4: "ASCSTR_LEN4",  # Delphi string, length is 4 bytes
    5: "ASCSTR_ULEN2",  # Pascal-style Unicode, length is 2 bytes
    6: "ASCSTR_ULEN4",  # Pascal-style Unicode, length is 4 bytes
}


def calc_str_percent(s):
    if len(s) == 0:
        return 0

    rs = string.ascii_letters + string.octdigits + "%, "
    c = 0
    for i in s:

        if i not in string.printable:
            return 0

        if i in rs:
            c += 1
    
    return c/len(s)



def main():


    # Do not use default set up, we'll call setup().
    s = idautils.Strings(default_setup=False)
    # we want C & Unicode strings, and *only* existing strings.
    s.setup(strtypes=[idaapi.STRTYPE_C], ignore_instructions=False,
            display_only_existing_strings=False)

    cnt = 0

    # loop through strings
    for i, v in enumerate(s):
        if not v:
            print("Failed to retrieve string at index {}".format(i))
        else:
            ds = str(v)
            ds = ds.strip()
            per = calc_str_percent(ds)

            if per > 0.8 and "wl" in ds:
                print("[{}] ea: {:#x} ; length: {}; '{}' per: {}".format(
                    i, v.ea, v.length, ds, per))
                
                cnt += 1
                idc.create_strlit(v.ea, idaapi.BADADDR)

    print("cnt:{}".format(cnt))

if __name__ == "__main__":
    main()
