#!/usr/bin/env python3
# exports.py -- dump exports of pe file
# Efe C. <efe@efe.lol>, 2022-09

import os, sys, struct


class dotteddict(dict):
    __getattr__ = dict.get
    __setattr__ = dict.__setitem__
    __delattr__ = dict.__delitem__


def exports(filename):
    f = open(filename, "rb")
    # parse DOS header, only get magic and nt header pointer
    doshdr = struct.unpack("<H58sL", f.read(64))

    if doshdr[0] != 0x5A4D:
        raise Exception("not a PE file")

    f.seek(doshdr[-1]) # seek to nt header
    # check signature
    if f.read(4) != b"PE\0\0":
        raise Exception("malformed file")

    # parse file header
    filehdr = struct.unpack("<2H3L2H", f.read(20))
    nsects = filehdr[1]
    opthdrlen = filehdr[-2]

    magic = f.read(2)
    peplus = True
    if magic != b"\x0b\x02":
        peplus = False

    f.read(22 if peplus else 26) # skip standard fields
    f.read(84 if peplus else 64) # skip windows specific fields
    nrvas = struct.unpack("<L", f.read(4))[0] # number of RVAs and sizes

    # get export table virtual address and size
    expva, expsz = struct.unpack("<LL", f.read(8))

    f.seek(doshdr[-1] + 4 + 20 + opthdrlen) # skip optional header

    sections = list()
    sect = None
    for i in range(nsects):
        hdr = dotteddict(zip(
            ("Name", "VirtualSize", "VirtualAddress", "SizeOfRawData",
             "PointerToRawData", "Useless"),
            struct.unpack("<8s4L16s", f.read(40))
        ))

        sections.append(hdr)
        if (expva >= hdr.VirtualAddress and
            expva < hdr.SizeOfRawData + hdr.VirtualAddress):
            sect = hdr

    assert sect is not None
    sys.stderr.write("containing section: " + sect.Name.strip(b"\0").decode())
    # print("          position:",
    #       expva - sect.VirtualAddress + sect.PointerToRawData)

    f.seek(expva - sect.VirtualAddress + sect.PointerToRawData)
    expdirtab = dotteddict(zip(
        ("Useless", "NameRVA", "OrdinalBase", "AddressTableEntries",
         "NumberOfNamePointers", "ExportAddressTableRVA", "NamePointerRVA",
         "OrdinalTableRVA"),
        struct.unpack("<12s7L", f.read(40))
    ))

    container = None
    for sect in sections:
        if (expdirtab.NamePointerRVA > sect.VirtualAddress and
            expdirtab.NamePointerRVA < sect.VirtualAddress +
            sect.SizeOfRawData):
            container = sect

    assert container is not None
    nametab = expdirtab.NamePointerRVA - container.VirtualAddress + \
        container.PointerToRawData
    f.seek(nametab)

    addresses = list()
    for i in range(expdirtab.NumberOfNamePointers):
        addresses.append(struct.unpack("<L", f.read(4))[0])

    for address in addresses:
        container = None
        for sect in sections:
            if (address > sect.VirtualAddress and
                address < sect.VirtualAddress + sect.SizeOfRawData):
                container = sect

        name = address - container.VirtualAddress + container.PointerToRawData
        oldpos = f.tell()
        f.seek(name)

        ch = f.read(1)
        ascname = b""
        while ch != b"\0" and ch != b"":
            ascname += ch
            ch = f.read(1)
        print(ascname.decode())

        f.seek(oldpos)

    f.close()


if __name__ == "__main__":
    if len(sys.argv) == 2:
        exports(sys.argv[1])
    else:
        print("usage:", sys.argv[0], "FILE")
