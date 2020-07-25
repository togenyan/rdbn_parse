# coding: utf-8

__author__ = "nyantoge"
__version__ = "0.1"
__license__ = "MIT"

import struct
import binascii
import sqlite3

import logging
import logzero
from logzero import logger

def ensure_allzero(b):
    return all(map(lambda x: x == 0, b))

def get_type(id_):
    if id_ == 3: # BOOL
        return ("INTEGER", 1)
    if id_ in (4, 5, 6):
        return ("INTEGER", 2 ** (id_ - 4))
    if id_ == 0x0F:
        return ("INTEGER", 4)
    if id_ == 0x14:
        return ("TEXT", 4)
    if id_ == 0x15:
        return ("TEXT", 4) # TODO: BLOB
    return None

def parse(f, dbfile):
    if f.read(4) != b"RDBN":
        logger.error("magic not found")
        return False

    data_offset, unk2, _, unk3, data_size = struct.unpack("<HHHHI", f.read(12))
    logger.debug("data_offset = 0x{:04x}".format(data_offset))
    logger.debug("unk2 = 0x{:04x}".format(unk2))
    logger.debug("data_size = 0x{:08x}".format(data_size))

    table_count, unk22, unk23, unk24, unk25, unk31, unk32, unk33, unk34, string_offset = \
        struct.unpack("<16x6x5H5H6x", f.read(48))
    logger.debug("table_count = {}".format(table_count))
    logger.debug("unk22 = 0x{:04x}".format(unk22))
    logger.debug("unk23 = 0x{:04x}".format(unk23))
    logger.debug("unk24 = 0x{:04x}".format(unk24))
    logger.debug("unk25 = 0x{:04x}".format(unk25))
    logger.debug("unk31 = 0x{:04x}".format(unk31))
    logger.debug("unk32 = 0x{:04x}".format(unk32))
    logger.debug("unk33 = 0x{:04x}".format(unk33))
    logger.debug("unk34 = 0x{:04x}".format(unk34))

    f.seek(data_offset + string_offset)
    strings = f.read()
    strings_table = {}
    for i in strings.rstrip(b"\0").split(b"\0"):
        strings_table[binascii.crc32(i)] = i.decode()

    f.seek(data_offset)

    tables = []
    child_counts = []

    while True:
        name_crc, unk1, unk2, unk3, child_count, unk4 = struct.unpack("<I 2H 2H I", f.read(16))
        logger.debug(
            "col {:<30}: {:4x}, {:4x}, size: {}, has {} children, offset: {}."
            .format(strings_table[name_crc], unk1, unk2, unk3, child_count, unk4))

        col = {"name": strings_table[name_crc],
               "unk1": unk1,
               "unk2": unk2,
               "size": unk3,
               "offset": unk4,
               "children": []
        }
        flag = f.read(1)[0] # 1 if it has no child?
        if flag != (0 if child_count else 1):
            logger.warning("unexpected use of flag: (flag={}, children={})".format(flag, child_count))

        if child_count:
            tables.append(col)
            child_counts.append(child_count)
        else:
            # child node
            v = next((c for c in child_counts if c > 0), None)
            if not v:
                logger.error("no parent found")
                return False
            tables[child_counts.index(v)]["children"].append(col)
            child_counts[child_counts.index(v)] = v - 1
        f.read(15)
        if sum(child_counts) == 0:
            break

    if table_count != len(tables):
        logger.warning("incorrect table count")

    lists = {}
    for i in range(table_count):
        idx, unk, offset, size, count = struct.unpack("<2HIII", f.read(16))
        listname_crc = int.from_bytes(f.read(4), "little")
        lists[strings_table[listname_crc]] = {
            "unk": unk,
            "offset": offset,
            "size": size,
            "count": count,
        }
        if not ensure_allzero(f.read(12)):
            logger.warning("nonzero value found after list name id")

    tmp = []
    keylist = []
    for i in range(table_count * 2 + sum(len(x["children"]) for x in tables)):
        tmp.append(strings_table[int.from_bytes(f.read(4), "little")])
    for i in tmp:
        keylist.append((i, int.from_bytes(f.read(4), "little")))
    logger.debug("end: 0x{:04x}".format(f.tell()))

    con = sqlite3.connect(dbfile)

    keylist_table = keylist[:table_count]
    keylist = keylist[table_count:]
    while keylist:
        # fetch list name
        lname = keylist_table.pop(0)

        # table name
        tname = keylist.pop(0)

        # get entry size and count from lists information
        size = lists[lname[0]]["size"]
        count = lists[lname[0]]["count"]

        # get table information
        structure = [x for x in tables if x["name"] == tname[0]][0]
        columns = ", ".join("{} {}".format(x["name"], get_type(x["unk1"])[0]) for x in structure["children"])
        con.execute("CREATE TABLE IF NOT EXISTS {} ({});".format(structure["name"], columns))

        # TODO: skip entries
        # these data should contain metadata on columns
        for i in structure["children"]:
            keylist.pop(0)

        # insert information
        for i in range(count):
            row_data = f.read(size)
            row_out = []
            for child in structure["children"]:
                type_ = get_type(child["unk1"])
                if type_ is None:
                    logger.error("unknown data type {} (size: {})".format(child["unk1"], child["size"]))
                    return False
                if child["size"] != type_[1]:
                    logger.error("type {} is {} byte long, but {} found".format(
                        child["unk1"], type_[1], child["size"]))
                    return False
                data = int.from_bytes(row_data[child["offset"]:child["offset"]+child["size"]], "little")
                if type_[0] == "TEXT":
                    row_out.append("[{:08X}]".format(data))
                else:
                    row_out.append(data)
            placeholder = ", ".join("?" * len(row_out))
            con.execute("INSERT INTO {} VALUES ({});".format(structure["name"], placeholder), row_out)
    con.commit()
    con.close()
    logger.debug("proccessing finished at 0x{:08x}".format(f.tell()))
    return True

def main():
    import sys
    import argparse
    parser = argparse.ArgumentParser()
    parser.add_argument("file", type=argparse.FileType("rb"))
    parser.add_argument("dbfile")
    parser.add_argument("--verbose", action="store_true")
    args = parser.parse_args()
    logzero.loglevel(logging.WARN)
    if args.verbose:
        logzero.loglevel(logging.DEBUG)
    if parse(args.file, args.dbfile):
        sys.exit(1)
    sys.exit(0)

if __name__ == "__main__":
    main()
