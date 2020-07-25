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

    table_count, unk22, type_count, unk24, list_count, unk31, unk32, unk33, unk34, string_offset = \
        struct.unpack("<16x6x5H5H6x", f.read(48))
    logger.debug("table_count = {}".format(table_count))
    logger.debug("unk22 = 0x{:04x}".format(unk22))
    logger.debug("type_count = 0x{:04x}".format(type_count))
    logger.debug("unk24 = 0x{:04x}".format(unk24))
    logger.debug("list_count = 0x{:04x}".format(list_count))
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

    tmp_tables = []
    child_counts = []
    for i in range(table_count + type_count):
        name_crc, unk1, unk2, unk3, child_count, unk4 = struct.unpack("<I 2H 2H I", f.read(16))
        logger.debug(
            "col {:<30}: {:4x}, {:4x}, size: {}, has {} children, offset: {}."
            .format(strings_table[name_crc], unk1, unk2, unk3, child_count, unk4))
        flag = f.read(1)[0] # 1 if it has no child?
        if flag != (0 if child_count else 1):
            logger.warning("unexpected use of flag: (flag={}, children={})".format(flag, child_count))
        col = {"name": strings_table[name_crc],
               "unk1": unk1,
               "unk2": unk2,
               "size": unk3,
               "offset": unk4,
               "children": [],
               "flag": flag,
        }
        f.read(15)

        if child_count == 0:
            val = next((x for x in child_counts if x > 0))
            idx = child_counts.index(val)
            child_counts[idx] = val - 1
            tmp_tables[idx]["children"].append(col)
        else:
            child_counts.append(child_count)
            tmp_tables.append(col)
    tables = {x["name"]: x for x in tmp_tables}

    lists = {}
    for i in range(list_count):
        idx, unk, offset, size, count = struct.unpack("<2HIII", f.read(16))
        listname_crc = int.from_bytes(f.read(4), "little")
        lists[strings_table[listname_crc]] = {
            "index": idx,
            "name": strings_table[listname_crc],
            "unk": unk,
            "offset": offset,
            "size": size,
            "count": count,
        }
        if not ensure_allzero(f.read(12)):
            logger.warning("nonzero value found after list name id")

    con = sqlite3.connect(dbfile)

    # list-table relationship and unknown property for each types
    list_order = []
    list_table = {}
    for _ in range(list_count):
        list_order.append(strings_table[int.from_bytes(f.read(4), "little")])
    idx = 0
    for _ in range(type_count + table_count):
        name = strings_table[int.from_bytes(f.read(4), "little")]
        if name in tables:
            list_name = [x for x in lists.values() if x["index"] == idx][0]["name"]
            list_table[list_name] = name
            idx += 1
    for _ in range(list_count + type_count + table_count):
        # skip unknown values
        f.read(4)

    for list_name in list_order:
        table_name = list_table[list_name]

        # fetch list
        list_struct = lists[list_name]

        # fetch type name
        table_type = tables[table_name]

        logger.debug("list {} starts at 0x{:08x}".format(list_name, f.tell()))

        # get entry size and count from lists information
        size = list_struct["size"]
        count = list_struct["count"]

        # get table information
        columns = ", ".join("{} {}".format(c["name"], get_type(c["unk1"])[0]) for c in table_type["children"])

        con.execute("CREATE TABLE IF NOT EXISTS {} ({});".format(table_name, columns))

        # insert information
        for i in range(count):
            row_data = f.read(size)
            row_out = []
            for child in table_type["children"]:
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
            con.execute("INSERT INTO {} VALUES ({});".format(table_name, placeholder), row_out)
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
