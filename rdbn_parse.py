# coding: utf-8

__author__ = "nyantoge"
__version__ = "0.2"
__license__ = "MIT"

import struct
import binascii
import sqlite3

import logging
import logzero
from logzero import logger

def ensure_allzero(b):
    return all(map(lambda x: x == 0, b))

class DBType:
    def __init__(self, id_, subid, name):
        self.id_, self.subid = id_, subid
        self.name = sqlite3_safe(name)
        if id_ == 1:
            if subid == 3: # BOOL
                self.sqlite_type, self.data_size, self.signed = "INTEGER", 1, False
            elif subid in (4, 5, 6):
                self.sqlite_type, self.data_size, self.signed = "INTEGER", 2 ** (subid - 4), False
            elif subid in (8, 9, 0xA): # SIGNED
                self.sqlite_type, self.data_size, self.signed = "INTEGER", 2 ** (subid - 8), True
            elif subid == 0x0D:
                self.sqlite_type, self.data_size = "REAL", 4
            elif subid == 0x0F:
                self.sqlite_type, self.data_size, self.signed = "INTEGER", 4, False
            else:
                raise ValueError("type (0x{:02x}, 0x{:02x}) is not supported".format(id_, subid))
        elif id_ == 2: # array
            self.sqlite_type = "TEXT"
            if subid == 0: # integer?
                self.list_entry_type = int
            elif subid == 1: # integer?
                self.list_entry_type = int
            elif subid == 3: # Float array
                self.list_entry_type = float
            else:
                raise ValueError("type (0x{:02x}, 0x{:02x}) is not supported".format(id_, subid))
        elif id_ == 3: # ID and special types
            if subid == 0x0F: # ID
                self.sqlite_type, self.data_size, self.signed = "INTEGER", 4, False
            elif subid == 0x12: # float quadruple?
                self.sqlite_type, self.data_size = "TEXT", 16
            elif subid == 0x13: # (X, Y, Z, W) coordinate
                self.sqlite_type, self.data_size = "TEXT", 16
            elif subid == 0x14: # TEXT
                self.sqlite_type, self.data_size = "TEXT", 4
            elif subid == 0x15: # BLOB
                self.sqlite_type, self.data_size = "TEXT", 4
            else:
                raise ValueError("type (0x{:02x}, 0x{:02x}) is not supported".format(id_, subid))
        else:
            raise ValueError("type (0x{:02x}, 0x{:02x}) is not supported".format(id_, subid))

    def convert(self, data):
        if self.id_ == 2:
            count = len(data) // 4
            if len(data) % 4 != 0:
                logger.error("length must be multiple of 4, but {}".format(len(data)))
                return None
            if self.list_entry_type is int:
                return "[{}]".format(", ".join(str(x) for x in struct.unpack("<{}I".format(count), data)))
            if self.list_entry_type is float:
                return "[{}]".format(", ".join(str(x) for x in struct.unpack("<{}f".format(count), data)))
            logger.error("data of type ({:04x}, {:04x}) is not handled".format(
                self.id_, self.subid, self.size, len(data)))
            return None

        if self.data_size != len(data):
            logger.error("data of type (0x{:02x}, 0x{:02x}) is expected to be {} byte long, but {}".format(
                self.id_, self.subid, self.data_size, len(data)))
            return None
        if self.sqlite_type == "REAL":
            return struct.unpack("<f", data)[0]
        elif self.sqlite_type == "INTEGER":
            return int.from_bytes(data, "little", signed=self.signed)
        elif self.subid in (0x12, 0x13):
            return "[{:f}, {:f}, {:f}, {:f}]".format(*struct.unpack("<4f", data))
        elif self.subid in (0x14, 0x15):
            return int.from_bytes(data, "little")
        elif self.sqlite_type == "BLOB":
            return data
        logger.error("data of type (0x{:02x}, 0x{:02x}) is not handled".format(
            self.id_, self.subid, len(data)))
        return None

def sqlite3_safe(wd):
    if wd.upper() in ("ABORT", "ACTION", "ADD", "AFTER", "ALL",
                      "ALTER", "ALWAYS", "ANALYZE", "AND", "AS", "ASC", "ATTACH",
                      "AUTOINCREMENT", "BEFORE", "BEGIN", "BETWEEN", "BY", "CASCADE",
                      "CASE", "CAST", "CHECK", "COLLATE", "COLUMN", "COMMIT", "CONFLICT",
                      "CONSTRAINT", "CREATE", "CROSS", "CURRENT", "CURRENT_DATE",
                      "CURRENT_TIME", "CURRENT_TIMESTAMP", "DATABASE", "DEFAULT",
                      "DEFERRABLE", "DEFERRED", "DELETE", "DESC", "DETACH", "DISTINCT",
                      "DO", "DROP", "EACH", "ELSE", "END", "ESCAPE", "EXCEPT", "EXCLUDE",
                      "EXCLUSIVE", "EXISTS", "EXPLAIN", "FAIL", "FILTER", "FIRST",
                      "FOLLOWING", "FOR", "FOREIGN", "FROM", "FULL", "GENERATED", "GLOB",
                      "GROUP", "GROUPS", "HAVING", "IF", "IGNORE", "IMMEDIATE", "IN",
                      "INDEX", "INDEXED", "INITIALLY", "INNER", "INSERT", "INSTEAD",
                      "INTERSECT", "INTO", "IS", "ISNULL", "JOIN", "KEY", "LAST", "LEFT",
                      "LIKE", "LIMIT", "MATCH", "NATURAL", "NO", "NOT", "NOTHING",
                      "NOTNULL", "NULL", "NULLS", "OF", "OFFSET", "ON", "OR", "ORDER",
                      "OTHERS", "OUTER", "OVER", "PARTITION", "PLAN", "PRAGMA",
                      "PRECEDING", "PRIMARY", "QUERY", "RAISE", "RANGE", "RECURSIVE",
                      "REFERENCES", "REGEXP", "REINDEX", "RELEASE", "RENAME", "REPLACE",
                      "RESTRICT", "RIGHT", "ROLLBACK", "ROW", "ROWS", "SAVEPOINT",
                      "SELECT", "SET", "TABLE", "TEMP", "TEMPORARY", "THEN", "TIES", "TO",
                      "TRANSACTION", "TRIGGER", "UNBOUNDED", "UNION", "UNIQUE", "UPDATE",
                      "USING", "VACUUM", "VALUES", "VIEW", "VIRTUAL", "WHEN", "WHERE",
                      "WINDOW", "WITH", "WITHOUT", ):
        return wd + "_"
    return wd

def parse(f, dbfile):
    if f.read(4) != b"RDBN":
        logger.error("magic not found")
        return False

    data_offset, unk2, _, unk3, data_size = struct.unpack("<HHHHI", f.read(12))
    logger.debug("data_offset = 0x{:04x}".format(data_offset))
    logger.debug("unk2 = 0x{:04x}".format(unk2))
    logger.debug("data_size = 0x{:08x}".format(data_size))

    table_count, unk22, type_count, unk24, list_count, unk31, unk32, unk33, unk34, string_offset = \
        struct.unpack("<16x6x5H4HI4x", f.read(48))
    logger.debug("table_count = {}".format(table_count))
    logger.debug("unk22 = 0x{:04x}".format(unk22))
    logger.debug("type_count = 0x{:04x}".format(type_count))
    logger.debug("unk24 = 0x{:04x}".format(unk24))
    logger.debug("list_count = 0x{:04x}".format(list_count))
    logger.debug("unk31 = 0x{:04x}".format(unk31))
    logger.debug("unk32 = 0x{:04x}".format(unk32))
    logger.debug("unk33 = 0x{:04x}".format(unk33))
    logger.debug("unk34 = 0x{:04x}".format(unk34))
    logger.debug("string_offset = 0x{:04x}".format(string_offset))

    f.seek(data_offset + string_offset)
    strings = f.read()
    strings_table = {}
    for i in strings.rstrip(b"\0").split(b"\0"):
        strings_table[binascii.crc32(i)] = i.decode()

    f.seek(data_offset)

    tmp_tables = []
    tmp_children = []
    nondata_strings = []
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
               "child_count": child_count,
               "offset": unk4,
               "children": [],
               "flag": flag,
        }
        nondata_strings.append(col["name"])
        f.read(15)

        if child_count == 0:
            tmp_children.append(col)
        else:
            tmp_tables.append(col)
    for t in tmp_tables:
        for i in range(t["size"], t["size"] + t["child_count"]):
            t["children"].append(tmp_children[i])
    tables = {x["name"]: x for x in tmp_tables}

    lists = {}
    for i in range(list_count):
        idx, unk, offset, size, count = struct.unpack("<2HIII", f.read(16))
        listname_crc = int.from_bytes(f.read(4), "little")
        nondata_strings.append(strings_table[listname_crc])
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

    for l in lists:
        logger.debug(lists[l])

    con = sqlite3.connect(dbfile)

    # list-table relationship and unknown property for each types
    list_order = []
    list_table = {}
    for _ in range(list_count):
        list_order.append(strings_table[int.from_bytes(f.read(4), "little")])
    idx = 0
    table_names = []
    for _ in range(type_count + table_count):
        name = strings_table[int.from_bytes(f.read(4), "little")]
        if name in tables:
            table_names.append(name)
    for l in lists:
        list_table[l] = table_names[lists[l]["index"]]
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

        # type convertors
        convertors = [DBType(c["unk2"], c["unk1"], c["name"]) for c in table_type["children"]]

        # get table information
        columns = ", ".join("{} {}".format(c.name, c.sqlite_type) for c in convertors)

        con.execute("CREATE TABLE IF NOT EXISTS {} ({});".format(table_name, columns))

        # insert information
        for i in range(count):
            row_data = f.read(size)
            row_out = []
            for child, conv in zip(table_type["children"], convertors):
                data = row_data[child["offset"]:child["offset"]+child["size"]]
                if conv.id_ == 3 and conv.subid in (0x14, 0x15):
                    addr = conv.convert(data)
                    if isinstance(addr, str):
                        print("str", addr)
                    if addr != 0 and addr != 0xFFFFFFFF and addr < len(strings):
                        # TODO: more accurate string offset detection
                        s = strings[addr:].split(b"\0")[0].decode()
                        if strings[addr - 1] != 0:
                            data = "[{:08x}]".format(addr)
                        elif s in nondata_strings:
                            data = "[{:08x}]".format(addr)
                        else: # OK
                            data = s
                    else:
                        data = "[{:08x}]".format(addr)
                else:
                    data = conv.convert(data)
                row_out.append(data)
            placeholder = ", ".join("?" * len(row_out))
            con.execute("INSERT INTO {} VALUES ({});".format(table_name, placeholder), row_out)
        logger.debug("list {} ends at 0x{:08x}".format(list_name, f.tell()))

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
