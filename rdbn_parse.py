# coding: utf-8

__author__ = "nyantoge"
__version__ = "0.3"
__license__ = "MIT"

import binascii
import math
import struct
import sqlite3
from dataclasses import dataclass
from io import FileIO
from pathlib import Path
from typing import Any, Callable, Dict, List, Literal, Optional, Type, Union

import logging
import logzero
from logzero import logger

def ensure_allzero(b: bytes):
    return all(map(lambda x: x == 0, b))


class DBType:
    id: int
    subid: int
    name: str
    sqlite_type: Literal["INTEGER", "REAL", "TEXT", "BLOB"]
    list_entry_type: Type[Any]
    signed: bool

    def __init__(self, _id: int, _subid: int, _name: str):
        self.id = _id
        self.subid = _subid
        self.name = sqlite3_safe(_name)

        if self.id == 1:
            if self.subid == 3:  # bool
                self.sqlite_type, self.signed = "INTEGER", False
            elif self.subid in (4, 5, 6):  # unsigned int
                self.sqlite_type, self.signed = "INTEGER", False
            elif self.subid in (8, 9, 0xA):  # signed int
                self.sqlite_type, self.signed = "INTEGER", True
            elif self.subid == 0x0D:
                self.sqlite_type = "REAL"
            elif self.subid == 0x0F:
                self.sqlite_type, self.signed = "INTEGER", False
            else:
                raise ValueError("type (0x{:02x}, 0x{:02x}) is not supported".format(self.id, self.subid))
        elif self.id == 2:
            # composite value
            #   length: column.size // 4
            #   total size: column.count
            self.sqlite_type = "TEXT"
            if self.subid == 0: # integer?
                self.list_entry_type = int
            elif self.subid == 1: # integer?
                self.list_entry_type = int
            elif self.subid == 3: # Float array
                self.list_entry_type = float
            else:
                raise ValueError("type (0x{:02x}, 0x{:02x}) is not supported".format(self.id, self.subid))
        elif self.id == 3: # ID and special types
            if self.subid == 0x0F: # ID
                self.sqlite_type, self.signed = "INTEGER", False
            elif self.subid == 0x12: # float quadruple?
                self.sqlite_type = "TEXT"
            elif self.subid == 0x13: # (X, Y, Z, W) coordinate
                self.sqlite_type = "TEXT"
            elif self.subid == 0x14: # TEXT
                self.sqlite_type = "TEXT"
            elif self.subid == 0x15: # BLOB
                self.sqlite_type = "TEXT"
            else:
                raise ValueError("type (0x{:02x}, 0x{:02x}) is not supported".format(self.id, self.subid))
        else:
            raise ValueError("type (0x{:02x}, 0x{:02x}) is not supported".format(self.id, self.subid))

    def convert(self, data: bytes) -> Optional[Union[str, int, bytes]]:
        if self.id == 2:
            count = len(data) // 4
            if len(data) % 4 != 0:
                logger.error("length must be multiple of 4, but {}".format(len(data)))
                return None
            if self.list_entry_type is int:
                return "[{}]".format(", ".join(str(x) for x in struct.unpack("<{}I".format(count), data)))
            if self.list_entry_type is float:
                return "[{}]".format(", ".join(str(x) for x in struct.unpack("<{}f".format(count), data)))
            logger.error("data of type ({:04x}, {:04x}) is not handled".format(
                self.id, self.subid))
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
            self.id, self.subid))
        return None

def sqlite3_safe(wd: str) -> str:
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


@dataclass(frozen=True)
class RDBNHeader:
    magic: bytes
    header_size: int
    unk1: int
    zero: int
    item_size: int  # 0x14. (beware of alignment)
    data_size: int  # header_size + data_size == file size
    pad1: bytes
    table_count: int
    unk2: int
    column_count: int  # columns, including dups
    unk3: int
    list_count: int
    id_name_table_size: int  # should be 2 * 4 * (table_count + list_count + column_count)
    unk4: int
    item_count: int  # list + table + column
    unk5: int
    body_size: int  # header_size + body_size + string_table_size == file size
    pad2: bytes

    @property
    def item_data_size(self):
        return math.ceil(self.item_size / 16) * 16

    def __post_init__(self):
        if self.magic != b"RDBN":
            logger.warning("[{}] magic should be b\"RDBN\"".format(
                self.__class__.__name__,
            ))
        logger.info("[{}] unknown values: {:04x}, {:04x}, {:04x}, {:04x}".format(
            self.__class__.__name__,
            self.unk1,
            self.unk2,
            self.unk3,
            self.unk4,
        ))
        if self.zero != 0:
            logger.warning("[{}] zero should be zero".format(
                self.__class__.__name__,
            ))
        if self.item_size != 0x14:
            logger.warning("[{}] item_size should be 0x14".format(
                self.__class__.__name__,
            ))
        if self.item_count != self.table_count + self.list_count + self.column_count:
            logger.warning("[{}] item_count should be {} but {}".format(
                self.__class__.__name__,
                self.table_count + self.list_count + self.column_count,
                self.item_count,
            ))
        expected = 2 * 4 * (self.table_count + self.list_count + self.column_count)
        if self.id_name_table_size != expected:
            logger.warning("[{}] id_name_table_size should be 0x{:04x} but {:04x}".format(
                self.__class__.__name__,
                expected, self.id_name_table_size
            ))
        if not ensure_allzero(self.pad1):
            logger.warning("[{}] pad1 should be all-zero".format(
                self.__class__.__name__,
            ))
        if not ensure_allzero(self.pad2):
            logger.warning("[{}] pad2 should be all-zero".format(
                self.__class__.__name__,
            ))


@dataclass(frozen=True)
class Item:
    id: int
    name: str


@dataclass(frozen=True)
class Column(Item):
    typeid: int
    sub_typeid: int
    size: int  # size per data
    offset: int
    unk: int  # 1 for non-array data


@dataclass(frozen=True)
class Table(Item):
    unk1: int
    col_offset: int
    col_count: int
    zero1: int
    zero2: int
    columns: List[Column]
    def __post_init__(self):
        logger.info("[{}] unknown values: {:08x}".format(
            self.__class__.__name__,
            self.unk1,
        ))
        if self.zero1 != 0:
            logger.warning("[{}] zero1 should be zero".format(
                self.__class__.__name__,
            ))
        if self.zero2 != 0:
            logger.warning("[{}] zero2 should be zero".format(
                self.__class__.__name__,
            ))


@dataclass(frozen=True)
class DataList(Item):
    index: int
    unk: int
    offset: int
    size: int
    count: int


def parse_header(data: bytes) -> RDBNHeader:
    magic = data[:4]
    values = struct.unpack(
        "<HHHHI 22s HHHHH HHHHI 20s", data[4:])
    return RDBNHeader(
        magic=magic,
        header_size=values[0],
        unk1=values[1],
        zero=values[2],
        item_size=values[3],
        data_size=values[4],
        pad1=values[5],
        table_count=values[6],
        unk2=values[7],
        column_count=values[8],
        unk3=values[9],
        list_count=values[10],
        id_name_table_size=values[11],
        unk4=values[12],
        item_count=values[13],
        unk5=values[14],
        body_size=values[15],
        pad2=values[16],
    )


def parse(f: FileIO, dbfile: str, use_prefix: bool=False) -> bool:
    prefix = "".join(c for c in Path(str(f.name)).name.replace(".cfg.bin", "").upper()
                     if "A" <= c <= "Z" or "0" <= c <= "9" or c == "_")
    prefix += "_"

    magic = f.read(4)
    if magic != b"RDBN":
        logger.error("magic not found")
        return False

    header_size = int.from_bytes(f.read(2), "little")
    if header_size != 0x50:
        logger.error("header must be 50 byte long")
        return False
    f.seek(0)
    header = parse_header(f.read(header_size))

    logger.debug(header)

    f.seek(header.header_size + header.body_size)
    strings = f.read()
    strings_table: Dict[int, str] = {}
    for i in strings.rstrip(b"\0").split(b"\0"):
        strings_table[binascii.crc32(i)] = i.decode()

    f.seek(header.header_size)

    tmp_tables: List[Table] = []
    nondata_strings: List[str] = []
    for i in range(header.table_count):
        name_crc, unk1, col_offset, col_count, zero1, zero2 = struct.unpack("<2I 2H II", f.read(header.item_size))
        f.read(header.item_data_size - header.item_size)
        table = Table(
            id=name_crc,
            name=strings_table[name_crc],
            unk1=unk1,
            col_offset=col_offset,
            col_count=col_count,
            zero1=zero1,
            zero2=zero2,
            columns=[],
        )
        logger.debug(table)
        nondata_strings.append(table.name)
        tmp_tables.append(table)

    tmp_columns: List[Column] = []
    for i in range(header.column_count):
        name_crc, subid, id, size, offset, unk = struct.unpack("<I 2H 2I I", f.read(header.item_size))
        f.read(header.item_data_size - header.item_size)
        col = Column(
            id=name_crc,
            name=strings_table[name_crc],
            typeid=id,
            sub_typeid=subid,
            size=size,
            offset=offset,
            unk=unk,
        )
        logger.debug(col)
        nondata_strings.append(col.name)
        tmp_columns.append(col)
    columns = {x.name: x for x in tmp_columns}

    # table-column relationships
    for t in tmp_tables:
        for i in range(t.col_offset, t.col_offset + t.col_count):
            t.columns.append(tmp_columns[i])
        logger.debug("table {} consists of columns {}".format(
            t.name, [c.name for c in t.columns]
        ))

    tables = {x.name: x for x in tmp_tables}

    tmp_lists: List[DataList] = []
    lists: Dict[str, DataList] = {}
    for i in range(header.list_count):
        idx, unk, offset, size, count, listname_crc = struct.unpack("<2HIIII", f.read(header.item_size))
        f.read(header.item_data_size - header.item_size)
        nondata_strings.append(strings_table[listname_crc])
        list_ = DataList(
            id=listname_crc,
            index=idx,
            name=strings_table[listname_crc],
            unk=unk,
            offset=offset,
            size=size,
            count=count,
        )
        tmp_lists.append(list_)
        logger.debug(list_)
    lists = {x.name: x for x in tmp_lists}

    con = sqlite3.connect(dbfile)

    # list-table relationship
    list_table: Dict[str, str] = {}  # list_name -> table_name
    for l in lists.values():
        table_cand = next((t.name for idx, t in enumerate(tmp_tables) if idx == l.index), None)
        if table_cand is None:
            logger.warning("table for list {} not found".format(l))
            return False
        list_table[l.name] = table_cand
        logger.debug("list {} is a list for tabel {}".format(
            l.name, table_cand
        ))

    # list, table, and column ids <-> string table offset relations
    # --
    # All item ids I have discovered so far equals to the crc32 of item names.
    # So this relation is not necessarily required.
    ids = [int.from_bytes(f.read(4), "little") for _ in range(header.id_name_table_size // 8)]
    name_offsets = [int.from_bytes(f.read(4), "little") for _ in range(header.id_name_table_size // 8)]
    all_items: Dict[int, str] = {i.id: i.name for i in lists.values()}
    all_items.update({i.id: i.name for i in tables.values()})
    all_items.update({i.id: i.name for i in columns.values()})
    for id, name_offset in zip(ids, name_offsets):
        name = all_items.get(id, None)
        if name is None:
            logger.warning("id (crc32 of name) {} is not recorded, but found in id-name table".format(id))
            continue
        name_ = strings[name_offset:].split(b"\0")[0].decode()
        if name != name_:
            logger.warning("name for id {} should be {} but {}".format(
                id, name_, name
            ))

    list_sorter: Callable[[DataList], int] = lambda l: l.offset
    for l in sorted(lists.values(), key=list_sorter):
        f.seek(
            header.header_size +
            header.item_data_size * (header.table_count + header.column_count + header.list_count) +
            header.id_name_table_size +
            l.offset
        )
        table_name = list_table[l.name]
        table_name_sql = table_name if not use_prefix else (prefix + table_name)

        # fetch type name
        table_type = tables[table_name]

        logger.debug("list {} starts at 0x{:08x}".format(l.name, f.tell()))

        # type convertors
        convertors = [DBType(c.typeid, c.sub_typeid, c.name) for c in table_type.columns]

        # get table information
        columns = ", ".join("{} {}".format(c.name, c.sqlite_type) for c in convertors)
        columns += ", unused_data TEXT"

        con.execute("CREATE TABLE IF NOT EXISTS {} ({});".format(table_name_sql, columns))

        # insert information
        for i in range(l.count):
            row_data = f.read(l.size)
            row_out: List[Optional[Union[str, int, bytes]]] = []
            last_pos = 0
            for col, conv in zip(table_type.columns, convertors):
                if i == 0 and last_pos != col.offset:
                    logger.debug("data reading jumps from {} to {}".format(last_pos, col.offset))
                last_pos = col.offset + col.size
                data = row_data[col.offset:col.offset+col.size]
                if conv.id == 3 and conv.subid in (0x14, 0x15):
                    addr = conv.convert(data)
                    assert isinstance(addr, int)
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
            if i == 0 and last_pos != l.size:
                logger.debug("data reading ends at {}, leaving {} byte unread".format(last_pos, l.size - last_pos))
                logger.debug("unread data (only the first row will be shown): {}".format(row_data[last_pos:]))
            placeholder = ", ".join("?" * (len(row_out) + 1))
            con.execute("INSERT INTO {} VALUES ({});".format(table_name_sql, placeholder),
                        row_out + [binascii.b2a_hex(row_data[last_pos:]).decode()])
        logger.debug("list {} ends at 0x{:08x}".format(l.name, f.tell()))

    con.commit()
    con.close()
    logger.debug("proccessing finished at 0x{:08x}".format(f.tell()))
    if f.tell() != header.header_size + header.body_size:
        logger.warning("data parsing finished at 0x{:08x}, but the data seems ends at {:08x}".format(
            f.tell(),
            header.header_size + header.body_size,
        ))
    return True

def main():
    import sys
    import argparse
    parser = argparse.ArgumentParser()
    parser.add_argument("file", type=argparse.FileType("rb"))
    parser.add_argument("dbfile")
    parser.add_argument("--verbose", action="store_true")
    parser.add_argument("--with-prefix", action="store_true")
    args = parser.parse_args()
    logzero.loglevel(logging.WARN)
    if args.verbose:
        logzero.loglevel(logging.DEBUG)
    if parse(args.file, args.dbfile, use_prefix=args.with_prefix):
        sys.exit(1)
    sys.exit(0)

if __name__ == "__main__":
    main()
