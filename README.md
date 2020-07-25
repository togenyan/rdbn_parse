# rdbn_parse

Parse resource files in "RDBN" format (*.cfg.bin files with magic header "RDBN").

## Usage

You need logzero library to run the script.

    python ./rdbn_parse.py [--verbose] <infile> <dbfile>

- infile: input file.
- dbfile: SQLite3 Database file. If the specified file does not exist, the script creates a new one.

## Development status

Currently in early alpha. Only supports fundamental structures of RDBN format.

## License

MIT
