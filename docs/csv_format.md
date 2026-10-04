# Export and pairing table formats (format_version 3)

The CSV files are UTF-8 (RFC 4180) with a header row. Cells that hold a list contain a
JSON array. Addresses are Ghidra address strings without the address space prefix
(`00401000`) and mean something only within their own build.

`ghidra_scripts/ExportMatchData.java` writes the exports and `src/ghidra_matching/model.py`
reads them. When the format changes, update both files and this one, and raise
`FORMAT_VERSION` in both code files.

Version 2 added `name_source` and `signature_source` to functions and `name_source` and
`custom_type` to data, so that your markup can be told apart from names that came from
analysis, imports or debug info. Version 3 added code entries (`defined` = 0),
`head_size`, `head_hash` and `string_args`. Older files can still be paired. In version 1
files every non-default name counts as user markup; version 2 files have no code entries,
so functions that only a table points to may stay unpaired.

The source columns hold Ghidra's `SourceType` names: `DEFAULT` (`FUN_…`, `DAT_…`),
`ANALYSIS` (`switchD_…`, `caseD_…`, RTTI labels), `AI`, `IMPORTED` (symbols, PDB or DWARF
information, imports) and `USER_DEFINED`.

## `<label>.functions.csv`

| Column | Type | Meaning |
|--------|------|---------|
| `address` | addr | function entry point |
| `name` | str | function name (`FUN_...` if unnamed) |
| `namespace` | str | full parent namespace (`Foo::Bar`), empty for global |
| `is_default_name` | 0/1 | 1 if the name is Ghidra's default (no markup). Thunks inherit this from the function they thunk to. |
| `is_thunk` | 0/1 | Ghidra thunk function |
| `size` | int | number of addresses in the function body |
| `insn_count` | int | number of instructions |
| `mnemonic_hash` | hex | first 16 hex digits of a SHA-1 over the instruction mnemonics in address order; unaffected by relocation, changed by any code change |
| `vtable_slots` | JSON `[[vtable_addr, slot], ...]` | every vtable or function-pointer table entry that points at this function |
| `string_refs` | JSON `[str, ...]` | strings referenced directly or through one pointer, in order of first use, without duplicates, each cut to 1024 characters |
| `callees` | JSON `[addr \| "EXT:name", ...]` | called functions and functions whose address is taken, in order of first use; imported functions appear as `EXT:<name>` |
| `data_refs` | JSON `[addr, ...]` | referenced data in non-executable memory (the start of the containing data item), in order of first use |
| `name_source` | SourceType | who set the name; for a thunk, who set the name of the function it thunks to |
| `signature_source` | SourceType | who set the signature |
| `defined` | 0/1 | 1 for a Ghidra function; 0 for a code entry, see below |
| `head_size`, `head_hash` | int, hex | size and mnemonic hash of the code from the entry up to the first instruction without fallthrough (return or unconditional jump); read the same way for functions and code entries, so the two can be compared |
| `string_args` | JSON `[[str, int], ...]` | strings and small constants (1 to 99,999) passed to the same call, for example the file path and line of `errorContext("expr", "D:\…\File.cpp", 0x9d)` |

A code entry is an address that a vtable or function-pointer table points to, where
Ghidra has no function: an instruction that is not inside any function. Many virtual
methods look like this because nothing calls them directly. Its row has `defined` = 0, a
`LAB_…` name unless the address has a label, and size, hash and references covering the
instructions from the entry up to the first return or jump. `ApplyMatchTable.java` creates
the function when it applies markup to one.

## `<label>.data.csv`

| Column | Type | Meaning |
|--------|------|---------|
| `address` | addr | start of the item |
| `name` | str | primary label (`DAT_…`, `s_…` and similar when it is a default label) |
| `namespace` | str | full parent namespace |
| `is_default_name` | 0/1 | 1 if the label is a default (dynamic) one |
| `kind` | `vtable` \| `string` \| `data` | see below |
| `datatype` | str | data type path (`/MyTypes/Config`), empty if undefined |
| `size` | int | length of the defined data, 0 if undefined |
| `value` | JSON str | string value for `kind=string`, otherwise empty |
| `slots` | JSON `[addr, ...]` | for `kind=vtable`: function entries in slot order |
| `referenced_by` | JSON `[addr, ...]` | functions that reference this item |
| `name_source` | SourceType | who set the label |
| `custom_type` | 0/1 | 1 if the data type is a structure, union, enum, typedef or function definition, or an array of or pointer to one |

There is a row for each detected vtable, each defined string, each data item with a
custom type, each data address referenced from a function, and each labelled address in
non-executable memory.

A vtable is any run of pointer-sized, aligned values in non-executable initialised memory
that all point to code: function entries, or instructions outside any function (code
entries). The run has to start at an address that is referenced or labelled, has to
contain at least one function entry, and ends early at any slot that is itself
referenced. This
finds MSVC and Itanium vtables as well as other tables of function pointers. For the
Itanium ABI the vtable address is that of the first function slot (`_ZTV… + 2 * pointer
size`), which is the address constructors store.

## `<label>.meta.json`

`format_version`, `label`, `program_name`, `project_path`, `executable_path`,
`executable_md5`, `executable_sha256`, `image_base`, `language`, `compiler_spec`,
`pointer_size`, `ghidra_version`, `exported_at`, `function_count`, `data_count`,
`vtable_count`.

## Pairing table (`ghidra-match pair -o ...`)

| Column | Meaning |
|--------|---------|
| `kind` | `function` or `data` |
| `source_address` | address in the build that has the markup |
| `target_address` | address in the build that receives it |
| `source_name`, `target_name` | full names at export time, for reading only |
| `method` | the step that found the pair: `name`, `string_set`, `unique_string`, `body_hash`, `string_value`, `string_args`, `vtable_votes`, `vtable_slot`, `callgraph`, `data_ref`, `data_referrer`, `source_order` or `neighbor` |
| `confidence` | 0 to 1. Anchors have fixed values; a propagated pair gets its parent's confidence times a factor below 1. |
| `markup` | what will be transferred, joined with `+`: `name` and `signature` for functions, `label` and `datatype` for data |

By default the table has only rows with something in `markup`: functions whose name or
signature a user set, and data whose label a user set. `--all` writes every pair, which
`ghidra-match eval` needs.

`ApplyMatchTable.java` reads `kind`, `source_address`, `target_address` and `confidence`.
You can edit the table before applying it, for example to delete a wrong row or add a pair
you know.

## Contenders (`ghidra-match pair --contenders ...`)

One row per contender; rows of one source function share the first five columns.

| Column | Meaning |
|--------|---------|
| `source_address`, `source_name` | the marked-up function in the source build |
| `status` | `unmatched`, or `low_confidence` when paired below `--contender-threshold` |
| `paired_target`, `paired_confidence` | the current pair, if any |
| `rank` | 0 for the current pair, then 1, 2, … by score |
| `contender_address`, `contender_name` | a possible partner in the target build |
| `score` | 0 to 1; a sum of weighted features (identical code 0.35 or identical start 0.15, size up to 0.1, shared strings up to 0.2, shared call arguments up to 0.15, paired callees and callers up to 0.1 each, closeness to the expected position up to 0.15, ambiguous matcher candidate 0.1) |
| `reasons` | the features that contributed, readable |
| `contender_paired_with` | the source function this contender is already paired with, if any |

A row with `reasons` = `no contenders found` means nothing scored at least 0.15.

