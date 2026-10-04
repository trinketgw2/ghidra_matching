// Exports the per-build matching data used by ghidra_matching:
//   <label>.functions.csv  one row per function (address, size, vtable slots, string refs, ...)
//   <label>.data.csv       one row per string / vtable / referenced or labelled global
//   <label>.meta.json      program metadata (image base, language, hashes, Ghidra version)
//
// Headless:  analyzeHeadless <projDir> <projName> -process <program> -noanalysis \
//                -scriptPath ghidra_scripts -postScript ExportMatchData.java <outDir> [label]
// GUI:       run from the Script Manager; you are prompted for the output folder and label.
//
// The CSV format is documented in docs/csv_format.md. Keep that file, this script and
// src/ghidra_matching/model.py in sync.
//
//@category Matching
//@author ghidra_matching

import java.io.File;
import java.io.IOException;
import java.io.OutputStreamWriter;
import java.io.PrintWriter;
import java.nio.charset.StandardCharsets;
import java.nio.file.Files;
import java.security.MessageDigest;
import java.time.Instant;
import java.util.ArrayList;
import java.util.HashMap;
import java.util.LinkedHashSet;
import java.util.List;
import java.util.Map;
import java.util.Set;
import java.util.TreeMap;
import java.util.TreeSet;

import ghidra.app.script.GhidraScript;
import ghidra.framework.Application;
import ghidra.program.model.address.Address;
import ghidra.program.model.address.AddressSetView;
import ghidra.program.model.address.AddressSpace;
import ghidra.program.model.data.Array;
import ghidra.program.model.data.Composite;
import ghidra.program.model.data.DataType;
import ghidra.program.model.data.Enum;
import ghidra.program.model.data.FunctionDefinition;
import ghidra.program.model.data.Pointer;
import ghidra.program.model.data.TypeDef;
import ghidra.program.model.data.Undefined;
import ghidra.program.model.lang.OperandType;
import ghidra.program.model.listing.Data;
import ghidra.program.model.listing.Function;
import ghidra.program.model.listing.FunctionIterator;
import ghidra.program.model.listing.FunctionManager;
import ghidra.program.model.listing.Instruction;
import ghidra.program.model.listing.InstructionIterator;
import ghidra.program.model.listing.Listing;
import ghidra.program.model.mem.Memory;
import ghidra.program.model.scalar.Scalar;
import ghidra.program.model.mem.MemoryAccessException;
import ghidra.program.model.mem.MemoryBlock;
import ghidra.program.model.symbol.Namespace;
import ghidra.program.model.symbol.Reference;
import ghidra.program.model.symbol.ReferenceManager;
import ghidra.program.model.symbol.SourceType;
import ghidra.program.model.symbol.Symbol;
import ghidra.program.model.symbol.SymbolIterator;
import ghidra.program.model.symbol.SymbolTable;
import ghidra.program.model.symbol.SymbolType;

public class ExportMatchData extends GhidraScript {

	/** Bump when the CSV columns change; mirrored in model.py (FORMAT_VERSION). */
	private static final int FORMAT_VERSION = 3;
	/** Strings longer than this are truncated in the export. */
	private static final int MAX_STRING_LENGTH = 1024;
	private static final int READ_CHUNK = 1 << 20;
	/** Instructions read for a code entry that has no function (see codeEntries). */
	private static final int MAX_CODE_ENTRY_INSNS = 2000;

	private Listing listing;
	private FunctionManager fm;
	private ReferenceManager refMgr;
	private SymbolTable symTab;
	private Memory memory;
	private AddressSetView executeSet;
	private AddressSpace defaultSpace;
	private int ptrSize;
	private boolean isArm;

	/** vtable start -> ordered function entries. */
	private final Map<Address, List<Address>> vtables = new TreeMap<>();
	/** function entry -> list of (vtable start, slot index). */
	private final Map<Address, List<Object[]>> vtableSlotsByFunction = new HashMap<>();
	/**
	 * Table slots that point to code where Ghidra has no function (common for virtual methods
	 * nobody called directly). Exported as functions with defined=0 so they can be paired;
	 * ApplyMatchTable creates the function when it applies markup there.
	 */
	private final Set<Address> codeEntries = new TreeSet<>();
	/** data address -> functions referencing it. */
	private final Map<Address, Set<Address>> dataReferencedBy = new TreeMap<>();

	@Override
	protected void run() throws Exception {
		String[] args = getScriptArgs();
		File outDir;
		String label;
		if (args.length > 0) {
			outDir = new File(args[0]);
			label = args.length > 1 ? args[1] : currentProgram.getName();
		}
		else {
			outDir = askDirectory("Output folder for match exports", "Export here");
			label = askString("Build label",
				"Label for this build (used as file prefix, e.g. v1.2.3):",
				currentProgram.getName());
		}
		label = label.trim().replaceAll("[\\\\/:*?\"<>|\\s]+", "_");
		if (!outDir.isDirectory() && !outDir.mkdirs()) {
			throw new IOException("Cannot create output folder " + outDir);
		}

		listing = currentProgram.getListing();
		fm = currentProgram.getFunctionManager();
		refMgr = currentProgram.getReferenceManager();
		symTab = currentProgram.getSymbolTable();
		memory = currentProgram.getMemory();
		executeSet = memory.getExecuteSet();
		defaultSpace = currentProgram.getAddressFactory().getDefaultAddressSpace();
		ptrSize = currentProgram.getDefaultPointerSize();
		isArm = currentProgram.getLanguage().getProcessor().toString().toUpperCase().contains("ARM");

		monitor.setMessage("Scanning for vtables / function pointer tables");
		findVtables();

		File functionsCsv = new File(outDir, label + ".functions.csv");
		File dataCsv = new File(outDir, label + ".data.csv");
		File metaJson = new File(outDir, label + ".meta.json");

		monitor.setMessage("Exporting functions");
		int nFunctions = exportFunctions(functionsCsv);
		monitor.setMessage("Exporting data");
		int nData = exportData(dataCsv);
		writeMeta(metaJson, label, nFunctions, nData);

		println(String.format("Exported %d functions, %d data items, %d vtables to %s",
			nFunctions, nData, vtables.size(), outDir.getAbsolutePath()));
	}

	// ------------------------------------------------------------------ vtables

	/**
	 * Finds runs of pointer-sized values in non-executable initialized memory that point at
	 * code: function entries, or instructions outside any function (methods Ghidra never made
	 * into functions). A run starts at a referenced (or user-labelled) address, is split
	 * whenever an interior slot is itself referenced, and must contain at least one function
	 * entry. This covers MSVC and Itanium vtables as well as other function pointer tables.
	 */
	private void findVtables() throws Exception {
		boolean bigEndian = memory.isBigEndian();
		for (MemoryBlock block : memory.getBlocks()) {
			if (!block.isInitialized() || block.isExecute() || block.isExternalBlock() ||
				block.isOverlay()) {
				continue;
			}
			Address blockStart = block.getStart();
			long size = block.getSize();
			long misalign = blockStart.getOffset() % ptrSize;
			long first = misalign == 0 ? 0 : ptrSize - misalign;

			Address runStart = null;
			List<Address> run = null;
			boolean runHasFunction = false;
			byte[] buf = new byte[READ_CHUNK + ptrSize];
			for (long chunk = first; chunk < size; chunk += READ_CHUNK) {
				monitor.checkCancelled();
				int want = (int) Math.min(READ_CHUNK + ptrSize, size - chunk);
				int got;
				try {
					got = block.getBytes(blockStart.add(chunk), buf, 0, want);
				}
				catch (MemoryAccessException e) {
					got = 0;
				}
				for (int i = 0; i + ptrSize <= got && i < READ_CHUNK; i += ptrSize) {
					Address slotAddr = blockStart.add(chunk + i);
					Address target = codeAtPointer(readPointer(buf, i, bigEndian));
					if (target == null) {
						closeRun(runStart, run, runHasFunction);
						runStart = null;
						run = null;
						continue;
					}
					if (run != null && refMgr.hasReferencesTo(slotAddr)) {
						closeRun(runStart, run, runHasFunction);
						run = null;
					}
					if (run == null) {
						runStart = slotAddr;
						run = new ArrayList<>();
						runHasFunction = false;
					}
					run.add(target);
					runHasFunction |= fm.getFunctionAt(target) != null;
				}
			}
			closeRun(runStart, run, runHasFunction);
		}
		for (Map.Entry<Address, List<Address>> e : vtables.entrySet()) {
			List<Address> slots = e.getValue();
			for (int i = 0; i < slots.size(); i++) {
				if (fm.getFunctionAt(slots.get(i)) == null) {
					codeEntries.add(slots.get(i));
				}
				vtableSlotsByFunction.computeIfAbsent(slots.get(i), k -> new ArrayList<>())
						.add(new Object[] { e.getKey(), i });
			}
		}
	}

	private void closeRun(Address start, List<Address> run, boolean hasFunction) {
		if (start == null || run == null || run.isEmpty() || !hasFunction) {
			return;
		}
		Symbol sym = symTab.getPrimarySymbol(start);
		boolean labelled = sym != null && sym.getSource() != SourceType.DEFAULT;
		if (refMgr.hasReferencesTo(start) || labelled) {
			vtables.put(start, run);
		}
	}

	private long readPointer(byte[] buf, int off, boolean bigEndian) {
		long v = 0;
		for (int k = 0; k < ptrSize; k++) {
			int b = buf[off + (bigEndian ? k : ptrSize - 1 - k)] & 0xff;
			v = (v << 8) | b;
		}
		return v;
	}

	private Address codeAtPointer(long value) {
		if (value == 0) {
			return null;
		}
		Address a = codeEntryAt(toDefaultAddress(value));
		if (a == null && isArm && (value & 1) == 1) { // Thumb pointers carry the low bit
			a = codeEntryAt(toDefaultAddress(value - 1));
		}
		return a;
	}

	/**
	 * The address if it starts a function, or starts an instruction that is not inside any
	 * function (a pointer into the middle of a function is a label, e.g. a switch case).
	 */
	private Address codeEntryAt(Address a) {
		if (a == null || !executeSet.contains(a)) {
			return null;
		}
		if (fm.getFunctionAt(a) != null) {
			return a;
		}
		if (listing.getInstructionAt(a) != null && fm.getFunctionContaining(a) == null) {
			return a;
		}
		return null;
	}

	private Address toDefaultAddress(long value) {
		try {
			return defaultSpace.getAddress(value);
		}
		catch (Exception e) {
			return null;
		}
	}

	// --------------------------------------------------------------- functions

	private int exportFunctions(File out) throws Exception {
		int count = 0;
		try (PrintWriter w = writer(out)) {
			w.println(csvRow("address", "name", "namespace", "is_default_name", "is_thunk",
				"size", "insn_count", "mnemonic_hash", "vtable_slots", "string_refs", "callees",
				"data_refs", "name_source", "signature_source", "defined", "head_size",
				"head_hash", "string_args"));
			FunctionIterator it = fm.getFunctions(true);
			while (it.hasNext()) {
				monitor.checkCancelled();
				Function f = it.next();
				if (f.isExternal()) {
					continue;
				}
				writeFunction(w, f);
				count++;
			}
			for (Address a : codeEntries) {
				monitor.checkCancelled();
				writeCodeEntry(w, a);
				count++;
			}
		}
		return count;
	}

	/**
	 * A table slot target without a function: its instructions are read in address order up
	 * to the first one without fallthrough (return, unconditional jump), the next function or
	 * code entry, or a gap.
	 */
	private void writeCodeEntry(PrintWriter w, Address entry) throws Exception {
		LinkedHashSet<String> strings = new LinkedHashSet<>();
		LinkedHashSet<String> callees = new LinkedHashSet<>();
		LinkedHashSet<String> dataRefs = new LinkedHashSet<>();
		MessageDigest md = MessageDigest.getInstance("SHA-1");
		CallArgs callArgs = new CallArgs();
		int insnCount = 0;
		Address end = entry;
		Instruction insn = listing.getInstructionAt(entry);
		while (insn != null && insnCount < MAX_CODE_ENTRY_INSNS) {
			Address at = insn.getAddress();
			if (insnCount > 0 && (fm.getFunctionAt(at) != null || codeEntries.contains(at))) {
				break;
			}
			insnCount++;
			md.update(insn.getMnemonicString().getBytes(StandardCharsets.UTF_8));
			md.update((byte) ';');
			for (Reference ref : insn.getReferencesFrom()) {
				callArgs.string(collectReference(ref, entry, strings, callees, dataRefs));
			}
			callArgs.instruction(insn);
			end = insn.getMaxAddress();
			if (!insn.getFlowType().hasFallthrough()) {
				break;
			}
			Address next = end.next();
			insn = next == null ? null : listing.getInstructionAt(next);
		}

		List<String> slots = new ArrayList<>();
		for (Object[] s : vtableSlotsByFunction.getOrDefault(entry, List.of())) {
			slots.add("[" + jsonString(addr((Address) s[0])) + "," + s[1] + "]");
		}
		Symbol sym = symTab.getPrimarySymbol(entry);
		SourceType source = sym != null ? sym.getSource() : SourceType.DEFAULT;
		String hash = insnCount == 0 ? "" : hex(md.digest()).substring(0, 16);
		String size = Long.toString(end.subtract(entry) + 1);
		w.println(csvRow(
			addr(entry),
			sym != null ? sym.getName() : "LAB_" + addr(entry),
			sym != null ? namespacePath(sym.getParentNamespace()) : "",
			source == SourceType.DEFAULT ? "1" : "0",
			"0",
			size,
			Integer.toString(insnCount),
			hash,
			"[" + String.join(",", slots) + "]",
			jsonArray(strings),
			jsonArray(callees),
			jsonArray(dataRefs),
			source.name(),
			SourceType.DEFAULT.name(),
			"0",
			size,
			hash,
			callArgs.json()));
	}

	/**
	 * Size and mnemonic hash of the code from the entry up to the first instruction without
	 * fallthrough, read the same way as for code entries, so functions and code entries can
	 * be compared.
	 */
	private String[] head(Address entry) throws Exception {
		MessageDigest md = MessageDigest.getInstance("SHA-1");
		int n = 0;
		Address end = entry;
		Instruction insn = listing.getInstructionAt(entry);
		while (insn != null && n < MAX_CODE_ENTRY_INSNS) {
			Address at = insn.getAddress();
			if (n > 0 && (fm.getFunctionAt(at) != null || codeEntries.contains(at))) {
				break;
			}
			n++;
			md.update(insn.getMnemonicString().getBytes(StandardCharsets.UTF_8));
			md.update((byte) ';');
			end = insn.getMaxAddress();
			if (!insn.getFlowType().hasFallthrough()) {
				break;
			}
			Address next = end.next();
			insn = next == null ? null : listing.getInstructionAt(next);
		}
		if (n == 0) {
			return new String[] { "0", "" };
		}
		return new String[] { Long.toString(end.subtract(entry) + 1),
			hex(md.digest()).substring(0, 16) };
	}

	private void writeFunction(PrintWriter w, Function f) throws Exception {
		Address entry = f.getEntryPoint();
		LinkedHashSet<String> strings = new LinkedHashSet<>();
		LinkedHashSet<String> callees = new LinkedHashSet<>();
		LinkedHashSet<String> dataRefs = new LinkedHashSet<>();
		MessageDigest md = MessageDigest.getInstance("SHA-1");
		CallArgs callArgs = new CallArgs();
		int insnCount = 0;

		InstructionIterator insns = listing.getInstructions(f.getBody(), true);
		while (insns.hasNext()) {
			Instruction insn = insns.next();
			insnCount++;
			md.update(insn.getMnemonicString().getBytes(StandardCharsets.UTF_8));
			md.update((byte) ';');
			for (Reference ref : insn.getReferencesFrom()) {
				callArgs.string(collectReference(ref, entry, strings, callees, dataRefs));
			}
			callArgs.instruction(insn);
		}

		List<String> slots = new ArrayList<>();
		for (Object[] s : vtableSlotsByFunction.getOrDefault(entry, List.of())) {
			slots.add("[" + jsonString(addr((Address) s[0])) + "," + s[1] + "]");
		}
		String[] head = head(entry);

		w.println(csvRow(
			addr(entry),
			f.getName(),
			namespacePath(f.getParentNamespace()),
			hasDefaultName(f) ? "1" : "0",
			f.isThunk() ? "1" : "0",
			Long.toString(f.getBody().getNumAddresses()),
			Integer.toString(insnCount),
			insnCount == 0 ? "" : hex(md.digest()).substring(0, 16),
			"[" + String.join(",", slots) + "]",
			jsonArray(strings),
			jsonArray(callees),
			jsonArray(dataRefs),
			nameSource(f).name(),
			f.getSignatureSource().name(),
			"1",
			head[0],
			head[1],
			callArgs.json()));
	}

	/**
	 * Strings and small constants passed to the same call, e.g. the file path and line of
	 * errorContext("expr", "D:\\...\\File.cpp", 0x9d). Collects what the instructions since
	 * the previous call referenced and emits every (string, constant) combination when a call
	 * is reached. Line numbers move a little between builds but keep their order.
	 */
	private static final class CallArgs {
		private static final int MAX_PAIRS = 256;
		private final List<String> strings = new ArrayList<>();
		private final List<Long> numbers = new ArrayList<>();
		private final LinkedHashSet<String> pairs = new LinkedHashSet<>();

		void string(String s) {
			if (s != null && strings.size() < 8) {
				strings.add(s);
			}
		}

		void instruction(Instruction insn) {
			for (int op = 0; op < insn.getNumOperands(); op++) {
				int type = insn.getOperandType(op);
				if (!OperandType.isScalar(type) || OperandType.isDynamic(type) ||
					OperandType.isAddress(type) || insn.getOperandReferences(op).length > 0) {
					continue;
				}
				Scalar sc = insn.getScalar(op);
				if (sc != null && sc.getValue() > 0 && sc.getValue() < 100_000 &&
					numbers.size() < 8) {
					numbers.add(sc.getValue());
				}
			}
			if (insn.getFlowType().isCall()) {
				for (String s : strings) {
					for (long n : numbers) {
						if (pairs.size() < MAX_PAIRS) {
							pairs.add("[" + jsonString(s) + "," + n + "]");
						}
					}
				}
				strings.clear();
				numbers.clear();
			}
		}

		String json() {
			return "[" + String.join(",", pairs) + "]";
		}
	}

	private static boolean hasDefaultName(Function f) {
		return nameSource(f) == SourceType.DEFAULT;
	}

	/** Thunks inherit their name from the thunked (often external) function. */
	private static SourceType nameSource(Function f) {
		Function named = f.isThunk() ? f.getThunkedFunction(true) : f;
		if (named == null) {
			named = f;
		}
		return named.getSymbol().getSource();
	}

	/**
	 * True for data types that are normally created on purpose (structures, unions, enums,
	 * typedefs, function definitions), also behind pointers and arrays. Strings, primitives and
	 * plain pointers are what auto-analysis creates.
	 */
	private static boolean isCustomType(DataType dt) {
		while (dt instanceof Array || dt instanceof Pointer) {
			dt = dt instanceof Array ? ((Array) dt).getDataType() : ((Pointer) dt).getDataType();
		}
		return dt instanceof TypeDef || dt instanceof Composite || dt instanceof Enum ||
			dt instanceof FunctionDefinition;
	}

	/** Records one reference; returns the string it refers to, if any. */
	private String collectReference(Reference ref, Address fromFunction, Set<String> strings,
			Set<String> callees, Set<String> dataRefs) {
		Address to = ref.getToAddress();
		if (to.isExternalAddress()) {
			if (ref.getReferenceType().isCall()) {
				Symbol s = symTab.getPrimarySymbol(to);
				if (s != null) {
					callees.add("EXT:" + s.getName());
				}
			}
			return null;
		}
		if (!to.isMemoryAddress()) {
			return null; // stack / register / constant
		}
		Function callee = fm.getFunctionAt(to);
		if (callee != null || codeEntries.contains(to)) {
			// direct calls and taken function addresses (callbacks)
			if (ref.getReferenceType().isCall() || ref.getReferenceType().isData()) {
				callees.add(addr(to));
			}
			return null;
		}
		if (executeSet.contains(to) || !ref.getReferenceType().isData()) {
			return null; // jumps / labels inside code
		}
		Address dataStart = to;
		String found = null;
		Data data = listing.getDataContaining(to);
		if (data != null && data.isDefined()) {
			dataStart = data.getAddress();
			String s = stringValue(data);
			if (s == null && data.isPointer() && data.getValue() instanceof Address) {
				// one level of indirection: literal pools / string pointer tables
				Address pointed = (Address) data.getValue();
				Data pd = listing.getDataAt(pointed);
				s = pd != null ? stringValue(pd) : null;
				if (s == null && fm.getFunctionAt(pointed) != null) {
					callees.add(addr(pointed));
				}
			}
			if (s != null) {
				strings.add(s);
				found = s;
			}
		}
		dataRefs.add(addr(dataStart));
		dataReferencedBy.computeIfAbsent(dataStart, k -> new TreeSet<>()).add(fromFunction);
		return found;
	}

	private static String stringValue(Data data) {
		if (data == null || !data.hasStringValue()) {
			return null;
		}
		Object v = data.getValue();
		if (!(v instanceof String)) {
			return null;
		}
		String s = (String) v;
		return s.length() > MAX_STRING_LENGTH ? s.substring(0, MAX_STRING_LENGTH) : s;
	}

	// -------------------------------------------------------------------- data

	private int exportData(File out) throws Exception {
		// Collect every address worth describing: vtables, strings, referenced data and
		// user-labelled data.
		Set<Address> addresses = new TreeSet<>();
		addresses.addAll(vtables.keySet());
		addresses.addAll(dataReferencedBy.keySet());
		for (Data d : listing.getDefinedData(true)) {
			monitor.checkCancelled();
			if (d.hasStringValue() || isCustomType(d.getDataType())) {
				addresses.add(d.getAddress());
			}
		}
		SymbolIterator syms = symTab.getAllSymbols(false);
		while (syms.hasNext()) {
			Symbol s = syms.next();
			if (s.getSymbolType() == SymbolType.LABEL && s.isPrimary() &&
				s.getSource() != SourceType.DEFAULT && s.getAddress().isMemoryAddress() &&
				!executeSet.contains(s.getAddress())) {
				addresses.add(s.getAddress());
			}
		}

		int count = 0;
		try (PrintWriter w = writer(out)) {
			w.println(csvRow("address", "name", "namespace", "is_default_name", "kind",
				"datatype", "size", "value", "slots", "referenced_by", "name_source", "custom_type"));
			for (Address a : addresses) {
				monitor.checkCancelled();
				Symbol sym = symTab.getPrimarySymbol(a);
				Data data = listing.getDefinedDataAt(a);
				List<Address> slots = vtables.get(a);
				String value = stringValue(data);
				String kind = slots != null ? "vtable" : value != null ? "string" : "data";
				DataType dt = data != null ? data.getDataType() : null;
				boolean undefinedType = dt == null || Undefined.isUndefined(dt);

				List<String> slotStrs = new ArrayList<>();
				if (slots != null) {
					for (Address s : slots) {
						slotStrs.add(addr(s));
					}
				}
				List<String> refBy = new ArrayList<>();
				for (Address f : dataReferencedBy.getOrDefault(a, Set.of())) {
					refBy.add(addr(f));
				}
				w.println(csvRow(
					addr(a),
					sym != null ? sym.getName() : "",
					sym != null ? namespacePath(sym.getParentNamespace()) : "",
					sym == null || sym.getSource() == SourceType.DEFAULT ? "1" : "0",
					kind,
					undefinedType ? "" : dt.getPathName(),
					data != null ? Integer.toString(data.getLength()) : "0",
					value != null ? jsonString(value) : "",
					jsonArray(slotStrs),
					jsonArray(refBy),
					sym != null ? sym.getSource().name() : SourceType.DEFAULT.name(),
					!undefinedType && isCustomType(dt) ? "1" : "0"));
				count++;
			}
		}
		return count;
	}

	// -------------------------------------------------------------------- meta

	private void writeMeta(File out, String label, int nFunctions, int nData)
			throws IOException {
		String[][] fields = {
			{ "format_version", Integer.toString(FORMAT_VERSION) },
			{ "label", jsonString(label) },
			{ "program_name", jsonString(currentProgram.getName()) },
			{ "project_path", jsonString(currentProgram.getDomainFile().getPathname()) },
			{ "executable_path", jsonString(String.valueOf(currentProgram.getExecutablePath())) },
			{ "executable_md5", jsonString(String.valueOf(currentProgram.getExecutableMD5())) },
			{ "executable_sha256",
				jsonString(String.valueOf(currentProgram.getExecutableSHA256())) },
			{ "image_base", jsonString(addr(currentProgram.getImageBase())) },
			{ "language", jsonString(currentProgram.getLanguageID().getIdAsString()) },
			{ "compiler_spec",
				jsonString(currentProgram.getCompilerSpec().getCompilerSpecID().getIdAsString()) },
			{ "pointer_size", Integer.toString(ptrSize) },
			{ "ghidra_version", jsonString(Application.getApplicationVersion()) },
			{ "exported_at", jsonString(Instant.now().toString()) },
			{ "function_count", Integer.toString(nFunctions) },
			{ "data_count", Integer.toString(nData) },
			{ "vtable_count", Integer.toString(vtables.size()) },
		};
		StringBuilder sb = new StringBuilder("{\n");
		for (int i = 0; i < fields.length; i++) {
			sb.append("  ").append(jsonString(fields[i][0])).append(": ").append(fields[i][1]);
			sb.append(i + 1 < fields.length ? ",\n" : "\n");
		}
		sb.append("}\n");
		Files.writeString(out.toPath(), sb.toString(), StandardCharsets.UTF_8);
	}

	// ----------------------------------------------------------------- helpers

	private static String addr(Address a) {
		return a.toString(false);
	}

	private static String namespacePath(Namespace ns) {
		if (ns == null || ns.isGlobal()) {
			return "";
		}
		return ns.getName(true);
	}

	private static PrintWriter writer(File f) throws IOException {
		return new PrintWriter(
			new OutputStreamWriter(Files.newOutputStream(f.toPath()), StandardCharsets.UTF_8));
	}

	private static String hex(byte[] bytes) {
		StringBuilder sb = new StringBuilder();
		for (byte b : bytes) {
			sb.append(String.format("%02x", b & 0xff));
		}
		return sb.toString();
	}

	private static String jsonArray(Iterable<String> items) {
		StringBuilder sb = new StringBuilder("[");
		boolean first = true;
		for (String s : items) {
			if (!first) {
				sb.append(',');
			}
			sb.append(jsonString(s));
			first = false;
		}
		return sb.append(']').toString();
	}

	private static String jsonString(String s) {
		StringBuilder sb = new StringBuilder("\"");
		for (int i = 0; i < s.length(); i++) {
			char c = s.charAt(i);
			switch (c) {
				case '"':
					sb.append("\\\"");
					break;
				case '\\':
					sb.append("\\\\");
					break;
				case '\n':
					sb.append("\\n");
					break;
				case '\r':
					sb.append("\\r");
					break;
				case '\t':
					sb.append("\\t");
					break;
				default:
					if (c < 0x20 || (c >= 0xd800 && c <= 0xdfff)) {
						sb.append(String.format("\\u%04x", (int) c));
					}
					else {
						sb.append(c);
					}
			}
		}
		return sb.append('"').toString();
	}

	private static String csvRow(String... fields) {
		StringBuilder sb = new StringBuilder();
		for (int i = 0; i < fields.length; i++) {
			if (i > 0) {
				sb.append(',');
			}
			String f = fields[i] == null ? "" : fields[i];
			if (f.indexOf(',') >= 0 || f.indexOf('"') >= 0 || f.indexOf('\n') >= 0 ||
				f.indexOf('\r') >= 0) {
				sb.append('"').append(f.replace("\"", "\"\"")).append('"');
			}
			else {
				sb.append(f);
			}
		}
		return sb.toString();
	}
}
