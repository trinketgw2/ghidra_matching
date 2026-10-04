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
import ghidra.program.model.listing.Data;
import ghidra.program.model.listing.Function;
import ghidra.program.model.listing.FunctionIterator;
import ghidra.program.model.listing.FunctionManager;
import ghidra.program.model.listing.Instruction;
import ghidra.program.model.listing.InstructionIterator;
import ghidra.program.model.listing.Listing;
import ghidra.program.model.mem.Memory;
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
	private static final int FORMAT_VERSION = 2;
	/** Strings longer than this are truncated in the export. */
	private static final int MAX_STRING_LENGTH = 1024;
	private static final int READ_CHUNK = 1 << 20;

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
	 * function entries. A run starts at a referenced (or user-labelled) address and is split
	 * whenever an interior slot is itself referenced. This covers MSVC and Itanium vtables as
	 * well as other function pointer tables.
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
					Address target = functionAtPointer(readPointer(buf, i, bigEndian));
					if (target == null) {
						closeRun(runStart, run);
						runStart = null;
						run = null;
						continue;
					}
					if (run != null && refMgr.hasReferencesTo(slotAddr)) {
						closeRun(runStart, run);
						run = null;
					}
					if (run == null) {
						runStart = slotAddr;
						run = new ArrayList<>();
					}
					run.add(target);
				}
			}
			closeRun(runStart, run);
		}
		for (Map.Entry<Address, List<Address>> e : vtables.entrySet()) {
			List<Address> slots = e.getValue();
			for (int i = 0; i < slots.size(); i++) {
				vtableSlotsByFunction.computeIfAbsent(slots.get(i), k -> new ArrayList<>())
						.add(new Object[] { e.getKey(), i });
			}
		}
	}

	private void closeRun(Address start, List<Address> run) {
		if (start == null || run == null || run.isEmpty()) {
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

	private Address functionAtPointer(long value) {
		if (value == 0) {
			return null;
		}
		Address a = toDefaultAddress(value);
		if (a != null && executeSet.contains(a) && fm.getFunctionAt(a) != null) {
			return a;
		}
		if (isArm && (value & 1) == 1) { // Thumb pointers carry the low bit
			a = toDefaultAddress(value - 1);
			if (a != null && executeSet.contains(a) && fm.getFunctionAt(a) != null) {
				return a;
			}
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
				"data_refs", "name_source", "signature_source"));
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
		}
		return count;
	}

	private void writeFunction(PrintWriter w, Function f) throws Exception {
		Address entry = f.getEntryPoint();
		LinkedHashSet<String> strings = new LinkedHashSet<>();
		LinkedHashSet<String> callees = new LinkedHashSet<>();
		LinkedHashSet<String> dataRefs = new LinkedHashSet<>();
		MessageDigest md = MessageDigest.getInstance("SHA-1");
		int insnCount = 0;

		InstructionIterator insns = listing.getInstructions(f.getBody(), true);
		while (insns.hasNext()) {
			Instruction insn = insns.next();
			insnCount++;
			md.update(insn.getMnemonicString().getBytes(StandardCharsets.UTF_8));
			md.update((byte) ';');
			for (Reference ref : insn.getReferencesFrom()) {
				collectReference(ref, entry, strings, callees, dataRefs);
			}
		}

		List<String> slots = new ArrayList<>();
		for (Object[] s : vtableSlotsByFunction.getOrDefault(entry, List.of())) {
			slots.add("[" + jsonString(addr((Address) s[0])) + "," + s[1] + "]");
		}

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
			f.getSignatureSource().name()));
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

	private void collectReference(Reference ref, Address fromFunction, Set<String> strings,
			Set<String> callees, Set<String> dataRefs) {
		Address to = ref.getToAddress();
		if (to.isExternalAddress()) {
			if (ref.getReferenceType().isCall()) {
				Symbol s = symTab.getPrimarySymbol(to);
				if (s != null) {
					callees.add("EXT:" + s.getName());
				}
			}
			return;
		}
		if (!to.isMemoryAddress()) {
			return; // stack / register / constant
		}
		Function callee = fm.getFunctionAt(to);
		if (callee != null) {
			// direct calls and taken function addresses (callbacks)
			if (ref.getReferenceType().isCall() || ref.getReferenceType().isData()) {
				callees.add(addr(to));
			}
			return;
		}
		if (executeSet.contains(to) || !ref.getReferenceType().isData()) {
			return; // jumps / labels inside code
		}
		Address dataStart = to;
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
			}
		}
		dataRefs.add(addr(dataStart));
		dataReferencedBy.computeIfAbsent(dataStart, k -> new TreeSet<>()).add(fromFunction);
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
