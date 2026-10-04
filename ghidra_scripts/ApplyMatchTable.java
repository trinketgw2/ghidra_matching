// Applies markup from a source program onto the current (target) program using a pairing
// table produced by `ghidra-match pair`.
//
// Only user markup is transferred (user_only=true, the default):
//   functions: name + namespace/class if the name was set by a user; signature (return type,
//              parameters, calling convention) if set by a user, or imported on a user-named
//              function
//   data:      label + namespace and data type, if the label was set by a user (Ghidra does not
//              record who created a data type, so loader/analysis types would be carried
//              along otherwise)
//   types:     every data type defined in the source program (structures, enums, typedefs, ...)
//              is copied first, so types not applied anywhere yet are carried over too
// Names from auto-analysis (FUN_, switchD_, caseD_, ...), imports and RTTI are never applied.
//
// The source program must live in the same Ghidra project as the target.
//
// Headless:
//   analyzeHeadless <projDir> <projName> -process <target> -noanalysis -scriptPath ghidra_scripts \
//       -postScript ApplyMatchTable.java <pairs.csv> </project/path/to/source> [key=value ...]
// GUI: run from the Script Manager on the target program; you are prompted for the inputs.
//
// Options (key=value):
//   min_confidence=0.0   ignore pairs below this confidence
//   names=true           apply function / data names and namespaces
//   signatures=true      apply function signatures
//   data=true            apply data types at paired data addresses
//   copy_types=local     local: copy all types defined in the source program first
//                        all:   also types from attached archives; used: only types needed
//                        by applied signatures and data
//   conflict=keep        a type that already exists in the target (same path) is reused and
//                        left as is, except empty placeholder structures/unions, which get the
//                        source definition. replace: source definition wins. rename: add the
//                        source version as <name>.conflict. replace_empty: fill empty
//                        placeholders, otherwise add a .conflict copy.
//   user_only=true       only transfer markup made by a user (false: any non-default markup)
//   replace_signatures=true  when the target function already has the source's name, apply
//                        the source signature even if the target's was set by a user
//   overwrite=false      also replace target markup that was set by a user or imported
//   dry_run=false        only report what would change
//   report=<path.csv>    write one row per action / skip
//
//@category Matching
//@author ghidra_matching

import java.io.File;
import java.io.IOException;
import java.io.PrintWriter;
import java.nio.charset.StandardCharsets;
import java.nio.file.Files;
import java.util.ArrayList;
import java.util.HashMap;
import java.util.Iterator;
import java.util.List;
import java.util.Map;
import java.util.TreeMap;

import ghidra.app.cmd.function.ApplyFunctionSignatureCmd;
import ghidra.app.cmd.function.FunctionRenameOption;
import ghidra.app.script.GhidraScript;
import ghidra.app.util.NamespaceUtils;
import ghidra.framework.model.DomainFile;
import ghidra.framework.model.DomainObject;
import ghidra.program.model.address.Address;
import ghidra.program.model.data.ArchiveType;
import ghidra.program.model.data.Array;
import ghidra.program.model.data.BuiltInDataType;
import ghidra.program.model.data.Composite;
import ghidra.program.model.data.DataType;
import ghidra.program.model.data.DataTypeConflictHandler;
import ghidra.program.model.data.DataTypeManager;
import ghidra.program.model.data.DataUtilities;
import ghidra.program.model.data.Enum;
import ghidra.program.model.data.FunctionDefinition;
import ghidra.program.model.data.FunctionDefinitionDataType;
import ghidra.program.model.data.Pointer;
import ghidra.program.model.data.SourceArchive;
import ghidra.program.model.data.Structure;
import ghidra.program.model.data.TypeDef;
import ghidra.program.model.data.Undefined;
import ghidra.program.model.data.Union;
import ghidra.program.model.listing.Data;
import ghidra.program.model.listing.Function;
import ghidra.program.model.listing.Program;
import ghidra.program.model.symbol.Namespace;
import ghidra.program.model.symbol.SourceType;
import ghidra.program.model.symbol.Symbol;
import ghidra.program.model.symbol.SymbolTable;
import ghidra.program.model.symbol.SymbolType;
import ghidra.program.model.listing.GhidraClass;
import ghidra.util.UniversalID;

public class ApplyMatchTable extends GhidraScript {

	private Program src;
	private Program tgt;
	private DataTypeManager tgtDtm;
	private SymbolTable srcSt;
	private SymbolTable tgtSt;
	private DataTypeConflictHandler conflictHandler;

	private double minConfidence = 0.0;
	private boolean applyNames = true;
	private boolean applySignatures = true;
	private boolean applyData = true;
	private String copyTypes = "local";
	private boolean userOnly = true;
	private boolean overwrite = false;
	private boolean replaceSignatures = true;
	private boolean dryRun = false;
	private File reportFile;

	private final Map<String, Integer> stats = new TreeMap<>();
	private final List<String[]> report = new ArrayList<>();

	@Override
	protected void run() throws Exception {
		tgt = currentProgram;
		File pairsFile;
		String sourcePath;
		String conflict = "keep";
		String[] args = getScriptArgs();
		if (args.length >= 2) {
			pairsFile = new File(args[0]);
			sourcePath = args[1];
			Map<String, String> opts = new HashMap<>();
			for (int i = 2; i < args.length; i++) {
				int eq = args[i].indexOf('=');
				if (eq <= 0) {
					throw new IllegalArgumentException("Expected key=value, got: " + args[i]);
				}
				opts.put(args[i].substring(0, eq).trim().toLowerCase(),
					args[i].substring(eq + 1).trim());
			}
			minConfidence = Double.parseDouble(opts.getOrDefault("min_confidence", "0"));
			applyNames = bool(opts, "names", true);
			applySignatures = bool(opts, "signatures", true);
			applyData = bool(opts, "data", true);
			copyTypes = opts.getOrDefault("copy_types",
				bool(opts, "copy_all_types", false) ? "all" : copyTypes).toLowerCase();
			userOnly = bool(opts, "user_only", true);
			overwrite = bool(opts, "overwrite", false);
			replaceSignatures = bool(opts, "replace_signatures", true);
			dryRun = bool(opts, "dry_run", false);
			conflict = opts.getOrDefault("conflict", conflict);
			if (opts.containsKey("report")) {
				reportFile = new File(opts.get("report"));
			}
		}
		else if (args.length == 0 && !isRunningHeadless()) {
			pairsFile = askFile("Pairing table (CSV)", "Use");
			sourcePath = askDomainFile("Source program (markup comes from here)").getPathname();
			minConfidence = askDouble("Minimum confidence", "Ignore pairs below (0.0 - 1.0):");
			overwrite = askYesNo("Overwrite",
				"Also overwrite target names/signatures set by a user or imported symbols?");
			dryRun = askYesNo("Dry run", "Only report what would change (no modifications)?");
		}
		else {
			throw new IllegalArgumentException(
				"Usage: ApplyMatchTable.java <pairs.csv> </project/path/source> [key=value ...]");
		}
		conflictHandler = conflictHandler(conflict);
		if (!copyTypes.equals("used") && !copyTypes.equals("local") && !copyTypes.equals("all")) {
			throw new IllegalArgumentException("copy_types must be used, local or all");
		}

		DomainFile df = state.getProject().getProjectData().getFile(sourcePath);
		if (df == null) {
			throw new IllegalArgumentException("Source program not found in project: " + sourcePath);
		}
		DomainObject obj = df.getReadOnlyDomainObject(this, DomainFile.DEFAULT_VERSION, monitor);
		try {
			if (!(obj instanceof Program)) {
				throw new IllegalArgumentException(sourcePath + " is not a program");
			}
			src = (Program) obj;
			if (src.getDomainFile().equals(tgt.getDomainFile())) {
				throw new IllegalArgumentException("Source and target are the same program");
			}
			apply(pairsFile);
		}
		finally {
			obj.release(this);
		}
	}

	private void apply(File pairsFile) throws Exception {
		tgtDtm = tgt.getDataTypeManager();
		srcSt = src.getSymbolTable();
		tgtSt = tgt.getSymbolTable();

		List<Map<String, String>> rows = readCsv(pairsFile);
		println(String.format("%s%d pairs from %s, source=%s, target=%s",
			dryRun ? "[dry run] " : "", rows.size(), pairsFile.getName(), src.getName(),
			tgt.getName()));

		if (!copyTypes.equals("used")) {
			copyDataTypes(copyTypes.equals("all"));
		}

		monitor.initialize(rows.size());
		for (Map<String, String> row : rows) {
			monitor.checkCancelled();
			monitor.incrementProgress(1);
			double conf = Double.parseDouble(row.getOrDefault("confidence", "1"));
			if (conf < minConfidence) {
				count("skipped_low_confidence");
				continue;
			}
			String kind = row.get("kind");
			Address s = src.getAddressFactory().getAddress(row.get("source_address"));
			Address t = tgt.getAddressFactory().getAddress(row.get("target_address"));
			if (s == null || t == null) {
				record(row, "error", "unparseable address");
				continue;
			}
			try {
				if ("function".equals(kind)) {
					applyFunction(row, s, t);
				}
				else if ("data".equals(kind)) {
					applyDataPair(row, s, t);
				}
				else {
					record(row, "error", "unknown kind " + kind);
				}
			}
			catch (Exception e) {
				record(row, "error", e.getClass().getSimpleName() + ": " + e.getMessage());
			}
		}

		StringBuilder sb = new StringBuilder(dryRun ? "[dry run] summary:" : "Summary:");
		for (Map.Entry<String, Integer> e : stats.entrySet()) {
			sb.append("\n  ").append(e.getKey()).append(": ").append(e.getValue());
		}
		println(sb.toString());
		if (reportFile != null) {
			writeReport();
			println("Report written to " + reportFile.getAbsolutePath());
		}
	}

	// --------------------------------------------------------------- functions

	private void applyFunction(Map<String, String> row, Address s, Address t) throws Exception {
		Function sf = src.getFunctionManager().getFunctionAt(s);
		if (sf == null) {
			record(row, "error", "no source function");
			return;
		}
		Function tf = tgt.getFunctionManager().getFunctionAt(t);
		if (tf == null) {
			if (dryRun) {
				record(row, "create_function", "");
			}
			else {
				if (getInstructionAt(t) == null) {
					disassemble(t);
				}
				tf = createFunction(t, null);
				if (tf == null) {
					record(row, "error", "could not create target function");
					return;
				}
			}
		}
		if (sf.isThunk() || (tf != null && tf.isThunk())) {
			record(row, "skip", "thunk");
			return;
		}

		boolean userName = isMarkup(sf.getSymbol().getSource());
		SourceType sigSource = sf.getSignatureSource();
		boolean userSignature = isMarkup(sigSource) ||
			(userName && sigSource == SourceType.IMPORTED);
		if (!userName && !userSignature) {
			record(row, "skip", "no user markup");
			return;
		}

		if (applyNames && userName) {
			if (tf != null && sameName(sf.getSymbol(), tf.getSymbol())) {
				count("unchanged_name");
			}
			else if (tf != null && !mayReplace(tf.getSymbol().getSource())) {
				record(row, "skip_name", "target has " + tf.getName(true) + " (" +
					tf.getSymbol().getSource() + ")");
			}
			else {
				if (!dryRun) {
					Namespace ns = copyNamespace(sf.getParentNamespace());
					tf.getSymbol().setNameAndNamespace(sf.getName(), ns, SourceType.USER_DEFINED);
				}
				record(row, "name", sf.getName(true));
			}
		}

		if (applySignatures && userSignature) {
			FunctionDefinitionDataType sig = new FunctionDefinitionDataType(sf, true);
			if (tf != null && sameSignature(sig, tf)) {
				count("unchanged_signature");
			}
			else if (tf != null && !mayReplace(tf.getSignatureSource()) &&
				!(replaceSignatures && sameName(sf.getSymbol(), tf.getSymbol()))) {
				record(row, "skip_signature", "target has " + tf.getSignature(true).getPrototypeString() +
					" (" + tf.getSignatureSource() + ")");
			}
			else {
				String replaced = tf != null && !mayReplace(tf.getSignatureSource())
						? " (replaced " + tf.getSignature(true).getPrototypeString() + ")"
						: "";
				if (!dryRun) {
					ApplyFunctionSignatureCmd cmd = new ApplyFunctionSignatureCmd(t, sig,
						SourceType.USER_DEFINED, false, false, conflictHandler,
						FunctionRenameOption.NO_CHANGE);
					if (!cmd.applyTo(tgt, monitor)) {
						record(row, "error", "signature: " + cmd.getStatusMsg());
						return;
					}
				}
				record(row, "signature", sig.getPrototypeString() + replaced);
			}
		}
	}

	// -------------------------------------------------------------------- data

	private void applyDataPair(Map<String, String> row, Address s, Address t) throws Exception {
		if (applyNames) {
			Symbol ss = srcSt.getPrimarySymbol(s);
			if (ss != null && isMarkup(ss.getSource()) && ss.getSymbolType() == SymbolType.LABEL) {
				Symbol ts = tgtSt.getPrimarySymbol(t);
				if (ts != null && ts.getSymbolType() == SymbolType.FUNCTION) {
					record(row, "skip_label", "target address is a function");
				}
				else if (ts != null && sameName(ss, ts)) {
					count("unchanged_label");
				}
				else if (ts != null && !mayReplace(ts.getSource())) {
					record(row, "skip_label",
						"target has " + ts.getName(true) + " (" + ts.getSource() + ")");
				}
				else {
					if (!dryRun) {
						Namespace ns = copyNamespace(ss.getParentNamespace());
						Symbol created =
							tgtSt.createLabel(t, ss.getName(), ns, SourceType.USER_DEFINED);
						created.setPrimary();
					}
					record(row, "label", ss.getName(true));
				}
			}
		}

		if (applyData) {
			Data sd = src.getListing().getDefinedDataAt(s);
			if (sd == null || Undefined.isUndefined(sd.getDataType())) {
				return;
			}
			DataType srcType = sd.getDataType();
			Symbol ss = srcSt.getPrimarySymbol(s);
			boolean userLabel = ss != null && isMarkup(ss.getSource());
			if (userOnly ? !userLabel : !userLabel && !looksUserDefined(srcType)) {
				record(row, "skip_datatype", "no user label: " + srcType.getPathName());
				return;
			}
			Data td = tgt.getListing().getDataAt(t);
			if (td == null && tgt.getListing().getInstructionContaining(t) != null) {
				record(row, "skip_datatype", "target address is code");
				return;
			}
			if (td != null && td.isDefined() && !Undefined.isUndefined(td.getDataType())) {
				DataType cur = td.getDataType();
				if (cur.getPathName().equals(srcType.getPathName()) &&
					td.getLength() == sd.getLength()) {
					count("unchanged_datatype");
					return;
				}
				if (!overwrite && looksUserDefined(cur)) {
					record(row, "skip_datatype", "target has " + cur.getPathName());
					return;
				}
			}
			if (!dryRun) {
				DataType resolved = tgtDtm.resolve(srcType, conflictHandler);
				DataUtilities.createData(tgt, t, resolved, sd.getLength(),
					DataUtilities.ClearDataMode.CLEAR_ALL_CONFLICT_DATA);
			}
			record(row, "datatype", srcType.getPathName());
		}
	}

	/**
	 * Structures, unions, enums, typedefs and function definitions (also behind arrays and
	 * pointers) are assumed to be deliberate user work. Must match isCustomType in
	 * ExportMatchData.java.
	 */
	private static boolean looksUserDefined(DataType dt) {
		while (dt instanceof Array || dt instanceof Pointer) {
			dt = dt instanceof Array ? ((Array) dt).getDataType() : ((Pointer) dt).getDataType();
		}
		return dt instanceof TypeDef || dt instanceof Composite || dt instanceof Enum ||
			dt instanceof FunctionDefinition;
	}

	/**
	 * Resolves the source program's data types into the target so that structures, enums
	 * etc. are carried over even where they are not applied to a paired item.
	 */
	private void copyDataTypes(boolean includeArchives) throws Exception {
		int n = 0;
		monitor.setMessage("Copying data types");
		UniversalID localArchive =
			src.getDataTypeManager().getLocalSourceArchive().getSourceArchiveID();
		Iterator<DataType> it = src.getDataTypeManager().getAllDataTypes();
		while (it.hasNext()) {
			monitor.checkCancelled();
			DataType dt = it.next();
			if (dt instanceof BuiltInDataType || dt instanceof Pointer || dt instanceof Array) {
				continue; // pulled in as dependencies when needed
			}
			if (!includeArchives && !isLocalType(dt, localArchive)) {
				continue;
			}
			if (!dryRun) {
				tgtDtm.resolve(dt, conflictHandler);
			}
			n++;
		}
		stats.put("types_copied", n);
	}

	/** Defined in the program itself rather than taken from an attached archive (.gdt). */
	private static boolean isLocalType(DataType dt, UniversalID localArchive) {
		SourceArchive archive = dt.getSourceArchive();
		if (archive == null) {
			return true;
		}
		UniversalID id = archive.getSourceArchiveID();
		return localArchive.equals(id) || DataTypeManager.LOCAL_ARCHIVE_UNIVERSAL_ID.equals(id) ||
			archive.getArchiveType() == ArchiveType.PROGRAM;
	}

	// ----------------------------------------------------------------- helpers

	/** Markup worth transferring: user-made, or any non-default with user_only=false. */
	private boolean isMarkup(SourceType source) {
		return userOnly ? source == SourceType.USER_DEFINED : source != SourceType.DEFAULT;
	}

	/** DEFAULT, ANALYSIS and AI names may always be replaced; others only with overwrite. */
	private boolean mayReplace(SourceType current) {
		return overwrite || current.isLowerPriorityThan(SourceType.IMPORTED);
	}

	/** Same return/parameter types and names and calling convention; function names ignored. */
	private static boolean sameSignature(FunctionDefinitionDataType sig, Function tf) {
		FunctionDefinitionDataType cur = new FunctionDefinitionDataType(tf, true);
		try {
			cur.setName(sig.getName());
		}
		catch (Exception e) {
			return false;
		}
		cur.setComment(sig.getComment());
		return sig.isEquivalentSignature(cur);
	}

	private static boolean sameName(Symbol a, Symbol b) {
		return a.getName(true).equals(b.getName(true));
	}

	private Namespace copyNamespace(Namespace ns) throws Exception {
		if (ns == null || ns.isGlobal() || ns.isExternal() ||
			ns.getSymbol().getSymbolType() == SymbolType.LIBRARY) {
			return tgt.getGlobalNamespace();
		}
		Namespace parent = copyNamespace(ns.getParentNamespace());
		Namespace existing = tgtSt.getNamespace(ns.getName(), parent);
		boolean isClass = ns instanceof GhidraClass;
		if (existing != null) {
			if (isClass && !(existing instanceof GhidraClass) &&
				existing.getSymbol().getSymbolType() == SymbolType.NAMESPACE) {
				return NamespaceUtils.convertNamespaceToClass(existing);
			}
			return existing;
		}
		return isClass ? tgtSt.createClass(parent, ns.getName(), SourceType.USER_DEFINED)
				: tgtSt.createNameSpace(parent, ns.getName(), SourceType.USER_DEFINED);
	}

	private static DataTypeConflictHandler conflictHandler(String name) {
		switch (name.toLowerCase()) {
			case "keep":
				return KEEP_EXISTING_FILL_EMPTY;
			case "replace":
				return DataTypeConflictHandler.REPLACE_HANDLER;
			case "rename":
				return DataTypeConflictHandler.DEFAULT_HANDLER;
			case "replace_empty":
				return DataTypeConflictHandler.REPLACE_EMPTY_STRUCTS_OR_RENAME_AND_ADD_HANDLER;
			default:
				throw new IllegalArgumentException("Unknown conflict handler: " + name);
		}
	}

	/**
	 * Reuses the target's type when one with the same path exists, so no ".conflict" copies
	 * are created. Empty placeholder structures/unions in the target are filled from the source.
	 */
	private static final DataTypeConflictHandler KEEP_EXISTING_FILL_EMPTY =
		new DataTypeConflictHandler() {
			@Override
			public ConflictResult resolveConflict(DataType added, DataType existing) {
				boolean sameKind = (added instanceof Structure && existing instanceof Structure) ||
					(added instanceof Union && existing instanceof Union);
				if (sameKind && existing.isNotYetDefined() && !added.isNotYetDefined()) {
					return ConflictResult.REPLACE_EXISTING;
				}
				return ConflictResult.USE_EXISTING;
			}

			@Override
			public boolean shouldUpdate(DataType sourceDataType, DataType localDataType) {
				return false;
			}

			@Override
			public DataTypeConflictHandler getSubsequentHandler() {
				return this;
			}
		};

	private static boolean bool(Map<String, String> opts, String key, boolean dflt) {
		String v = opts.get(key);
		if (v == null) {
			return dflt;
		}
		return v.equalsIgnoreCase("true") || v.equals("1") || v.equalsIgnoreCase("yes");
	}

	private void count(String key) {
		stats.merge(key, 1, Integer::sum);
	}

	private void record(Map<String, String> row, String action, String detail) {
		count(action);
		report.add(new String[] { row.get("kind"), row.get("source_address"),
			row.get("target_address"), action, detail });
		if (action.equals("error")) {
			printerr(String.format("%s %s -> %s: %s", row.get("kind"), row.get("source_address"),
				row.get("target_address"), detail));
		}
	}

	private void writeReport() throws IOException {
		try (PrintWriter w = new PrintWriter(Files.newBufferedWriter(reportFile.toPath(),
			StandardCharsets.UTF_8))) {
			w.println("kind,source_address,target_address,action,detail");
			for (String[] r : report) {
				StringBuilder sb = new StringBuilder();
				for (int i = 0; i < r.length; i++) {
					String f = r[i] == null ? "" : r[i];
					if (i > 0) {
						sb.append(',');
					}
					if (f.contains(",") || f.contains("\"") || f.contains("\n")) {
						f = '"' + f.replace("\"", "\"\"") + '"';
					}
					sb.append(f);
				}
				w.println(sb);
			}
		}
	}

	/** Minimal RFC 4180 reader: header row + quoted fields with "" escapes. */
	private static List<Map<String, String>> readCsv(File f) throws IOException {
		String text = Files.readString(f.toPath(), StandardCharsets.UTF_8);
		List<List<String>> records = new ArrayList<>();
		List<String> rec = new ArrayList<>();
		StringBuilder field = new StringBuilder();
		boolean quoted = false;
		for (int i = 0; i < text.length(); i++) {
			char c = text.charAt(i);
			if (quoted) {
				if (c == '"') {
					if (i + 1 < text.length() && text.charAt(i + 1) == '"') {
						field.append('"');
						i++;
					}
					else {
						quoted = false;
					}
				}
				else {
					field.append(c);
				}
			}
			else if (c == '"') {
				quoted = true;
			}
			else if (c == ',') {
				rec.add(field.toString());
				field.setLength(0);
			}
			else if (c == '\n' || c == '\r') {
				if (c == '\r' && i + 1 < text.length() && text.charAt(i + 1) == '\n') {
					i++;
				}
				rec.add(field.toString());
				field.setLength(0);
				records.add(rec);
				rec = new ArrayList<>();
			}
			else {
				field.append(c);
			}
		}
		if (field.length() > 0 || !rec.isEmpty()) {
			rec.add(field.toString());
			records.add(rec);
		}
		List<Map<String, String>> rows = new ArrayList<>();
		if (records.isEmpty()) {
			return rows;
		}
		List<String> header = records.get(0);
		for (int r = 1; r < records.size(); r++) {
			List<String> values = records.get(r);
			if (values.size() == 1 && values.get(0).isEmpty()) {
				continue;
			}
			Map<String, String> row = new HashMap<>();
			for (int i = 0; i < header.size() && i < values.size(); i++) {
				row.put(header.get(i), values.get(i));
			}
			rows.add(row);
		}
		return rows;
	}
}
