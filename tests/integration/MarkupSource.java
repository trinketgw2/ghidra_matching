// Integration test helper: simulates a user's work on the source build (sample_v1).
// Everything here is USER_DEFINED, unlike the names imported from DWARF, which the apply
// step must ignore.
//
//  - renames the sample's own functions to <name>_u (runtime functions keep their names)
//  - checksum: signature `int checksum(LogText text)` with a user typedef LogText = char *
//  - g_config: relabelled g_app_config, retyped to the user struct /UserTypes/AppConfig
//  - g_counter: relabelled g_hits
//  - /UserTypes/ShapeStats: a structure that is not applied anywhere
//@category Matching.Tests

import java.util.Set;

import ghidra.app.cmd.function.ApplyFunctionSignatureCmd;
import ghidra.app.cmd.function.FunctionRenameOption;
import ghidra.app.script.GhidraScript;
import ghidra.program.model.data.CategoryPath;
import ghidra.program.model.data.CharDataType;
import ghidra.program.model.data.DataType;
import ghidra.program.model.data.DataTypeConflictHandler;
import ghidra.program.model.data.DataTypeManager;
import ghidra.program.model.data.DataUtilities;
import ghidra.program.model.data.DoubleDataType;
import ghidra.program.model.data.FunctionDefinitionDataType;
import ghidra.program.model.data.IntegerDataType;
import ghidra.program.model.data.ParameterDefinition;
import ghidra.program.model.data.ParameterDefinitionImpl;
import ghidra.program.model.data.PointerDataType;
import ghidra.program.model.data.StructureDataType;
import ghidra.program.model.data.TypedefDataType;
import ghidra.program.model.listing.Function;
import ghidra.program.model.symbol.Namespace;
import ghidra.program.model.symbol.SourceType;
import ghidra.program.model.symbol.Symbol;

public class MarkupSource extends GhidraScript {

	private static final Set<String> FUNCTIONS = Set.of("parse_verbosity", "checksum",
		"log_message", "retry_operation", "flaky_op", "make_shape", "process_shapes", "main");
	private static final Set<String> CLASSES = Set.of("Shape", "Rect", "Circle");

	@Override
	protected void run() throws Exception {
		DataTypeManager dtm = currentProgram.getDataTypeManager();
		CategoryPath cat = new CategoryPath("/UserTypes");

		int renamed = 0;
		Function checksum = null;
		for (Function f : currentProgram.getFunctionManager().getFunctions(true)) {
			if (f.isThunk() || f.isExternal()) {
				continue;
			}
			Namespace ns = f.getParentNamespace();
			boolean ours = FUNCTIONS.contains(f.getName()) ||
				(!ns.isGlobal() && CLASSES.contains(ns.getName()));
			if (!ours) {
				continue;
			}
			if (f.getName().equals("checksum")) {
				checksum = f;
			}
			f.setName(f.getName() + "_u", SourceType.USER_DEFINED);
			renamed++;
		}

		DataType logText = dtm.resolve(new TypedefDataType(cat, "LogText",
			new PointerDataType(CharDataType.dataType, dtm), dtm), DataTypeConflictHandler.DEFAULT_HANDLER);
		FunctionDefinitionDataType sig = new FunctionDefinitionDataType(checksum, true);
		sig.setReturnType(IntegerDataType.dataType);
		sig.setArguments(new ParameterDefinition[] { new ParameterDefinitionImpl("text", logText, "") });
		ApplyFunctionSignatureCmd cmd = new ApplyFunctionSignatureCmd(checksum.getEntryPoint(), sig,
			SourceType.USER_DEFINED, true, false, DataTypeConflictHandler.DEFAULT_HANDLER,
			FunctionRenameOption.NO_CHANGE);
		if (!cmd.applyTo(currentProgram, monitor)) {
			throw new IllegalStateException(cmd.getStatusMsg());
		}

		StructureDataType appConfig = new StructureDataType(cat, "AppConfig", 0, dtm);
		appConfig.add(IntegerDataType.dataType, "verbosity", "");
		appConfig.add(IntegerDataType.dataType, "retries", "");
		appConfig.add(new PointerDataType(CharDataType.dataType, dtm), "name", "");
		DataType appConfigDt = dtm.resolve(appConfig, DataTypeConflictHandler.DEFAULT_HANDLER);

		StructureDataType stats = new StructureDataType(cat, "ShapeStats", 0, dtm);
		stats.add(IntegerDataType.dataType, "count", "");
		stats.add(DoubleDataType.dataType, "total_area", "");
		dtm.resolve(stats, DataTypeConflictHandler.DEFAULT_HANDLER);

		relabel("g_config", "g_app_config");
		Symbol cfg = getSymbol("g_app_config", null);
		DataUtilities.createData(currentProgram, cfg.getAddress(), appConfigDt, -1,
			DataUtilities.ClearDataMode.CLEAR_ALL_CONFLICT_DATA);
		relabel("g_counter", "g_hits");

		println("MarkupSource: renamed " + renamed + " functions, added user types and labels");
	}

	private void relabel(String from, String to) throws Exception {
		Symbol s = getSymbol(from, null);
		if (s == null) {
			throw new IllegalStateException("symbol not found: " + from);
		}
		s.setName(to, SourceType.USER_DEFINED);
	}
}
