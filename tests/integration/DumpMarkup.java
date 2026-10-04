// Integration test helper: dumps the markup the apply step is responsible for, so that
// check_applied.py can compare source and target.
//   function,<entry>,<full name>,<name source>,<prototype>|<signature source>
//   label,<address>,<full name>,<source>,<data type path>
//   type,<path>,,,<length>|<components>
// Usage: -postScript DumpMarkup.java <out.csv>
//@category Matching.Tests

import java.io.PrintWriter;
import java.nio.charset.StandardCharsets;
import java.nio.file.Files;
import java.nio.file.Path;
import java.util.Iterator;

import ghidra.app.script.GhidraScript;
import ghidra.program.model.data.DataType;
import ghidra.program.model.data.DataTypeComponent;
import ghidra.program.model.data.Structure;
import ghidra.program.model.listing.Data;
import ghidra.program.model.listing.Function;
import ghidra.program.model.symbol.SourceType;
import ghidra.program.model.symbol.Symbol;
import ghidra.program.model.symbol.SymbolIterator;
import ghidra.program.model.symbol.SymbolType;

public class DumpMarkup extends GhidraScript {

	@Override
	protected void run() throws Exception {
		Path out = Path.of(getScriptArgs()[0]);
		try (PrintWriter w = new PrintWriter(Files.newBufferedWriter(out, StandardCharsets.UTF_8))) {
			w.println("kind,key,name,source,detail");
			for (Function f : currentProgram.getFunctionManager().getFunctions(true)) {
				w.println(row("function", f.getEntryPoint().toString(false), f.getName(true),
					f.getSymbol().getSource().name(),
					f.getSignature().getPrototypeString() + "|" + f.getSignatureSource().name()));
			}
			SymbolIterator it = currentProgram.getSymbolTable().getAllSymbols(false);
			while (it.hasNext()) {
				Symbol s = it.next();
				if (s.getSymbolType() != SymbolType.LABEL || !s.isPrimary() ||
					s.getSource() == SourceType.DEFAULT || !s.getAddress().isMemoryAddress()) {
					continue;
				}
				Data d = getDataAt(s.getAddress());
				String dt = d != null && d.isDefined() ? d.getDataType().getPathName() : "";
				w.println(row("label", s.getAddress().toString(false), s.getName(true),
					s.getSource().name(), dt));
			}
			Iterator<DataType> types = currentProgram.getDataTypeManager().getAllDataTypes();
			while (types.hasNext()) {
				DataType dt = types.next();
				if (!dt.getCategoryPath().getPath().startsWith("/UserTypes")) {
					continue;
				}
				StringBuilder detail = new StringBuilder(Integer.toString(dt.getLength()));
				if (dt instanceof Structure) {
					for (DataTypeComponent c : ((Structure) dt).getDefinedComponents()) {
						detail.append('|').append(c.getDataType().getName()).append(' ')
								.append(c.getFieldName());
					}
				}
				w.println(row("type", dt.getPathName(), dt.getName(), "", detail.toString()));
			}
		}
		println("DumpMarkup: wrote " + out);
	}

	private static String row(String... fields) {
		StringBuilder sb = new StringBuilder();
		for (int i = 0; i < fields.length; i++) {
			String f = fields[i];
			if (i > 0) {
				sb.append(',');
			}
			if (f.contains(",") || f.contains("\"")) {
				f = '"' + f.replace("\"", "\"\"") + '"';
			}
			sb.append(f);
		}
		return sb.toString();
	}
}
