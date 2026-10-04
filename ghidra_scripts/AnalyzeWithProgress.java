// Runs auto-analysis on the current program and prints progress while it runs: the active
// analyzer, its progress and the elapsed time. Optionally copies the analysis options of
// another program in the same project first, so a new build is analysed exactly like the
// build it will be matched against.
//
// Headless (used by `ghidra-match update`):
//   analyzeHeadless <projDir> <projName>/<folder> -import <exe> -noanalysis \
//       -scriptPath ghidra_scripts -postScript AnalyzeWithProgress.java [/<folder>/<program>]
// GUI: run on an open program; you are asked for the program to copy options from (Cancel
// keeps the current options).
//
//@category Matching
//@author ghidra_matching

import java.util.Timer;
import java.util.TimerTask;

import ghidra.app.plugin.core.analysis.AutoAnalysisManager;
import ghidra.app.script.GhidraScript;
import ghidra.framework.model.DomainFile;
import ghidra.framework.model.DomainObject;
import ghidra.framework.options.Options;
import ghidra.program.model.listing.Program;
import ghidra.util.exception.CancelledException;
import ghidra.util.task.TaskMonitorAdapter;

public class AnalyzeWithProgress extends GhidraScript {

	/** Status line at least this often, even if nothing changed. */
	private static final long HEARTBEAT_MS = 30_000;
	/** At most one line per this interval for message changes. */
	private static final long MIN_LINE_MS = 3_000;

	private long start;

	@Override
	protected void run() throws Exception {
		String sourcePath = null;
		String[] args = getScriptArgs();
		if (args.length > 0) {
			sourcePath = args[0];
		}
		else if (!isRunningHeadless()) {
			try {
				sourcePath = askDomainFile("Copy analysis options from (Cancel: keep current)")
						.getPathname();
			}
			catch (CancelledException e) {
				sourcePath = null;
			}
		}
		if (sourcePath != null && !sourcePath.isBlank()) {
			copyAnalysisOptions(sourcePath);
		}

		start = System.currentTimeMillis();
		AutoAnalysisManager mgr = AutoAnalysisManager.getAnalysisManager(currentProgram);
		mgr.initializeOptions();
		mgr.reAnalyzeAll(null);

		PrintingMonitor progress = new PrintingMonitor();
		Timer heartbeat = new Timer("analysis-heartbeat", true);
		heartbeat.scheduleAtFixedRate(new TimerTask() {
			@Override
			public void run() {
				progress.status(true);
			}
		}, HEARTBEAT_MS, HEARTBEAT_MS);
		status("Analysis started for " + currentProgram.getName());
		try {
			mgr.startAnalysis(progress, true);
		}
		finally {
			heartbeat.cancel();
		}
		status(String.format("Analysis finished: %d functions, %s elapsed",
			currentProgram.getFunctionManager().getFunctionCount(), elapsed()));
	}

	private void copyAnalysisOptions(String sourcePath) throws Exception {
		DomainFile df = state.getProject().getProjectData().getFile(sourcePath);
		if (df == null) {
			throw new IllegalArgumentException("Program not found in project: " + sourcePath);
		}
		DomainObject obj = df.getReadOnlyDomainObject(this, DomainFile.DEFAULT_VERSION, monitor);
		int copied = 0;
		int failed = 0;
		try {
			if (!(obj instanceof Program)) {
				throw new IllegalArgumentException(sourcePath + " is not a program");
			}
			Options src = ((Program) obj).getOptions(Program.ANALYSIS_PROPERTIES);
			Options dst = currentProgram.getOptions(Program.ANALYSIS_PROPERTIES);
			for (String name : src.getOptionNames()) {
				if (src.isDefaultValue(name)) {
					continue;
				}
				try {
					Object value = src.getObject(name, null);
					if (value != null) {
						dst.putObject(name, value);
						copied++;
					}
				}
				catch (RuntimeException e) {
					failed++;
					printerr("could not copy option " + name + ": " +
						e.getMessage());
				}
			}
		}
		finally {
			obj.release(this);
		}
		println(String.format(
			"copied %d non-default analysis options from %s%s", copied,
			sourcePath, failed > 0 ? " (" + failed + " failed)" : ""));
	}

	private void status(String message) {
		println("[" + elapsed() + "] " + message);
	}

	private String elapsed() {
		long s = (System.currentTimeMillis() - start) / 1000;
		return String.format("%d:%02d:%02d", s / 3600, (s / 60) % 60, s % 60);
	}

	/** Prints analyzer messages and progress, throttled, plus a periodic heartbeat. */
	private class PrintingMonitor extends TaskMonitorAdapter {
		private volatile String message = "";
		private volatile long progress;
		private volatile long maximum;
		private String lastPrinted = "";
		private long lastPrintTime;

		PrintingMonitor() {
			super(true);
		}

		@Override
		public void setMessage(String msg) {
			message = msg == null ? "" : msg;
			status(false);
		}

		@Override
		public String getMessage() {
			return message;
		}

		@Override
		public void initialize(long max) {
			maximum = max;
			progress = 0;
		}

		@Override
		public void setMaximum(long max) {
			maximum = max;
		}

		@Override
		public long getMaximum() {
			return maximum;
		}

		@Override
		public void setProgress(long value) {
			progress = value;
		}

		@Override
		public void incrementProgress(long amount) {
			progress += amount;
		}

		@Override
		public long getProgress() {
			return progress;
		}

		synchronized void status(boolean heartbeat) {
			long now = System.currentTimeMillis();
			String line = message;
			if (line.isBlank()) {
				line = "working";
			}
			if (maximum > 0 && progress > 0 && progress <= maximum) {
				line += String.format(" (%d%%)", progress * 100 / maximum);
			}
			boolean changed = !line.equals(lastPrinted);
			if (heartbeat ? now - lastPrintTime < HEARTBEAT_MS / 2 : !changed ||
				now - lastPrintTime < MIN_LINE_MS) {
				return;
			}
			lastPrinted = line;
			lastPrintTime = now;
			AnalyzeWithProgress.this.status((heartbeat && !changed ? "still running: " : "") + line);
		}
	}
}
