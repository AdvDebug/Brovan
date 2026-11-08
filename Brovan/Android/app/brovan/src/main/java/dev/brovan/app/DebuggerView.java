package dev.brovan.app;

import android.content.ClipData;
import android.content.ClipboardManager;
import android.content.Context;
import android.graphics.Paint;
import android.graphics.Typeface;
import android.text.Spannable;
import android.text.SpannableStringBuilder;
import android.text.style.ForegroundColorSpan;
import android.text.style.StyleSpan;
import android.util.AttributeSet;
import android.util.SparseIntArray;
import android.util.TypedValue;
import android.view.LayoutInflater;
import android.view.View;
import android.view.ViewGroup;
import android.view.inputmethod.EditorInfo;
import android.widget.EditText;
import android.widget.FrameLayout;
import android.widget.LinearLayout;
import android.widget.TextView;
import android.widget.Toast;

import androidx.annotation.NonNull;
import androidx.annotation.Nullable;
import androidx.core.content.ContextCompat;
import androidx.recyclerview.widget.GridLayoutManager;
import androidx.recyclerview.widget.LinearLayoutManager;
import androidx.recyclerview.widget.RecyclerView;

import com.google.android.material.button.MaterialButton;
import com.google.android.material.tabs.TabLayout;

import java.util.ArrayDeque;
import java.util.ArrayList;
import java.util.Arrays;
import java.util.HashMap;
import java.util.HashSet;
import java.util.List;
import java.util.Locale;
import java.util.Map;
import java.util.Set;
import java.util.function.Consumer;

import dev.brovan.BrovanNative;

public class DebuggerView extends LinearLayout {

    public interface Listener {
        void onDebuggerMessage(String line);

        void onShowProgram();
    }

    private enum Tab {
        LOG(R.string.debug_tab_log, null, false),
        REGISTERS(R.string.debug_tab_registers, null, true),
        STACK(R.string.debug_tab_stack, "stack . " + STACK_FRAMES, true),
        THREADS(R.string.debug_tab_threads, "threads", false),
        MODULES(R.string.debug_tab_modules, "modules", false),
        MEMORY(R.string.debug_tab_memory, null, true),
        BREAKPOINTS(R.string.debug_tab_breakpoints, "bp", false),
        REGIONS(R.string.debug_tab_regions, "regions", false);

        final int label;
        final String query;
        final boolean needsStop;

        Tab(int label, String query, boolean needsStop) {
            this.label = label;
            this.query = query;
            this.needsStop = needsStop;
        }
    }

    private static final long POLL_INTERVAL_MS = 400;
    private static final long COMMAND_SETTLE_MS = 250;
    private static final int DISASSEMBLY_LINES = 96;
    private static final int MEMORY_LENGTH = 512;
    private static final int MEMORY_ROW_SPACING = 3;
    private static final int MEMORY_COLUMNS_PER_BYTE = 4;
    private static final int STACK_FRAMES = 32;
    private static final int HISTORY_LIMIT = 50;
    private static final int REGISTER_CELL_CHARS = 26;
    private static final String ZEROS = "0000000000000000";

    private final RowAdapter code = new RowAdapter(this::onCodeClicked, this::onCodeLongPressed);
    private final RowAdapter panel = new RowAdapter(this::onPanelClicked, null);
    private final Set<Long> breakpoints = new HashSet<>();
    private final ArrayDeque<String> history = new ArrayDeque<>();
    private final List<String[]> registerRecords = new ArrayList<>();
    private final SparseIntArray colors = new SparseIntArray();
    private Map<String, String> previousRegisters = new HashMap<>();
    private Map<String, String> currentRegisters = new HashMap<>();
    private String[] panelRecords;

    private TextView state;
    private TextView stats;
    private TextView codeEmpty;
    private TextView panelEmpty;
    private TextView memoryLabel;
    private TabLayout tabs;
    private RecyclerView codeRows;
    private RecyclerView panelRows;
    private GridLayoutManager panelLayout;
    private View logScroll;
    private View memoryBar;
    private View commandRow;
    private MaterialButton run;
    private MaterialButton step;
    private MaterialButton stepOver;

    private Listener listener;
    private Tab tab = Tab.LOG;
    private int rowBackground;
    private int rowPadding;
    private int runMode = -1;
    private float charWidth;
    private boolean developerMode = true;
    private boolean started;
    private boolean paused;
    private boolean wide = true;
    private long instructionPointer;
    private long codeShownAt = -1;
    private long panelShownAt = -1;
    private long registersAt = -1;
    private long disassemblyAddress;
    private long memoryAddress;
    private long memoryShownAt;
    private long runToAddress;
    private long stopExecuted = -1;

    private final Runnable poll = new Runnable() {
        @Override
        public void run() {
            if (!developerMode) {
                return;
            }

            readState();
            if (isShown()) {
                postDelayed(this, POLL_INTERVAL_MS);
            }
        }
    };

    private final Runnable settle = () -> {
        codeShownAt = -1;
        panelShownAt = -1;
        readState();
    };

    public DebuggerView(Context context) {
        this(context, null);
    }

    public DebuggerView(Context context, @Nullable AttributeSet attributes) {
        super(context, attributes);
        setOrientation(VERTICAL);
        LayoutInflater.from(context).inflate(R.layout.view_debugger, this, true);
    }

    @Override
    protected void onFinishInflate() {
        super.onFinishInflate();

        state = findViewById(R.id.debug_state);
        stats = findViewById(R.id.debug_stats);
        codeEmpty = findViewById(R.id.debug_code_empty);
        panelEmpty = findViewById(R.id.debug_empty);
        memoryLabel = findViewById(R.id.debug_memory_address);
        tabs = findViewById(R.id.debug_tabs);
        codeRows = findViewById(R.id.debug_code);
        panelRows = findViewById(R.id.debug_rows);
        logScroll = findViewById(R.id.log_scroll);
        memoryBar = findViewById(R.id.debug_memory_bar);
        commandRow = findViewById(R.id.debug_command_row);
        run = findViewById(R.id.debug_run);
        step = findViewById(R.id.debug_step);
        stepOver = findViewById(R.id.debug_step_over);

        codeRows.setLayoutManager(new LinearLayoutManager(getContext()));
        codeRows.setAdapter(code);

        panelLayout = new GridLayoutManager(getContext(), 1);
        panelLayout.setSpanSizeLookup(new GridLayoutManager.SpanSizeLookup() {
            @Override
            public int getSpanSize(int position) {
                return panel.isCell(position) ? 1 : panelLayout.getSpanCount();
            }
        });
        panelRows.setLayoutManager(panelLayout);
        panelRows.setAdapter(panel);
        panelRows.addOnLayoutChangeListener((view, left, top, right, bottom, oldLeft, oldTop, oldRight, oldBottom) -> {
            if (right - left != oldRight - oldLeft) {
                post(this::fitPanelToWidth);
            }
        });

        Paint measure = new Paint();
        measure.setTypeface(Typeface.MONOSPACE);
        measure.setTextSize(getResources().getDimension(R.dimen.debug_row_text));
        charWidth = Math.max(1f, measure.measureText("0"));
        rowPadding = 2 * getResources().getDimensionPixelSize(R.dimen.debug_row_padding);

        TypedValue background = new TypedValue();
        getContext().getTheme().resolveAttribute(android.R.attr.selectableItemBackground, background, true);
        rowBackground = background.resourceId;

        for (Tab value : Tab.values()) {
            tabs.addTab(tabs.newTab().setText(value.label));
        }

        tabs.addOnTabSelectedListener(new TabLayout.OnTabSelectedListener() {
            @Override
            public void onTabSelected(TabLayout.Tab selected) {
                tab = Tab.values()[selected.getPosition()];
                panelShownAt = -1;
                refreshPanel();
            }

            @Override
            public void onTabUnselected(TabLayout.Tab selected) {
            }

            @Override
            public void onTabReselected(TabLayout.Tab selected) {
                panelShownAt = -1;
                refreshPanel();
            }
        });

        run.setOnClickListener(view -> {
            if (!started) {
                send("start");
            } else if (paused) {
                send("c");
            } else {
                requestPause();
            }
        });
        step.setOnClickListener(view -> send("step"));
        stepOver.setOnClickListener(view -> send("stepover"));
        findViewById(R.id.debug_goto).setOnClickListener(view -> askForAddress());
        findViewById(R.id.debug_program).setOnClickListener(view -> {
            Listener current = listener;
            if (current != null) {
                current.onShowProgram();
            }
        });

        findViewById(R.id.debug_memory_previous).setOnClickListener(view -> showMemoryAt(memoryShownAt - MEMORY_LENGTH));
        findViewById(R.id.debug_memory_next).setOnClickListener(view -> showMemoryAt(memoryShownAt + MEMORY_LENGTH));
        memoryLabel.setOnClickListener(view -> askForAddress());

        findViewById(R.id.debug_history).setOnClickListener(view -> showHistory());
        ((EditText) findViewById(R.id.command)).setOnEditorActionListener((view, action, event) -> {
            if (action != EditorInfo.IME_ACTION_SEND) {
                return false;
            }

            findViewById(R.id.send).performClick();
            return true;
        });

        updateButtons(false);
    }

    public void setListener(Listener value) {
        listener = value;
    }

    /**
     * Without developer mode the panel is the emulator log and nothing else, which is all a start-up failure
     * has to show a player.
     */
    public void setDeveloperMode(boolean enabled) {
        developerMode = enabled;

        int visibility = enabled ? VISIBLE : GONE;
        findViewById(R.id.debug_bar).setVisibility(visibility);
        findViewById(R.id.debug_bar_divider).setVisibility(visibility);
        findViewById(R.id.debug_code_pane).setVisibility(visibility);
        findViewById(R.id.debug_pane_divider).setVisibility(visibility);
        tabs.setVisibility(visibility);
        commandRow.setVisibility(enabled && tab == Tab.LOG ? VISIBLE : GONE);
    }

    public boolean isLogVisible() {
        return isShown() && tab == Tab.LOG;
    }

    public void submit(String command) {
        history.remove(command);
        history.addFirst(command);
        while (history.size() > HISTORY_LIMIT) {
            history.removeLast();
        }

        send(command);
    }

    public void send(String command) {
        if (command.isEmpty()) {
            return;
        }

        if (command.equals("start") || command.equals("run")) {
            started = true;
        }

        BrovanNative.sendCommand(command);
        removeCallbacks(settle);
        postDelayed(settle, COMMAND_SETTLE_MS);
    }

    @Override
    protected void onVisibilityChanged(@NonNull View changed, int visibility) {
        super.onVisibilityChanged(changed, visibility);

        removeCallbacks(poll);
        if (isShown()) {
            post(poll);
        }
    }

    @Override
    protected void onAttachedToWindow() {
        super.onAttachedToWindow();

        if (isShown()) {
            post(poll);
        }
    }

    @Override
    protected void onDetachedFromWindow() {
        super.onDetachedFromWindow();
        removeCallbacks(poll);
        removeCallbacks(settle);
    }

    private void requestPause() {
        if (!started) {
            report(getContext().getString(R.string.debug_not_started));
            return;
        }

        BrovanNative.debugPause();
        report(getContext().getString(R.string.debug_pausing));
    }

    private void readState() {
        String[] records = BrovanNative.debugQuery("state");
        if (records.length == 0) {
            return;
        }

        String[] fields = records[0].split("\\|", -1);
        if (fields.length < 9) {
            return;
        }

        boolean wasPaused = paused;
        long previousIp = instructionPointer;
        long executed = parseLong(fields[8]);
        paused = "paused".equals(fields[0]);
        instructionPointer = parseHex(fields[2]);

        // A short run can start and stop between two polls, so a stop is new when the guest moved since the last one.
        boolean newStop = paused && (!wasPaused || executed != stopExecuted || instructionPointer != previousIp);
        if (paused) {
            stopExecuted = executed;
        }

        wide = !"x86".equals(fields[4]);
        boolean alive = BrovanNative.isRunning();
        state.setText(stateLabel(alive));

        String counters = getContext().getString(R.string.debug_stats, parseInt(fields[5]), parseInt(fields[6]),
                String.format(Locale.getDefault(), "%,d", executed));
        stats.setText(fields[3].isEmpty() ? counters : fields[3] + "  ·  " + counters);
        updateButtons(alive);

        if (!paused) {
            registersAt = -1;
        }

        if (newStop) {
            // A stop moves the disassembly back to wherever the guest actually is.
            disassemblyAddress = 0;
            registersAt = -1;
            codeShownAt = -1;
            panelShownAt = -1;

            if (runToAddress != 0) {
                long target = runToAddress;
                runToAddress = 0;
                send("bp del " + hex(target));
            }
        }

        refresh();
    }

    private void updateButtons(boolean running) {
        boolean alive = !started || running;
        boolean canStep = alive && started && paused;
        int mode = !started ? R.string.debug_run : paused || !alive ? R.string.debug_continue : R.string.debug_pause;

        if (mode != runMode) {
            runMode = mode;
            run.setText(mode);
            run.setIconResource(mode == R.string.debug_pause ? R.drawable.ic_pause : R.drawable.ic_play);
        }

        run.setEnabled(alive);
        step.setEnabled(canStep);
        stepOver.setEnabled(canStep);
    }

    private void refresh() {
        if (paused && registersAt != instructionPointer) {
            readRegisters();
        }

        refreshCode();
        refreshPanel();
    }

    private void refreshCode() {
        if (!developerMode) {
            return;
        }

        if (!started || !paused || instructionPointer == 0) {
            codeRows.setVisibility(GONE);
            codeEmpty.setVisibility(VISIBLE);
            codeEmpty.setText(started ? R.string.debug_pause_first : R.string.debug_not_started);
            return;
        }

        if (codeShownAt == instructionPointer && !code.isEmpty()) {
            return;
        }

        // Replacing the rows under a scroll or a layout pass throws, so the next poll builds them instead.
        if (busy(codeRows)) {
            return;
        }

        readBreakpoints();
        List<Row> built = buildDisassembly();
        if (built.isEmpty() && !code.isEmpty()) {
            return;
        }

        codeShownAt = instructionPointer;
        code.replace(built);
        codeRows.setVisibility(built.isEmpty() ? GONE : VISIBLE);
        codeEmpty.setVisibility(built.isEmpty() ? VISIBLE : GONE);
        codeEmpty.setText(R.string.debug_empty);
        scrollToCurrent(built);
    }

    private void refreshPanel() {
        boolean log = tab == Tab.LOG;
        logScroll.setVisibility(log ? VISIBLE : GONE);
        commandRow.setVisibility(developerMode && log ? VISIBLE : GONE);
        memoryBar.setVisibility(tab == Tab.MEMORY && paused ? VISIBLE : GONE);

        if (log) {
            panelRows.setVisibility(GONE);
            panelEmpty.setVisibility(GONE);
            return;
        }

        if (tab.needsStop && !paused) {
            panelRows.setVisibility(GONE);
            panelEmpty.setVisibility(VISIBLE);
            panelEmpty.setText(started ? R.string.debug_pause_first : R.string.debug_not_started);
            return;
        }

        if (paused && panelShownAt == instructionPointer && !panel.isEmpty()) {
            return;
        }

        if (busy(panelRows)) {
            return;
        }

        String[] records = tab.query != null ? BrovanNative.debugQuery(tab.query) : null;
        if (records != null && panelShownAt != -1 && !panel.isEmpty() && Arrays.equals(records, panelRecords)) {
            return;
        }

        List<Row> built = buildPanel(records);

        // A query made while the guest runs can come back empty, so the rows on screen stay until a real result.
        if (built.isEmpty() && !paused && !panel.isEmpty()) {
            return;
        }

        panelShownAt = instructionPointer;
        panelRecords = records;
        panel.replace(built);
        panelRows.setVisibility(built.isEmpty() ? GONE : VISIBLE);
        panelEmpty.setVisibility(built.isEmpty() ? VISIBLE : GONE);
        panelEmpty.setText(tab == Tab.BREAKPOINTS ? R.string.debug_breakpoints_hint : R.string.debug_empty);
    }

    private static boolean busy(RecyclerView list) {
        return list.isComputingLayout() || list.getScrollState() != RecyclerView.SCROLL_STATE_IDLE;
    }

    private List<Row> buildPanel(String[] records) {
        switch (tab) {
            case REGISTERS: return buildRegisters();
            case STACK: return buildStack(records);
            case THREADS: return buildThreads(records);
            case MODULES: return buildModules(records);
            case MEMORY: return buildMemory();
            case BREAKPOINTS: return buildBreakpoints(records);
            case REGIONS: return buildRegions(records);
            default: return new ArrayList<>();
        }
    }

    private void fitPanelToWidth() {
        int width = panelRows.getWidth() - rowPadding;
        int spans = Math.max(1, (int) (width / (charWidth * REGISTER_CELL_CHARS)));
        if (spans != panelLayout.getSpanCount()) {
            panelLayout.setSpanCount(spans);
        }

        if (tab == Tab.MEMORY) {
            panelShownAt = -1;
            refreshPanel();
        }
    }

    private List<Row> buildDisassembly() {
        long start = disassemblyAddress != 0 ? disassemblyAddress : instructionPointer;
        List<Row> built = new ArrayList<>();

        for (String record : BrovanNative.debugQuery("disasm " + hex(start) + " " + DISASSEMBLY_LINES)) {
            String[] fields = record.split("\\|", -1);
            if (fields.length < 3) {
                continue;
            }

            long address = parseHex(fields[0]);
            boolean current = address == instructionPointer;
            SpannableStringBuilder text = new SpannableStringBuilder();

            append(text, breakpoints.contains(address) ? "●" : " ", R.color.debug_breakpoint);
            append(text, current ? "▶ " : "  ", R.color.accent);
            append(text, address(address) + "  ", R.color.asm_address);
            append(text, shortBytes(fields[1]) + "  ", R.color.asm_bytes);
            append(text, fields[2], R.color.asm_mnemonic);

            if (fields.length > 3 && !fields[3].isEmpty()) {
                append(text, " ", R.color.text_primary);
                appendTokens(text, fields[3]);
            }

            built.add(new Row(text, address, current, false));
        }

        return built;
    }

    private void readRegisters() {
        registerRecords.clear();
        previousRegisters = currentRegisters;
        currentRegisters = new HashMap<>();

        for (String record : BrovanNative.debugQuery("regs .")) {
            String[] fields = record.split("\\|", -1);
            if (fields.length < 4) {
                continue;
            }

            registerRecords.add(fields);
            currentRegisters.put(fields[1], fields[2]);
        }

        registersAt = instructionPointer;
    }

    private List<Row> buildRegisters() {
        List<Row> built = new ArrayList<>();
        String group = "";

        for (String[] fields : registerRecords) {
            if (!fields[0].equals(group)) {
                group = fields[0];
                built.add(new Row(header(group), 0, false, false));
            }

            String before = previousRegisters.get(fields[1]);
            boolean changed = before != null && !before.equals(fields[2]);
            int color = changed ? R.color.log_warn : isZero(fields[2]) ? R.color.debug_value_zero : R.color.debug_value;

            SpannableStringBuilder text = new SpannableStringBuilder();
            append(text, pad(fields[1], 7), R.color.asm_register);
            append(text, fields[2], color);

            if (!fields[3].isEmpty()) {
                append(text, "  " + fields[3], R.color.text_secondary);
            }

            built.add(new Row(text, parseHex(fields[2]), false, fields[3].isEmpty()));
        }

        return built;
    }

    private List<Row> buildStack(String[] records) {
        List<Row> built = new ArrayList<>();
        boolean guessed = false;
        int number = 0;

        for (String record : records) {
            String[] fields = record.split("\\|", -1);
            if (fields.length < 5) {
                continue;
            }

            boolean raw = "raw".equals(fields[4]);
            SpannableStringBuilder text = new SpannableStringBuilder();
            append(text, pad("#" + number++, 5), R.color.asm_address);
            append(text, fields[2].isEmpty() ? address(parseHex(fields[1])) : fields[2], R.color.text_primary);
            append(text, "  sp=" + fields[3], R.color.text_secondary);

            if (raw) {
                append(text, "  ?", R.color.log_warn);
                guessed = true;
            }

            built.add(new Row(text, parseHex(fields[1]), false, false));
        }

        if (guessed) {
            SpannableStringBuilder note = new SpannableStringBuilder();
            append(note, getContext().getString(R.string.debug_stack_guessed), R.color.text_secondary);
            built.add(new Row(note, 0, false, false));
        }

        return built;
    }

    private List<Row> buildThreads(String[] records) {
        List<Row> built = new ArrayList<>();

        for (String record : records) {
            String[] fields = record.split("\\|", -1);
            if (fields.length < 10) {
                continue;
            }

            boolean current = "1".equals(fields[2]);
            SpannableStringBuilder text = new SpannableStringBuilder();
            append(text, current ? "▶ " : "  ", R.color.accent);
            append(text, pad(fields[0], 7), R.color.text_primary);
            append(text, pad(fields[1], 11), colorForState(fields[1]));
            append(text, address(parseHex(fields[3])) + "  ", R.color.asm_address);
            append(text, fields[9], R.color.text_primary);
            append(text, "\n    " + fields[8] + "  prio " + fields[6] + "  " + fields[7] + " instructions",
                    R.color.text_secondary);

            built.add(new Row(text, parseLong(fields[0]), current, false));
        }

        return built;
    }

    private List<Row> buildModules(String[] records) {
        List<Row> built = new ArrayList<>();

        for (String record : records) {
            String[] fields = record.split("\\|", -1);
            if (fields.length < 5) {
                continue;
            }

            SpannableStringBuilder text = new SpannableStringBuilder();
            append(text, address(parseHex(fields[1])) + "  ", R.color.asm_address);
            append(text, fields[0], R.color.text_primary);
            append(text, "  " + size(fields[2]), R.color.text_secondary);

            built.add(new Row(text, parseHex(fields[1]), false, false));
        }

        return built;
    }

    private List<Row> buildMemory() {
        long start = memoryAddress != 0 ? memoryAddress : stackPointer();
        memoryShownAt = start;
        memoryLabel.setText(getContext().getString(R.string.debug_memory_range, address(start), MEMORY_LENGTH));

        StringBuilder bytes = new StringBuilder(MEMORY_LENGTH * 2);
        for (String record : BrovanNative.debugQuery("mem " + hex(start) + " " + MEMORY_LENGTH)) {
            String[] fields = record.split("\\|", -1);
            if (fields.length < 2 || parseHex(fields[0]) != start + bytes.length() / 2) {
                break;
            }

            bytes.append(fields[1]);
        }

        int perRow = bytesPerRow();
        List<Row> built = new ArrayList<>();

        for (int offset = 0; offset * 2 < bytes.length(); offset += perRow) {
            String line = bytes.substring(offset * 2, Math.min(bytes.length(), (offset + perRow) * 2));
            long address = start + offset;

            SpannableStringBuilder text = new SpannableStringBuilder();
            append(text, address(address) + "  ", R.color.asm_address);
            append(text, spaced(line) + " ", R.color.debug_value);
            append(text, printable(line), R.color.asm_label);

            built.add(new Row(text, address, false, false));
        }

        return built;
    }

    private int bytesPerRow() {
        int width = panelRows.getWidth() > 0 ? panelRows.getWidth() : getWidth() / 2;
        int columns = (int) ((width - rowPadding) / charWidth);
        int fits = (columns - addressDigits() - MEMORY_ROW_SPACING) / MEMORY_COLUMNS_PER_BYTE;
        return fits >= 32 ? 32 : fits >= 16 ? 16 : 8;
    }

    private long stackPointer() {
        String value = currentRegisters.get(wide ? "RSP" : "ESP");
        long pointer = value == null ? 0 : parseHex(value);
        return pointer != 0 ? pointer : instructionPointer;
    }

    private List<Row> buildBreakpoints(String[] records) {
        List<Row> built = new ArrayList<>();

        for (String record : records) {
            String[] fields = record.split("\\|", -1);
            if (fields.length < 4) {
                continue;
            }

            SpannableStringBuilder text = new SpannableStringBuilder();

            if ("bp".equals(fields[0])) {
                append(text, "● ", R.color.debug_breakpoint);
                append(text, fields[2].isEmpty() ? address(parseHex(fields[1])) : fields[2], R.color.text_primary);

                if (!fields[3].isEmpty()) {
                    append(text, "  if (" + fields[3] + ")", R.color.text_secondary);
                }

                built.add(new Row(text, parseHex(fields[1]), false, false));
                continue;
            }

            append(text, "■ ", R.color.log_warn);
            append(text, fields[4] + " " + address(parseHex(fields[2])), R.color.text_primary);
            append(text, "  " + fields[3] + " bytes", R.color.text_secondary);
            built.add(new Row(text, parseHex(fields[2]), false, false));
        }

        return built;
    }

    private List<Row> buildRegions(String[] records) {
        List<Row> built = new ArrayList<>();

        for (String record : records) {
            String[] fields = record.split("\\|", -1);
            if (fields.length < 4) {
                continue;
            }

            long base = parseHex(fields[0]);
            SpannableStringBuilder text = new SpannableStringBuilder();
            append(text, address(base) + "  ", R.color.asm_address);
            append(text, pad(fields[2], 22), R.color.asm_memory);
            append(text, size(fields[1]), R.color.text_secondary);

            if (!fields[3].isEmpty()) {
                append(text, "  " + fields[3], R.color.text_primary);
            }

            built.add(new Row(text, base, false, false));
        }

        return built;
    }

    private void readBreakpoints() {
        breakpoints.clear();

        for (String record : BrovanNative.debugQuery("bp")) {
            String[] fields = record.split("\\|", -1);
            if (fields.length > 1 && "bp".equals(fields[0])) {
                breakpoints.add(parseHex(fields[1]));
            }
        }
    }

    private void onCodeClicked(Row row) {
        toggleBreakpoint(row.address);
    }

    private void onCodeLongPressed(Row row) {
        CharSequence[] actions = {
                getContext().getString(R.string.debug_run_here),
                getContext().getString(R.string.debug_toggle_breakpoint),
                getContext().getString(R.string.debug_show_memory),
                getContext().getString(R.string.debug_copy_address)
        };

        Theming.dialog(getContext())
                .setTitle(address(row.address))
                .setItems(actions, (dialog, index) -> {
                    switch (index) {
                        case 0: runTo(row.address); break;
                        case 1: toggleBreakpoint(row.address); break;
                        case 2: showMemoryAt(row.address); break;
                        default: copyAddress(row.address); break;
                    }
                })
                .show();
    }

    private void onPanelClicked(Row row) {
        switch (tab) {
            case THREADS:
                send("threads switch " + row.address);
                return;

            case STACK:
            case MODULES:
            case BREAKPOINTS:
            case REGIONS:
                showDisassemblyAt(row.address);
                return;

            default:
        }
    }

    private void toggleBreakpoint(long address) {
        if (!paused) {
            report(getContext().getString(R.string.debug_pause_first));
            return;
        }

        send(breakpoints.contains(address) ? "bp del " + hex(address) : "bp add " + hex(address));
    }

    private void runTo(long address) {
        if (!paused) {
            report(getContext().getString(R.string.debug_pause_first));
            return;
        }

        if (!breakpoints.contains(address)) {
            send("bp add " + hex(address));
            runToAddress = address;
        }

        send("c");
    }

    private void copyAddress(long address) {
        ClipboardManager clipboard = getContext().getSystemService(ClipboardManager.class);
        if (clipboard != null) {
            clipboard.setPrimaryClip(ClipData.newPlainText(address(address), hex(address)));
            Toast.makeText(getContext(), R.string.debug_copied, Toast.LENGTH_SHORT).show();
        }
    }

    private void showDisassemblyAt(long address) {
        if (address == 0) {
            return;
        }

        disassemblyAddress = address;
        codeShownAt = -1;
        refreshCode();
    }

    private void showMemoryAt(long address) {
        if (address == 0) {
            return;
        }

        memoryAddress = address;
        panelShownAt = -1;
        if (tab == Tab.MEMORY) {
            refreshPanel();
        } else {
            tabs.selectTab(tabs.getTabAt(Tab.MEMORY.ordinal()));
        }
    }

    private void showHistory() {
        if (history.isEmpty()) {
            Toast.makeText(getContext(), R.string.debug_history_empty, Toast.LENGTH_SHORT).show();
            return;
        }

        String[] entries = history.toArray(new String[0]);
        Theming.dialog(getContext())
                .setTitle(R.string.debug_history)
                .setItems(entries, (dialog, index) -> {
                    EditText command = findViewById(R.id.command);
                    command.setText(entries[index]);
                    command.setSelection(entries[index].length());
                    command.requestFocus();
                })
                .show();
    }

    private void askForAddress() {
        EditText input = new EditText(getContext());
        input.setHint(R.string.debug_goto_hint);
        input.setSingleLine(true);

        FrameLayout box = new FrameLayout(getContext());
        box.setPadding(dp(24), dp(8), dp(24), 0);
        box.addView(input);

        Theming.dialog(getContext())
                .setTitle(R.string.debug_goto_title)
                .setView(box)
                .setPositiveButton(android.R.string.ok, (dialog, which) -> goTo(input.getText().toString().trim()))
                .setNegativeButton(android.R.string.cancel, null)
                .show();
    }

    private void goTo(String expression) {
        if (expression.isEmpty()) {
            return;
        }

        String[] resolved = BrovanNative.debugQuery("resolve " + expression);
        if (resolved.length == 0 || resolved[0].isEmpty()) {
            report(getContext().getString(R.string.debug_goto_failed, expression));
            return;
        }

        long address = parseHex(resolved[0]);
        if (tab == Tab.MEMORY) {
            showMemoryAt(address);
            return;
        }

        showDisassemblyAt(address);
    }

    private void scrollToCurrent(List<Row> built) {
        for (int i = 0; i < built.size(); i++) {
            if (built.get(i).current) {
                codeRows.scrollToPosition(Math.max(0, i - 4));
                return;
            }
        }

        codeRows.scrollToPosition(0);
    }

    /** The log is one tab among several, so anything worth saying is also said where the user is looking. */
    private void report(String message) {
        Toast.makeText(getContext(), message, Toast.LENGTH_SHORT).show();

        Listener current = listener;
        if (current != null) {
            current.onDebuggerMessage("[*] " + message);
        }
    }

    private String stateLabel(boolean running) {
        if (!started) {
            return getContext().getString(R.string.debug_state_loaded);
        }

        if (!running) {
            return getContext().getString(R.string.debug_state_stopped);
        }

        return getContext().getString(paused ? R.string.debug_state_paused : R.string.debug_state_running);
    }

    private int colorForState(String value) {
        switch (value) {
            case "Running": return R.color.log_ok;
            case "Waiting": return R.color.log_info;
            case "Suspended": return R.color.log_warn;
            case "Terminated": return R.color.text_secondary;
            case "Exception": return R.color.log_error;
            default: return R.color.text_secondary;
        }
    }

    private CharSequence header(String group) {
        SpannableStringBuilder text = new SpannableStringBuilder();
        append(text, group.toUpperCase(Locale.ROOT), R.color.accent);
        text.setSpan(new StyleSpan(Typeface.BOLD), 0, text.length(), Spannable.SPAN_EXCLUSIVE_EXCLUSIVE);
        return text;
    }

    /**
     * Colours one operand run the way the emulator's own console formatter does.
     */
    private void appendTokens(SpannableStringBuilder text, String tokens) {
        for (String token : tokens.split("\u001E")) {
            if (token.isEmpty()) {
                continue;
            }

            append(text, token.substring(1), colorForToken(token.charAt(0)));
        }
    }

    private int colorForToken(char kind) {
        switch (kind) {
            case '2': return R.color.asm_separator;
            case '3': return R.color.asm_mnemonic;
            case '4': return R.color.asm_register;
            case '5': return R.color.asm_immediate;
            case '6': return R.color.asm_label;
            case '7': return R.color.asm_memory;
            default: return R.color.text_primary;
        }
    }

    private void append(SpannableStringBuilder text, String value, int color) {
        int start = text.length();
        text.append(value);
        text.setSpan(new ForegroundColorSpan(color(color)), start, text.length(), Spannable.SPAN_EXCLUSIVE_EXCLUSIVE);
    }

    private int dp(int value) {
        return Math.round(value * getResources().getDisplayMetrics().density);
    }

    private int color(int resource) {
        int index = colors.indexOfKey(resource);
        if (index >= 0) {
            return colors.valueAt(index);
        }

        int value = ContextCompat.getColor(getContext(), resource);
        colors.put(resource, value);
        return value;
    }

    /** The debugger prompt reads plain digits as decimal, so an address always carries its prefix. */
    private static String hex(long value) {
        return "0x" + Long.toHexString(value);
    }

    private int addressDigits() {
        return wide ? 16 : 8;
    }

    private String address(long value) {
        String digits = Long.toHexString(value).toUpperCase(Locale.ROOT);
        int padding = addressDigits() - digits.length();
        return padding > 0 ? ZEROS.substring(0, padding) + digits : digits;
    }

    private static String size(String hex) {
        long bytes = parseHex(hex);
        String human;
        if (bytes >= 1024L * 1024L) {
            human = String.format(Locale.ROOT, "%.1f MB", bytes / (1024.0 * 1024.0));
        } else if (bytes >= 1024L) {
            human = String.format(Locale.ROOT, "%.1f KB", bytes / 1024.0);
        } else {
            human = bytes + " B";
        }

        return "0x" + Long.toHexString(bytes).toUpperCase(Locale.ROOT) + " · " + human;
    }

    private static String shortBytes(String hex) {
        return hex.length() > 12 ? hex.substring(0, 12) + ".." : pad(hex, 14);
    }

    private static String spaced(String hex) {
        StringBuilder text = new StringBuilder(hex.length() + (hex.length() / 2));
        for (int i = 0; i + 1 < hex.length(); i += 2) {
            text.append(hex, i, i + 2).append(' ');
        }

        return text.toString();
    }

    private static String printable(String hex) {
        StringBuilder text = new StringBuilder(hex.length() / 2);
        for (int i = 0; i + 1 < hex.length(); i += 2) {
            int value = Character.digit(hex.charAt(i), 16) << 4 | Character.digit(hex.charAt(i + 1), 16);
            text.append(value >= 0x20 && value < 0x7F ? (char) value : '.');
        }

        return text.toString();
    }

    private static String pad(String value, int width) {
        if (value.length() >= width) {
            return value + " ";
        }

        StringBuilder text = new StringBuilder(value);
        while (text.length() < width) {
            text.append(' ');
        }

        return text.toString();
    }

    private static boolean isZero(String hex) {
        for (int i = 0; i < hex.length(); i++) {
            if (hex.charAt(i) != '0') {
                return false;
            }
        }

        return true;
    }

    private static long parseHex(String value) {
        try {
            return value.isEmpty() ? 0 : Long.parseUnsignedLong(value, 16);
        } catch (NumberFormatException ignored) {
            return 0;
        }
    }

    private static long parseLong(String value) {
        try {
            return value.isEmpty() ? 0 : Long.parseLong(value);
        } catch (NumberFormatException ignored) {
            return 0;
        }
    }

    private static int parseInt(String value) {
        return (int) parseLong(value);
    }

    private static final class Row {
        final CharSequence text;
        final long address;
        final boolean current;
        final boolean cell;

        Row(CharSequence text, long address, boolean current, boolean cell) {
            this.text = text;
            this.address = address;
            this.current = current;
            this.cell = cell;
        }
    }

    private final class RowAdapter extends RecyclerView.Adapter<RowHolder> {

        private final List<Row> entries = new ArrayList<>();
        private final Consumer<Row> click;
        private final Consumer<Row> longClick;

        RowAdapter(Consumer<Row> click, Consumer<Row> longClick) {
            this.click = click;
            this.longClick = longClick;
        }

        void replace(List<Row> value) {
            entries.clear();
            entries.addAll(value);
            notifyDataSetChanged();
        }

        boolean isEmpty() {
            return entries.isEmpty();
        }

        boolean isCell(int position) {
            return position >= 0 && position < entries.size() && entries.get(position).cell;
        }

        @NonNull
        @Override
        public RowHolder onCreateViewHolder(@NonNull ViewGroup parent, int viewType) {
            RowHolder holder = new RowHolder((TextView) LayoutInflater.from(parent.getContext())
                    .inflate(R.layout.item_debug_row, parent, false));
            holder.text.setOnClickListener(view -> deliver(holder, click));

            if (longClick == null) {
                holder.text.setLongClickable(false);
            } else {
                holder.text.setOnLongClickListener(view -> {
                    deliver(holder, longClick);
                    return true;
                });
            }

            return holder;
        }

        @Override
        public void onBindViewHolder(@NonNull RowHolder holder, int position) {
            Row row = entries.get(position);
            holder.text.setText(row.text);

            if (row.current) {
                holder.text.setBackgroundColor(color(R.color.debug_current));
            } else {
                holder.text.setBackgroundResource(rowBackground);
            }
        }

        private void deliver(RowHolder holder, Consumer<Row> action) {
            int position = holder.getBindingAdapterPosition();
            if (position != RecyclerView.NO_POSITION) {
                action.accept(entries.get(position));
            }
        }

        @Override
        public int getItemCount() {
            return entries.size();
        }
    }

    private static final class RowHolder extends RecyclerView.ViewHolder {
        final TextView text;

        RowHolder(TextView view) {
            super(view);
            text = view;
        }
    }
}
