package dev.brovan.app;

import android.content.Context;
import android.text.Spannable;
import android.text.SpannableStringBuilder;
import android.text.style.ForegroundColorSpan;
import android.text.style.StyleSpan;
import android.util.AttributeSet;
import android.util.TypedValue;
import android.view.LayoutInflater;
import android.view.View;
import android.view.ViewGroup;
import android.widget.EditText;
import android.widget.LinearLayout;
import android.widget.TextView;
import android.widget.Toast;

import androidx.annotation.NonNull;
import androidx.annotation.Nullable;
import androidx.core.content.ContextCompat;
import androidx.recyclerview.widget.LinearLayoutManager;
import androidx.recyclerview.widget.RecyclerView;

import com.google.android.material.tabs.TabLayout;

import java.util.ArrayList;
import java.util.HashSet;
import java.util.List;
import java.util.Set;

import dev.brovan.BrovanNative;

/**
 * The developer mode inspector. the emulator log plus the debugger views the console commands print, laid
 * out as tabs over the running guest.
 */
public class DebuggerView extends LinearLayout {

    /** Reported to the host so debugger output lands in the same log as the emulator's own trace. */
    public interface Listener {
        void onDebuggerMessage(String line);
    }

    private enum Tab {
        LOG,
        DISASSEMBLY,
        REGISTERS,
        STACK,
        THREADS,
        MODULES,
        MEMORY,
        BREAKPOINTS,
        REGIONS
    }

    private static final long POLL_INTERVAL_MS = 400;
    private static final long COMMAND_SETTLE_MS = 250;
    private static final long SETTLE_RETRY_MS = 120;
    private static final int DISASSEMBLY_LINES = 96;
    private static final int MEMORY_LENGTH = 512;
    private static final int STACK_FRAMES = 32;

    private final RowAdapter adapter = new RowAdapter();
    private final Set<Long> breakpoints = new HashSet<>();

    private TextView state;
    private TextView stats;
    private TextView empty;
    private TabLayout tabs;
    private RecyclerView rows;
    private View logScroll;
    private TextView run;

    private Listener listener;
    private Tab tab = Tab.LOG;
    private int rowBackground;
    private boolean developerMode = true;
    private boolean started;
    private boolean paused;
    private boolean wide = true;
    private long instructionPointer;
    private long shownInstructionPointer = -1;
    private long disassemblyAddress;
    private long memoryAddress;

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
        empty = findViewById(R.id.debug_empty);
        tabs = findViewById(R.id.debug_tabs);
        rows = findViewById(R.id.debug_rows);
        logScroll = findViewById(R.id.log_scroll);
        run = findViewById(R.id.debug_run);

        rows.setLayoutManager(new LinearLayoutManager(getContext()));
        rows.setAdapter(adapter);

        TypedValue background = new TypedValue();
        getContext().getTheme().resolveAttribute(android.R.attr.selectableItemBackground, background, true);
        rowBackground = background.resourceId;

        for (Tab value : Tab.values()) {
            tabs.addTab(tabs.newTab().setText(labelOf(value)));
        }

        tabs.addOnTabSelectedListener(new TabLayout.OnTabSelectedListener() {
            @Override
            public void onTabSelected(TabLayout.Tab selected) {
                tab = Tab.values()[selected.getPosition()];
                shownInstructionPointer = -1;
                refresh();
            }

            @Override
            public void onTabUnselected(TabLayout.Tab selected) {
            }

            @Override
            public void onTabReselected(TabLayout.Tab selected) {
                refresh();
            }
        });

        findViewById(R.id.debug_run).setOnClickListener(view -> send(started ? "c" : "start"));
        findViewById(R.id.debug_pause).setOnClickListener(view -> requestPause());
        findViewById(R.id.debug_step).setOnClickListener(view -> send("step"));
        findViewById(R.id.debug_step_over).setOnClickListener(view -> send("stepover"));
        findViewById(R.id.debug_goto).setOnClickListener(view -> askForAddress());
        findViewById(R.id.debug_refresh).setOnClickListener(view -> {
            shownInstructionPointer = -1;
            refresh();
        });
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
        findViewById(R.id.debug_state).setVisibility(visibility);
        findViewById(R.id.debug_stats).setVisibility(visibility);
        findViewById(R.id.debug_toolbar).setVisibility(visibility);
        findViewById(R.id.debug_tabs).setVisibility(visibility);
        findViewById(R.id.debug_command_row).setVisibility(visibility);
    }

    /** True while the log tab owns the content area, so the host knows whether its log view is on screen. */
    public boolean isLogVisible() {
        return isShown() && tab == Tab.LOG;
    }

    public void send(String command) {
        if (command.isEmpty()) {
            return;
        }

        if (command.equals("start") || command.equals("run")) {
            started = true;
        }

        BrovanNative.sendCommand(command);
        postDelayed(() -> {
            shownInstructionPointer = -1;
            readState();
        }, COMMAND_SETTLE_MS);
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
        paused = "paused".equals(fields[0]);
        instructionPointer = parseHex(fields[2]);

        wide = !"x86".equals(fields[4]);
        state.setText(stateLabel());

        String counters = getContext().getString(R.string.debug_stats, parseInt(fields[5]), parseInt(fields[6]),
                String.format("%,d", parseLong(fields[8])));
        stats.setText(fields[3].isEmpty() ? counters : fields[3] + "  ·  " + counters);

        run.setText(started ? R.string.debug_continue : R.string.debug_run);

        if (paused && !wasPaused) {
            // A stop moves the disassembly back to wherever the guest actually is.
            disassemblyAddress = 0;
        }

        if (paused || tab == Tab.THREADS || tab == Tab.MODULES || tab == Tab.REGIONS) {
            refresh();
        }
    }

    private void refresh() {
        if (tab == Tab.LOG) {
            logScroll.setVisibility(VISIBLE);
            rows.setVisibility(GONE);
            empty.setVisibility(GONE);
            return;
        }

        logScroll.setVisibility(GONE);

        if (needsStoppedGuest() && !paused) {
            rows.setVisibility(GONE);
            empty.setVisibility(VISIBLE);
            empty.setText(started ? R.string.debug_pause_first : R.string.debug_not_started);
            return;
        }

        if (paused && shownInstructionPointer == instructionPointer && !adapter.isEmpty()) {
            return;
        }

        // Replacing the rows under a scroll or a layout pass throws, so the build waits for the view to settle.
        if (rows.isComputingLayout() || rows.getScrollState() != RecyclerView.SCROLL_STATE_IDLE) {
            postDelayed(this::refresh, SETTLE_RETRY_MS);
            return;
        }

        readBreakpoints();
        List<Row> built = build();

        // A query that reads guest state while it runs can come back torn and empty. Keeping what is on
        // screen is better than blanking the view every time that happens.
        if (built.isEmpty() && !paused && !adapter.isEmpty()) {
            return;
        }

        shownInstructionPointer = instructionPointer;

        adapter.replace(built);
        rows.setVisibility(built.isEmpty() ? GONE : VISIBLE);
        empty.setVisibility(built.isEmpty() ? VISIBLE : GONE);
        empty.setText(R.string.debug_empty);

        if (tab == Tab.DISASSEMBLY) {
            scrollToCurrent(built);
        }
    }

    private boolean needsStoppedGuest() {
        return tab == Tab.DISASSEMBLY || tab == Tab.REGISTERS || tab == Tab.STACK || tab == Tab.MEMORY;
    }

    private List<Row> build() {
        switch (tab) {
            case DISASSEMBLY: return buildDisassembly();
            case REGISTERS: return buildRegisters();
            case STACK: return buildStack();
            case THREADS: return buildThreads();
            case MODULES: return buildModules();
            case MEMORY: return buildMemory();
            case BREAKPOINTS: return buildBreakpoints();
            case REGIONS: return buildRegions();
            default: return new ArrayList<>();
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

            append(text, breakpoints.contains(address) ? "● " : current ? "▶ " : "  ",
                    breakpoints.contains(address) ? R.color.debug_breakpoint : R.color.accent);
            append(text, address(address) + "  ", R.color.asm_address);
            append(text, shortBytes(fields[1]) + "  ", R.color.asm_bytes);
            append(text, fields[2], R.color.asm_mnemonic);

            if (fields.length > 3 && !fields[3].isEmpty()) {
                append(text, " ", R.color.text_primary);
                appendTokens(text, fields[3]);
            }

            built.add(new Row(text, address, current));
        }

        return built;
    }

    private List<Row> buildRegisters() {
        List<Row> built = new ArrayList<>();
        String group = "";

        for (String record : BrovanNative.debugQuery("regs .")) {
            String[] fields = record.split("\\|", -1);
            if (fields.length < 4) {
                continue;
            }

            if (!fields[0].equals(group)) {
                group = fields[0];
                built.add(new Row(header(group), 0, false));
            }

            SpannableStringBuilder text = new SpannableStringBuilder();
            append(text, pad(fields[1], 7), R.color.asm_register);
            append(text, fields[2], isZero(fields[2]) ? R.color.debug_value_zero : R.color.debug_value);

            if (!fields[3].isEmpty()) {
                append(text, "  " + fields[3], R.color.text_secondary);
            }

            built.add(new Row(text, parseHex(fields[2]), false));
        }

        return built;
    }

    private List<Row> buildStack() {
        List<Row> built = new ArrayList<>();

        for (String record : BrovanNative.debugQuery("stack . " + STACK_FRAMES)) {
            String[] fields = record.split("\\|", -1);
            if (fields.length < 5) {
                continue;
            }

            SpannableStringBuilder text = new SpannableStringBuilder();
            append(text, pad("#" + fields[0], 5), R.color.asm_address);
            append(text, fields[2].isEmpty() ? address(parseHex(fields[1])) : fields[2], R.color.text_primary);
            append(text, "  sp=" + fields[3], R.color.text_secondary);

            if ("raw".equals(fields[4])) {
                append(text, "  ?", R.color.log_warn);
            }

            built.add(new Row(text, parseHex(fields[1]), false));
        }

        return built;
    }

    private List<Row> buildThreads() {
        List<Row> built = new ArrayList<>();

        for (String record : BrovanNative.debugQuery("threads")) {
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

            SpannableStringBuilder detail = new SpannableStringBuilder();
            append(detail, "\n    " + fields[8] + "  prio " + fields[6] + "  " + fields[7] + " instructions",
                    R.color.text_secondary);
            text.append(detail);

            built.add(new Row(text, parseLong(fields[0]), current));
        }

        return built;
    }

    private List<Row> buildModules() {
        List<Row> built = new ArrayList<>();

        for (String record : BrovanNative.debugQuery("modules")) {
            String[] fields = record.split("\\|", -1);
            if (fields.length < 5) {
                continue;
            }

            SpannableStringBuilder text = new SpannableStringBuilder();
            append(text, address(parseHex(fields[1])) + "  ", R.color.asm_address);
            append(text, fields[0], R.color.text_primary);
            append(text, "  " + fields[2] + " bytes", R.color.text_secondary);

            built.add(new Row(text, parseHex(fields[1]), false));
        }

        return built;
    }

    private List<Row> buildMemory() {
        long start = memoryAddress != 0 ? memoryAddress : instructionPointer;
        List<Row> built = new ArrayList<>();

        for (String record : BrovanNative.debugQuery("mem " + hex(start) + " " + MEMORY_LENGTH)) {
            String[] fields = record.split("\\|", -1);
            if (fields.length < 2) {
                continue;
            }

            SpannableStringBuilder text = new SpannableStringBuilder();
            append(text, address(parseHex(fields[0])) + "  ", R.color.asm_address);
            append(text, spaced(fields[1]) + "  ", R.color.debug_value);
            append(text, printable(fields[1]), R.color.asm_label);

            built.add(new Row(text, parseHex(fields[0]), false));
        }

        return built;
    }

    private List<Row> buildBreakpoints() {
        List<Row> built = new ArrayList<>();

        for (String record : BrovanNative.debugQuery("bp")) {
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

                built.add(new Row(text, parseHex(fields[1]), false));
                continue;
            }

            append(text, "■ ", R.color.log_warn);
            append(text, fields[4] + " " + address(parseHex(fields[2])), R.color.text_primary);
            append(text, "  " + fields[3] + " bytes", R.color.text_secondary);
            built.add(new Row(text, parseHex(fields[2]), false));
        }

        return built;
    }

    private List<Row> buildRegions() {
        List<Row> built = new ArrayList<>();

        for (String record : BrovanNative.debugQuery("regions")) {
            String[] fields = record.split("\\|", -1);
            if (fields.length < 4) {
                continue;
            }

            long base = parseHex(fields[0]);
            SpannableStringBuilder text = new SpannableStringBuilder();
            append(text, address(base) + "  ", R.color.asm_address);
            append(text, pad(fields[2], 22), R.color.asm_memory);
            append(text, fields[3].isEmpty() ? fields[1] + " bytes" : fields[3], R.color.text_primary);

            built.add(new Row(text, base, false));
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

    private void onRowClicked(Row row) {
        switch (tab) {
            case DISASSEMBLY:
                if (!paused) {
                    report(getContext().getString(R.string.debug_pause_first));
                    return;
                }

                send(breakpoints.contains(row.address)
                        ? "bp del " + hex(row.address)
                        : "bp add " + hex(row.address));
                return;

            case THREADS:
                send("threads switch " + row.address);
                return;

            case MEMORY:
            case REGISTERS:
                return;

            default:
                showDisassemblyAt(row.address);
        }
    }

    private void showDisassemblyAt(long address) {
        if (address == 0) {
            return;
        }

        disassemblyAddress = address;
        memoryAddress = address;
        shownInstructionPointer = -1;
        tabs.selectTab(tabs.getTabAt(Tab.DISASSEMBLY.ordinal()));
    }

    private void askForAddress() {
        EditText input = new EditText(getContext());
        input.setHint(R.string.debug_goto_hint);
        input.setSingleLine(true);

        Theming.dialog(getContext())
                .setTitle(R.string.debug_goto_title)
                .setView(input)
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
            memoryAddress = address;
            shownInstructionPointer = -1;
            refresh();
            return;
        }

        showDisassemblyAt(address);
    }

    private void scrollToCurrent(List<Row> built) {
        for (int i = 0; i < built.size(); i++) {
            if (built.get(i).current) {
                rows.scrollToPosition(Math.max(0, i - 4));
                return;
            }
        }

        rows.scrollToPosition(0);
    }

    /** The log is one tab among several, so anything worth saying is also said where the user is looking. */
    private void report(String message) {
        Toast.makeText(getContext(), message, Toast.LENGTH_SHORT).show();

        Listener current = listener;
        if (current != null) {
            current.onDebuggerMessage("[*] " + message);
        }
    }

    private String stateLabel() {
        if (!started) {
            return getContext().getString(R.string.debug_state_loaded);
        }

        if (!BrovanNative.isRunning()) {
            return getContext().getString(R.string.debug_state_stopped);
        }

        return getContext().getString(paused ? R.string.debug_state_paused : R.string.debug_state_running);
    }

    private int labelOf(Tab value) {
        switch (value) {
            case DISASSEMBLY: return R.string.debug_tab_disassembly;
            case REGISTERS: return R.string.debug_tab_registers;
            case STACK: return R.string.debug_tab_stack;
            case THREADS: return R.string.debug_tab_threads;
            case MODULES: return R.string.debug_tab_modules;
            case MEMORY: return R.string.debug_tab_memory;
            case BREAKPOINTS: return R.string.debug_tab_breakpoints;
            case REGIONS: return R.string.debug_tab_regions;
            default: return R.string.debug_tab_log;
        }
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
        append(text, group.toUpperCase(), R.color.accent);
        text.setSpan(new StyleSpan(android.graphics.Typeface.BOLD), 0, text.length(),
                Spannable.SPAN_EXCLUSIVE_EXCLUSIVE);
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
        text.setSpan(new ForegroundColorSpan(ContextCompat.getColor(getContext(), color)), start, text.length(),
                Spannable.SPAN_EXCLUSIVE_EXCLUSIVE);
    }

    /** The debugger prompt reads plain digits as decimal, so an address always carries its prefix. */
    private static String hex(long value) {
        return "0x" + Long.toHexString(value);
    }

    private String address(long value) {
        return String.format(wide ? "%016X" : "%08X", value);
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
            int value = Integer.parseInt(hex.substring(i, i + 2), 16);
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

        Row(CharSequence text, long address, boolean current) {
            this.text = text;
            this.address = address;
            this.current = current;
        }
    }

    private final class RowAdapter extends RecyclerView.Adapter<RowHolder> {

        private final List<Row> entries = new ArrayList<>();

        void replace(List<Row> value) {
            entries.clear();
            entries.addAll(value);
            notifyDataSetChanged();
        }

        boolean isEmpty() {
            return entries.isEmpty();
        }

        @NonNull
        @Override
        public RowHolder onCreateViewHolder(@NonNull ViewGroup parent, int viewType) {
            return new RowHolder((TextView) LayoutInflater.from(parent.getContext())
                    .inflate(R.layout.item_debug_row, parent, false));
        }

        @Override
        public void onBindViewHolder(@NonNull RowHolder holder, int position) {
            Row row = entries.get(position);
            holder.text.setText(row.text);

            if (row.current) {
                holder.text.setBackgroundColor(ContextCompat.getColor(getContext(), R.color.debug_current));
            } else {
                holder.text.setBackgroundResource(rowBackground);
            }

            holder.text.setOnClickListener(view -> onRowClicked(row));
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
