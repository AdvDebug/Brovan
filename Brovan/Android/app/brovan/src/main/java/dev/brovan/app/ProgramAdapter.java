package dev.brovan.app;

import android.view.LayoutInflater;
import android.view.View;
import android.view.ViewGroup;
import android.widget.TextView;

import androidx.annotation.NonNull;
import androidx.recyclerview.widget.RecyclerView;

import java.util.ArrayList;
import java.util.List;

final class ProgramAdapter extends RecyclerView.Adapter<ProgramAdapter.Holder> {

    interface Listener {
        void onLaunch(Program program);

        void onLongPress(Program program);
    }

    private final List<Program> programs = new ArrayList<>();
    private final Listener listener;

    ProgramAdapter(Listener listener) {
        this.listener = listener;
    }

    void submit(List<Program> updated) {
        programs.clear();
        programs.addAll(updated);
        notifyDataSetChanged();
    }

    @NonNull
    @Override
    public Holder onCreateViewHolder(@NonNull ViewGroup parent, int viewType) {
        View view = LayoutInflater.from(parent.getContext()).inflate(R.layout.item_app, parent, false);
        return new Holder(view);
    }

    @Override
    public void onBindViewHolder(@NonNull Holder holder, int position) {
        Program program = programs.get(position);
        holder.name.setText(program.name());
        holder.detail.setText(program.executableName());
        holder.itemView.setOnClickListener(view -> listener.onLaunch(program));
        holder.itemView.setOnLongClickListener(view -> {
            listener.onLongPress(program);
            return true;
        });
    }

    @Override
    public int getItemCount() {
        return programs.size();
    }

    static final class Holder extends RecyclerView.ViewHolder {
        final TextView name;
        final TextView detail;

        Holder(View view) {
            super(view);
            name = view.findViewById(R.id.name);
            detail = view.findViewById(R.id.detail);
        }
    }
}
