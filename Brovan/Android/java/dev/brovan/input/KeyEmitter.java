package dev.brovan.input;

import java.util.EnumSet;
import java.util.Set;

import dev.brovan.BrovanNative;

/**
 * Keeps track of which keys the touch controls are currently holding, so a control that changes direction
 * releases what it was holding instead of leaving the guest with a key stuck down.
 */
public final class KeyEmitter {

    private final Set<VirtualKey> held = EnumSet.noneOf(VirtualKey.class);

    public void press(VirtualKey key) {
        if (held.add(key)) {
            BrovanNative.injectKey(true, key.code(), key.scanCode());
        }
    }

    public void release(VirtualKey key) {
        if (held.remove(key)) {
            BrovanNative.injectKey(false, key.code(), key.scanCode());
        }
    }

    /** Presses everything in {@code wanted} and releases anything held that is no longer wanted. */
    public void apply(Set<VirtualKey> wanted) {
        for (VirtualKey key : EnumSet.copyOf(held)) {
            if (!wanted.contains(key)) {
                release(key);
            }
        }

        for (VirtualKey key : wanted) {
            press(key);
        }
    }

    public void releaseAll() {
        apply(EnumSet.noneOf(VirtualKey.class));
    }
}
