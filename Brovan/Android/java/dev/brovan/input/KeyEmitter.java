package dev.brovan.input;

import java.util.EnumMap;
import java.util.EnumSet;
import java.util.IdentityHashMap;
import java.util.Map;
import java.util.Set;

import dev.brovan.BrovanNative;

/**
 * Keeps track of which keys the touch controls are currently holding, so a control that changes direction
 * releases what it was holding instead of leaving the guest with a key stuck down.
 *
 * Holdings are per control: a stick sweeping through its directions must not release the key an action
 * button is holding at the same time. A key that two controls both hold stays down until both let go.
 */
public final class KeyEmitter {

    private final Map<Object, Set<VirtualKey>> owned = new IdentityHashMap<>();
    private final Map<VirtualKey, Integer> holders = new EnumMap<>(VirtualKey.class);

    public void press(Object owner, VirtualKey key) {
        Set<VirtualKey> keys = owned.get(owner);
        if (keys == null) {
            keys = EnumSet.noneOf(VirtualKey.class);
            owned.put(owner, keys);
        }

        if (!keys.add(key)) {
            return;
        }

        Integer count = holders.get(key);
        holders.put(key, count == null ? 1 : count + 1);

        if (count == null) {
            BrovanNative.injectKey(true, key.code(), key.scanCode());
        }
    }

    public void release(Object owner, VirtualKey key) {
        Set<VirtualKey> keys = owned.get(owner);
        if (keys == null || !keys.remove(key)) {
            return;
        }

        Integer count = holders.get(key);
        if (count == null) {
            return;
        }

        if (count <= 1) {
            holders.remove(key);
            BrovanNative.injectKey(false, key.code(), key.scanCode());
        } else {
            holders.put(key, count - 1);
        }
    }

    /** Presses everything in {@code wanted} and releases anything this owner holds that is not wanted. */
    public void apply(Object owner, Set<VirtualKey> wanted) {
        Set<VirtualKey> keys = owned.get(owner);

        if (keys != null) {
            for (VirtualKey key : EnumSet.copyOf(keys.isEmpty() ? EnumSet.noneOf(VirtualKey.class) : keys)) {
                if (!wanted.contains(key)) {
                    release(owner, key);
                }
            }
        }

        for (VirtualKey key : wanted) {
            press(owner, key);
        }
    }

    public void releaseAll() {
        for (Map.Entry<Object, Set<VirtualKey>> entry : new IdentityHashMap<>(owned).entrySet()) {
            for (VirtualKey key : EnumSet.copyOf(
                    entry.getValue().isEmpty() ? EnumSet.noneOf(VirtualKey.class) : entry.getValue())) {
                release(entry.getKey(), key);
            }
        }

        owned.clear();
        holders.clear();
    }
}
