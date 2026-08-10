package dev.brovan.app;

import android.content.Context;

import org.json.JSONArray;
import org.json.JSONObject;

import java.io.BufferedReader;
import java.io.File;
import java.io.FileInputStream;
import java.io.IOException;
import java.io.InputStream;
import java.io.InputStreamReader;
import java.net.HttpURLConnection;
import java.net.URL;
import java.nio.charset.StandardCharsets;
import java.util.ArrayList;
import java.util.List;

/** The DXVK releases: what is installed, and which versions the user can pick from. */
final class Dxvk {

    /** Empty means the newest release, resolved when the download runs. */
    static final String LATEST = "";

    private static final String RELEASES = "https://api.github.com/repos/doitsujin/dxvk/releases?per_page=30";
    private static final String VERSION_FILE = "dxvk.version";
    private static final int TIMEOUT = 15000;

    private Dxvk() {
    }

    /** The release tag that was installed last, or empty when DXVK has never been downloaded. */
    static String installedVersion(Context context) {
        File stamp = new File(context.getFilesDir(), VERSION_FILE);
        if (!stamp.isFile()) {
            return "";
        }

        try (InputStream in = new FileInputStream(stamp)) {
            byte[] content = new byte[(int) Math.min(stamp.length(), 64)];
            int read = in.read(content);
            return read <= 0 ? "" : new String(content, 0, read, StandardCharsets.UTF_8).trim();
        } catch (IOException error) {
            return "";
        }
    }

    /**
     * The release tags GitHub offers, newest first. Blocking; call from a worker thread. Returns an empty
     * list when the device is offline, in which case only the newest release can be asked for.
     */
    static List<String> versions() {
        List<String> tags = new ArrayList<>();
        HttpURLConnection connection = null;

        try {
            connection = (HttpURLConnection) new URL(RELEASES).openConnection();
            connection.setConnectTimeout(TIMEOUT);
            connection.setReadTimeout(TIMEOUT);
            connection.setRequestProperty("Accept", "application/vnd.github+json");
            connection.setRequestProperty("User-Agent", "Brovan");

            if (connection.getResponseCode() != HttpURLConnection.HTTP_OK) {
                return tags;
            }

            JSONArray releases = new JSONArray(read(connection.getInputStream()));

            for (int i = 0; i < releases.length(); i++) {
                JSONObject release = releases.optJSONObject(i);
                if (release == null || release.optBoolean("draft")) {
                    continue;
                }

                String tag = release.optString("tag_name");
                if (!tag.isEmpty() && hasWindowsBuild(release)) {
                    tags.add(tag);
                }
            }
        } catch (Exception failure) {
            tags.clear();
        } finally {
            if (connection != null) {
                connection.disconnect();
            }
        }

        return tags;
    }

    /** Source-only and Linux-native releases carry no Windows libraries, so they are not offered. */
    private static boolean hasWindowsBuild(JSONObject release) {
        JSONArray assets = release.optJSONArray("assets");
        if (assets == null) {
            return false;
        }

        for (int i = 0; i < assets.length(); i++) {
            JSONObject asset = assets.optJSONObject(i);
            if (asset == null) {
                continue;
            }

            String name = asset.optString("name");
            if (name.startsWith("dxvk-") && name.endsWith(".tar.gz")
                    && !name.contains("native") && !name.contains("source")) {
                return true;
            }
        }

        return false;
    }

    private static String read(InputStream stream) throws IOException {
        StringBuilder text = new StringBuilder();

        try (BufferedReader reader = new BufferedReader(new InputStreamReader(stream, StandardCharsets.UTF_8))) {
            char[] buffer = new char[8192];
            int count;

            while ((count = reader.read(buffer)) > 0) {
                text.append(buffer, 0, count);
            }
        }

        return text.toString();
    }
}
