#include <jni.h>
#include <android/bitmap.h>
#include <android/log.h>
#include <android/native_window.h>
#include <android/native_window_jni.h>
#include <pthread.h>
#include <stdlib.h>
#include <sys/stat.h>
#include <string.h>

#define TAG "BrovanJni"
#define METHOD(name) Java_dev_brovan_BrovanNative_native##name

extern int brovan_init(const char *baseDirectory);
extern int brovan_install_windows(const char *media, int mediaDescriptor, int acceptLicense,
                                  int imageIndex);
extern int brovan_install_runtimes(int acceptLicense);
extern int brovan_install_dxvk(const char *version);
extern void brovan_set_log_sink(void *sink);
extern void brovan_set_exit_sink(void *sink);
extern void brovan_set_install_progress_sink(void *sink);
extern void brovan_set_text_sink(void *sink);
extern void brovan_set_spawn_sink(void *sink);
extern void brovan_join_session(const char *sessionId, unsigned int spawnToken, int depth);
extern void brovan_set_verbose(int enabled);
extern void brovan_set_jit_cache(int enabled);
extern void brovan_set_surface(void *nativeWindow, int width, int height, int densityDpi);
extern void brovan_clear_surface(void);
extern int brovan_start(const char *binaryPath, const char *guestCommandLine, const char *workingDirectory,
                        const char *commands, int networkMode);
extern int brovan_is_running(void);
extern void brovan_send_command(const char *command);
extern void brovan_request_close(void);
extern void brovan_stop(void);
extern void brovan_request_repaint(void);
extern void brovan_inject_pointer(int action, int button, int x, int y, int buttons);
extern void brovan_inject_mouse_travel(int deltaX, int deltaY);
extern void brovan_inject_scroll(int delta, int x, int y, int buttons);
extern void brovan_inject_key(int down, int virtualKey, int scanCode);
extern void brovan_inject_focus(int focused);
extern int brovan_get_window_title(char *buffer, int capacity);
extern int brovan_list_windows(char *buffer, int capacity);
extern void brovan_select_window(unsigned long long hwnd);
extern int brovan_debug_query(const char *request, char *buffer, int capacity);
extern void brovan_debug_pause(void);

static JavaVM *g_vm;
static jclass g_callbacks;
static jmethodID g_onLog;
static jmethodID g_onExit;
static jmethodID g_onInstallProgress;
static jmethodID g_onTextMetrics;
static jmethodID g_onTextBitmap;
static jmethodID g_onSpawn;
static pthread_key_t g_attachment_key;
static int g_attachment_key_ready;

typedef struct {
    JNIEnv *env;
    int attached;
} Attachment;

/* ART aborts a thread that exits while still attached, so a thread kept attached across calls must
   detach from here. */
static void detach_at_thread_exit(void *value) {
    (void)value;

    if (g_vm != NULL) {
        (*g_vm)->DetachCurrentThread(g_vm);
    }
}

static Attachment attach(void) {
    Attachment attachment = {NULL, 0};

    if (g_vm == NULL) {
        return attachment;
    }

    if ((*g_vm)->GetEnv(g_vm, (void **)&attachment.env, JNI_VERSION_1_6) == JNI_OK) {
        return attachment;
    }

    /* Guest and emulator threads are created by the .NET runtime and are unknown to the JVM until
       attached; any JNI call from them without this crashes the process. */
    if ((*g_vm)->AttachCurrentThread(g_vm, &attachment.env, NULL) != JNI_OK) {
        return attachment;
    }

    /* Developer mode sends thousands of trace lines down this path, and an attach/detach pair per line
       costs far more than the call itself, so the attachment is kept for the life of the thread. */
    if (g_attachment_key_ready && pthread_setspecific(g_attachment_key, attachment.env) == 0) {
        return attachment;
    }

    attachment.attached = 1;
    return attachment;
}

static void detach(Attachment attachment) {
    if (attachment.attached) {
        (*g_vm)->DetachCurrentThread(g_vm);
    }
}

static void on_log(const char *text) {
    if (text == NULL || g_callbacks == NULL || g_onLog == NULL) {
        return;
    }

    Attachment attachment = attach();
    if (attachment.env == NULL) {
        return;
    }

    jstring line = (*attachment.env)->NewStringUTF(attachment.env, text);
    if (line != NULL) {
        (*attachment.env)->CallStaticVoidMethod(attachment.env, g_callbacks, g_onLog, line);
        (*attachment.env)->DeleteLocalRef(attachment.env, line);
    }

    detach(attachment);
}

static void on_install_progress(long long filesDone, long long filesTotal,
                                long long bytesDone, long long bytesTotal) {
    if (g_callbacks == NULL || g_onInstallProgress == NULL) {
        return;
    }

    Attachment attachment = attach();
    if (attachment.env == NULL) {
        return;
    }

    (*attachment.env)->CallStaticVoidMethod(attachment.env, g_callbacks, g_onInstallProgress,
                                            (jlong)filesDone, (jlong)filesTotal,
                                            (jlong)bytesDone, (jlong)bytesTotal);
    detach(attachment);
}

static void on_exit_guest(int reason) {
    if (g_callbacks == NULL || g_onExit == NULL) {
        return;
    }

    Attachment attachment = attach();
    if (attachment.env == NULL) {
        return;
    }

    (*attachment.env)->CallStaticVoidMethod(attachment.env, g_callbacks, g_onExit, (jint)reason);
    detach(attachment);
}

/* The calling guest thread blocks until the new process reports itself, so this only asks for the launch. */
static int on_spawn(const char *image, const char *arguments, const char *workingDirectory,
                    const char *sessionId, unsigned int spawnToken, int depth) {
    if (image == NULL || g_callbacks == NULL || g_onSpawn == NULL) {
        return 0;
    }

    Attachment attachment = attach();
    JNIEnv *env = attachment.env;
    if (env == NULL) {
        return 0;
    }

    jstring imageText = (*env)->NewStringUTF(env, image);
    jstring argumentsText = (*env)->NewStringUTF(env, arguments == NULL ? "" : arguments);
    jstring directoryText = (*env)->NewStringUTF(env, workingDirectory == NULL ? "" : workingDirectory);
    jstring sessionText = (*env)->NewStringUTF(env, sessionId == NULL ? "" : sessionId);

    jboolean accepted = JNI_FALSE;

    if (imageText != NULL && argumentsText != NULL && directoryText != NULL && sessionText != NULL) {
        accepted = (*env)->CallStaticBooleanMethod(env, g_callbacks, g_onSpawn, imageText, argumentsText,
                                                   directoryText, sessionText, (jint)spawnToken, (jint)depth);

        if ((*env)->ExceptionCheck(env)) {
            (*env)->ExceptionDescribe(env);
            (*env)->ExceptionClear(env);
            accepted = JNI_FALSE;
        }
    }

    if (imageText != NULL) {
        (*env)->DeleteLocalRef(env, imageText);
    }
    if (argumentsText != NULL) {
        (*env)->DeleteLocalRef(env, argumentsText);
    }
    if (directoryText != NULL) {
        (*env)->DeleteLocalRef(env, directoryText);
    }
    if (sessionText != NULL) {
        (*env)->DeleteLocalRef(env, sessionText);
    }

    detach(attachment);
    return accepted == JNI_TRUE ? 1 : 0;
}

#define TEXT_FIELD_COUNT 8

/* Mirrors AndroidText.TextRequest. */
typedef struct {
    unsigned char *coverage;
    int capacity;
    int width;
    int height;
    int ascent;
    int descent;
    int leading;
    int average;
    int maximum;
    int padding;
} BrovanText;

static int copy_coverage(JNIEnv *env, jstring text, BrovanText *request) {
    jobject bitmap = (*env)->CallStaticObjectMethod(env, g_callbacks, g_onTextBitmap, text);
    if ((*env)->ExceptionCheck(env)) {
        (*env)->ExceptionClear(env);
        return 0;
    }

    if (bitmap == NULL) {
        return 0;
    }

    AndroidBitmapInfo info;
    void *pixels = NULL;
    int copied = 0;

    if (AndroidBitmap_getInfo(env, bitmap, &info) == ANDROID_BITMAP_RESULT_SUCCESS &&
        info.format == ANDROID_BITMAP_FORMAT_A_8 &&
        (int)info.width >= request->width && (int)info.height >= request->height &&
        AndroidBitmap_lockPixels(env, bitmap, &pixels) == ANDROID_BITMAP_RESULT_SUCCESS) {

        for (int row = 0; row < request->height; row++) {
            memcpy(request->coverage + (size_t)row * (size_t)request->width,
                   (unsigned char *)pixels + (size_t)row * (size_t)info.stride,
                   (size_t)request->width);
        }

        AndroidBitmap_unlockPixels(env, bitmap);
        copied = 1;
    }

    (*env)->DeleteLocalRef(env, bitmap);
    return copied;
}

/* A NULL text asks for the font metrics alone, and a NULL coverage buffer for a measurement. Filling the
   dimensions and reporting failure is how a buffer that is too small asks the caller to grow it. */
static int on_text(const char *utf8, BrovanText *request) {
    if (request == NULL || g_callbacks == NULL || g_onTextMetrics == NULL || g_onTextBitmap == NULL) {
        return 0;
    }

    Attachment attachment = attach();
    JNIEnv *env = attachment.env;
    if (env == NULL) {
        return 0;
    }

    int result = 0;
    jstring text = utf8 == NULL ? NULL : (*env)->NewStringUTF(env, utf8);
    jintArray fields = (*env)->CallStaticObjectMethod(env, g_callbacks, g_onTextMetrics, text);

    if ((*env)->ExceptionCheck(env)) {
        (*env)->ExceptionClear(env);
        fields = NULL;
    }

    if (fields != NULL) {
        jint values[TEXT_FIELD_COUNT];
        (*env)->GetIntArrayRegion(env, fields, 0, TEXT_FIELD_COUNT, values);
        (*env)->DeleteLocalRef(env, fields);

        request->width = values[0];
        request->height = values[1];
        request->ascent = values[2];
        request->descent = values[3];
        request->leading = values[4];
        request->average = values[5];
        request->maximum = values[6];
        request->padding = values[7];

        if (request->coverage == NULL) {
            result = 1;
        } else if (request->width > 0 && request->height > 0 &&
                   (long long)request->capacity >= (long long)request->width * (long long)request->height) {
            result = copy_coverage(env, text, request);
        }
    }

    if (text != NULL) {
        (*env)->DeleteLocalRef(env, text);
    }

    detach(attachment);
    return result;
}

/* Borrowed UTF-8 view of a jstring; release() must be called with the same jstring. */
static const char *borrow(JNIEnv *env, jstring value) {
    return value == NULL ? NULL : (*env)->GetStringUTFChars(env, value, NULL);
}

static void release(JNIEnv *env, jstring value, const char *borrowed) {
    if (value != NULL && borrowed != NULL) {
        (*env)->ReleaseStringUTFChars(env, value, borrowed);
    }
}

static jstring read_into_string(JNIEnv *env, int (*reader)(char *, int), int capacity) {
    char *buffer = malloc((size_t)capacity);
    if (buffer == NULL) {
        return (*env)->NewStringUTF(env, "");
    }

    buffer[0] = '\0';
    reader(buffer, capacity);

    jstring result = (*env)->NewStringUTF(env, buffer);
    free(buffer);
    return result;
}

JNIEXPORT jint JNICALL JNI_OnLoad(JavaVM *vm, void *reserved) {
    (void)reserved;
    g_vm = vm;
    g_attachment_key_ready = pthread_key_create(&g_attachment_key, detach_at_thread_exit) == 0;
    return JNI_VERSION_1_6;
}

/* Android keeps its trust store as an OpenSSL hashed directory, but not where OpenSSL looks by default
   (/etc/ssl/certs is empty here), so TLS fails to validate anything until SSL_CERT_DIR points at it. This has to
   go through the real setenv: .NET's Environment.SetEnvironmentVariable does not touch the native environment on
   Unix, so OpenSSL would never see it. */
static void use_system_certificates(void) {
    static const char *const directories[] = {
        "/apex/com.android.conscrypt/cacerts",
        "/system/etc/security/cacerts",
    };

    char combined[256];
    size_t used = 0;

    for (size_t i = 0; i < sizeof(directories) / sizeof(directories[0]); i++) {
        struct stat info;
        if (stat(directories[i], &info) != 0 || !S_ISDIR(info.st_mode)) {
            continue;
        }

        size_t length = strlen(directories[i]);
        if (used + length + 2 > sizeof(combined)) {
            break;
        }

        if (used != 0) {
            combined[used++] = ':';
        }

        memcpy(combined + used, directories[i], length);
        used += length;
    }

    if (used == 0) {
        __android_log_print(ANDROID_LOG_WARN, TAG, "no system certificate directory; HTTPS will fail");
        return;
    }

    combined[used] = '\x00';
    setenv("SSL_CERT_DIR", combined, 0);
}

JNIEXPORT jint JNICALL METHOD(Init)(JNIEnv *env, jclass clazz, jstring baseDirectory) {
    if (g_callbacks == NULL) {
        g_callbacks = (jclass)(*env)->NewGlobalRef(env, clazz);
        g_onLog = (*env)->GetStaticMethodID(env, clazz, "onNativeLog", "(Ljava/lang/String;)V");
        g_onExit = (*env)->GetStaticMethodID(env, clazz, "onNativeExit", "(I)V");
        g_onInstallProgress = (*env)->GetStaticMethodID(env, clazz, "onNativeInstallProgress", "(JJJJ)V");
        g_onTextMetrics = (*env)->GetStaticMethodID(env, clazz, "onNativeTextMetrics", "(Ljava/lang/String;)[I");
        g_onTextBitmap = (*env)->GetStaticMethodID(env, clazz, "onNativeRasterizeText",
                                                   "(Ljava/lang/String;)Landroid/graphics/Bitmap;");
        g_onSpawn = (*env)->GetStaticMethodID(env, clazz, "onNativeSpawn",
                                              "(Ljava/lang/String;Ljava/lang/String;Ljava/lang/String;Ljava/lang/String;II)Z");
        (*env)->ExceptionClear(env);
    }

    const char *path = borrow(env, baseDirectory);
    if (path == NULL) {
        return -3;
    }

    use_system_certificates();

    int status = brovan_init(path);
    release(env, baseDirectory, path);

    if (status == 0) {
        brovan_set_log_sink((void *)&on_log);
        brovan_set_exit_sink((void *)&on_exit_guest);
        brovan_set_install_progress_sink((void *)&on_install_progress);
        brovan_set_text_sink((void *)&on_text);
        brovan_set_spawn_sink((void *)&on_spawn);
    } else {
        __android_log_print(ANDROID_LOG_ERROR, TAG, "brovan_init failed: %d", status);
    }

    return status;
}

JNIEXPORT jint JNICALL METHOD(InstallWindows)(JNIEnv *env, jclass clazz, jstring media, jint mediaDescriptor,
                                              jint acceptLicense, jint imageIndex) {
    (void)clazz;

    const char *path = media == NULL ? NULL : borrow(env, media);
    int status = brovan_install_windows(path, mediaDescriptor, acceptLicense, imageIndex);

    if (path != NULL) {
        release(env, media, path);
    }

    return status;
}

JNIEXPORT jint JNICALL METHOD(InstallRuntimes)(JNIEnv *env, jclass clazz, jint acceptLicense) {
    (void)env;
    (void)clazz;

    return brovan_install_runtimes(acceptLicense);
}

JNIEXPORT jint JNICALL METHOD(InstallDxvk)(JNIEnv *env, jclass clazz, jstring version) {
    (void)clazz;

    const char *tag = version == NULL ? NULL : borrow(env, version);
    int status = brovan_install_dxvk(tag);

    if (tag != NULL) {
        release(env, version, tag);
    }

    return status;
}

JNIEXPORT void JNICALL METHOD(SetSurface)(JNIEnv *env, jclass clazz, jobject surface, jint densityDpi) {
    (void)clazz;

    if (surface == NULL) {
        brovan_clear_surface();
        return;
    }

    ANativeWindow *window = ANativeWindow_fromSurface(env, surface);
    if (window == NULL) {
        __android_log_print(ANDROID_LOG_ERROR, TAG, "ANativeWindow_fromSurface returned NULL");
        return;
    }

    /* brovan_set_surface takes its own reference, so the one fromSurface returned is ours to drop. */
    brovan_set_surface(window, ANativeWindow_getWidth(window), ANativeWindow_getHeight(window), densityDpi);
    ANativeWindow_release(window);
}

JNIEXPORT void JNICALL METHOD(ClearSurface)(JNIEnv *env, jclass clazz) {
    (void)env;
    (void)clazz;
    brovan_clear_surface();
}

JNIEXPORT jint JNICALL METHOD(Start)(JNIEnv *env, jclass clazz, jstring binaryPath, jstring guestCommandLine,
                                     jstring workingDirectory, jstring commands, jint networkMode) {
    (void)clazz;

    const char *path = borrow(env, binaryPath);
    const char *cmdline = borrow(env, guestCommandLine);
    const char *cwd = borrow(env, workingDirectory);
    const char *debuggerCommands = borrow(env, commands);

    int status = path != NULL ? brovan_start(path, cmdline, cwd, debuggerCommands, networkMode) : -3;

    release(env, binaryPath, path);
    release(env, guestCommandLine, cmdline);
    release(env, workingDirectory, cwd);
    release(env, commands, debuggerCommands);

    return status;
}

JNIEXPORT void JNICALL METHOD(JoinSession)(JNIEnv *env, jclass clazz, jstring sessionId, jint spawnToken,
                                           jint depth) {
    (void)clazz;

    const char *session = borrow(env, sessionId);
    if (session == NULL) {
        return;
    }

    brovan_join_session(session, (unsigned int)spawnToken, depth);
    release(env, sessionId, session);
}

JNIEXPORT void JNICALL METHOD(SetVerbose)(JNIEnv *env, jclass clazz, jint enabled) {
    (void)env;
    (void)clazz;
    brovan_set_verbose(enabled);

    /* Only the developer console reads the log sink. Dropping it otherwise keeps the emulator from
       encoding and marshalling every line it writes for a listener that discards them. */
    brovan_set_log_sink(enabled ? (void *)&on_log : NULL);
}

JNIEXPORT void JNICALL METHOD(SetJitCache)(JNIEnv *env, jclass clazz, jint enabled) {
    (void)env;
    (void)clazz;
    brovan_set_jit_cache(enabled);
}

JNIEXPORT void JNICALL METHOD(SendCommand)(JNIEnv *env, jclass clazz, jstring command) {
    (void)clazz;

    const char *text = borrow(env, command);
    if (text == NULL) {
        return;
    }

    brovan_send_command(text);
    release(env, command, text);
}

JNIEXPORT jint JNICALL METHOD(IsRunning)(JNIEnv *env, jclass clazz) {
    (void)env;
    (void)clazz;
    return brovan_is_running();
}

JNIEXPORT void JNICALL METHOD(RequestClose)(JNIEnv *env, jclass clazz) {
    (void)env;
    (void)clazz;
    brovan_request_close();
}

JNIEXPORT void JNICALL METHOD(Stop)(JNIEnv *env, jclass clazz) {
    (void)env;
    (void)clazz;
    brovan_stop();
}

JNIEXPORT void JNICALL METHOD(RequestRepaint)(JNIEnv *env, jclass clazz) {
    (void)env;
    (void)clazz;
    brovan_request_repaint();
}

JNIEXPORT void JNICALL METHOD(InjectPointer)(JNIEnv *env, jclass clazz, jint action, jint button,
                                             jint x, jint y, jint buttons) {
    (void)env;
    (void)clazz;
    brovan_inject_pointer(action, button, x, y, buttons);
}

JNIEXPORT void JNICALL METHOD(InjectMouseTravel)(JNIEnv *env, jclass clazz, jint deltaX, jint deltaY) {
    (void)env;
    (void)clazz;
    brovan_inject_mouse_travel(deltaX, deltaY);
}

JNIEXPORT void JNICALL METHOD(InjectScroll)(JNIEnv *env, jclass clazz, jint delta, jint x, jint y, jint buttons) {
    (void)env;
    (void)clazz;
    brovan_inject_scroll(delta, x, y, buttons);
}

JNIEXPORT void JNICALL METHOD(InjectKey)(JNIEnv *env, jclass clazz, jint down, jint virtualKey, jint scanCode) {
    (void)env;
    (void)clazz;
    brovan_inject_key(down, virtualKey, scanCode);
}

JNIEXPORT void JNICALL METHOD(InjectFocus)(JNIEnv *env, jclass clazz, jint focused) {
    (void)env;
    (void)clazz;
    brovan_inject_focus(focused);
}

JNIEXPORT void JNICALL METHOD(SelectWindow)(JNIEnv *env, jclass clazz, jlong hwnd) {
    (void)env;
    (void)clazz;
    brovan_select_window((unsigned long long)hwnd);
}

JNIEXPORT jstring JNICALL METHOD(ListWindows)(JNIEnv *env, jclass clazz) {
    (void)clazz;
    return read_into_string(env, brovan_list_windows, 16384);
}

JNIEXPORT jstring JNICALL METHOD(GetWindowTitle)(JNIEnv *env, jclass clazz) {
    (void)clazz;
    return read_into_string(env, brovan_get_window_title, 512);
}

JNIEXPORT void JNICALL METHOD(DebugPause)(JNIEnv *env, jclass clazz) {
    (void)env;
    (void)clazz;
    brovan_debug_pause();
}

JNIEXPORT jstring JNICALL METHOD(DebugQuery)(JNIEnv *env, jclass clazz, jstring request) {
    (void)clazz;

    const char *text = borrow(env, request);
    if (text == NULL) {
        return (*env)->NewStringUTF(env, "");
    }

    /* Region and disassembly listings are the large ones; anything past this is dropped by the emulator
       at a record boundary. */
    const int capacity = 256 * 1024;
    char *buffer = malloc((size_t)capacity);
    if (buffer == NULL) {
        release(env, request, text);
        return (*env)->NewStringUTF(env, "");
    }

    buffer[0] = '\0';
    brovan_debug_query(text, buffer, capacity);
    release(env, request, text);

    jstring result = (*env)->NewStringUTF(env, buffer);
    free(buffer);
    return result;
}
