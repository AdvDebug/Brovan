#include <jni.h>
#include <android/log.h>
#include <android/native_window.h>
#include <android/native_window_jni.h>
#include <stdlib.h>
#include <sys/stat.h>
#include <string.h>

#define TAG "BrovanJni"
#define METHOD(name) Java_dev_brovan_BrovanNative_native##name

extern int brovan_init(const char *baseDirectory);
extern int brovan_install_windows(const char *media, int mediaDescriptor, int acceptLicense,
                                  int imageIndex);
extern int brovan_install_runtimes(int acceptLicense);
extern void brovan_set_log_sink(void *sink);
extern void brovan_set_exit_sink(void *sink);
extern void brovan_set_install_progress_sink(void *sink);
extern void brovan_set_verbose(int enabled);
extern void brovan_set_surface(void *nativeWindow, int width, int height, int densityDpi);
extern void brovan_clear_surface(void);
extern int brovan_start(const char *binaryPath, const char *guestCommandLine, const char *workingDirectory,
                        const char *commands, int networkMode);
extern int brovan_is_running(void);
extern void brovan_send_command(const char *command);
extern void brovan_request_close(void);
extern void brovan_request_repaint(void);
extern void brovan_inject_pointer(int action, int button, int x, int y, int buttons);
extern void brovan_inject_scroll(int delta, int x, int y, int buttons);
extern void brovan_inject_key(int down, int virtualKey, int scanCode);
extern void brovan_inject_focus(int focused);
extern int brovan_get_window_title(char *buffer, int capacity);
extern int brovan_list_windows(char *buffer, int capacity);
extern void brovan_select_window(unsigned long long hwnd);

static JavaVM *g_vm;
static jclass g_callbacks;
static jmethodID g_onLog;
static jmethodID g_onExit;
static jmethodID g_onInstallProgress;

typedef struct {
    JNIEnv *env;
    int attached;
} Attachment;

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
    if ((*g_vm)->AttachCurrentThread(g_vm, &attachment.env, NULL) == JNI_OK) {
        attachment.attached = 1;
    }

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

JNIEXPORT void JNICALL METHOD(SetVerbose)(JNIEnv *env, jclass clazz, jint enabled) {
    (void)env;
    (void)clazz;
    brovan_set_verbose(enabled);
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
