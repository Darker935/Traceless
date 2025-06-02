
#pragma once

#ifndef TRACELESS_LOG_H
#define TRACELESS_LOG_H

#ifdef DEBUG_BUILD
#define LOGD(...) __android_log_print(ANDROID_LOG_DEBUG, "Traceless", __VA_ARGS__)
#else
#define LOGD(...) ((void) 0)
#endif

#define LOGI(...) __android_log_print(ANDROID_LOG_INFO, "Traceless", __VA_ARGS__)
#define LOGE(...) __android_log_print(ANDROID_LOG_ERROR, "Traceless", __VA_ARGS__)
#define LOGW(...) __android_log_print(ANDROID_LOG_WARN, "Traceless", __VA_ARGS__)
#define LOGF(...) __android_log_print(ANDROID_LOG_FATAL, "Traceless", __VA_ARGS__)

#endif //TRACELESS_LOG_H
