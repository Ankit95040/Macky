// stt-adapter: first-party trusted whisper.cpp adapter for Macky M14.
//
// Reads raw signed 16-bit little-endian mono 16 kHz PCM from stdin,
// converts to float32 in memory, runs whisper_full() against a model
// file given as the SOLE argument, and prints plain segment text to
// stdout (one line per segment, no timestamps).
//
// Trust contract (mirrored in src/voice/stt.ts):
//   - argv is exactly [program, modelPath]; anything else exits 2.
//   - modelPath comes only from trusted application code (SHA-256
//     verified BEFORE spawn by the TS layer, never here).
//   - no network, no filesystem writes, no audio libraries, no model
//     downloads. Diagnostics to stderr only; stdout is transcript.
// Exit codes: 0 transcribed (possibly empty), 1 usage/IO/model error,
//   2 bad argv, 3 oversized input, 4 inference failure.

#include <cstdint>
#include <cstdio>
#include <string>
#include <vector>

#include <ggml-backend.h>

#include "whisper.h"

// Hard bounds (mirror VOICE_LIMITS in src/voice/limits.ts).
static constexpr size_t kMaxPcmBytes = 1048576;  // 1 MiB
static constexpr int kThreads = 4;

int main(int argc, char ** argv) {
    if (argc != 2 || argv[1] == nullptr || argv[1][0] == '\0') {
        std::fprintf(stderr, "usage: stt-adapter <model-path>\n");
        return 2;
    }
    const char * modelPath = argv[1];

    // Bounded stdin read: raw s16le PCM, even byte count enforced.
    std::vector<char> raw;
    raw.reserve(65536);
    char chunk[8192];
    size_t n = 0;
    while ((n = std::fread(chunk, 1, sizeof(chunk), stdin)) > 0) {
        if (raw.size() + n > kMaxPcmBytes) {
            std::fprintf(stderr, "input exceeds audio bound\n");
            return 3;
        }
        raw.insert(raw.end(), chunk, chunk + n);
    }
    if (std::ferror(stdin)) {
        std::fprintf(stderr, "stdin read failed\n");
        return 1;
    }
    if (raw.empty() || (raw.size() % 2) != 0) {
        std::fprintf(stderr, "empty or odd-length PCM input\n");
        return 1;
    }

    // int16 → float32 in memory. No WAV parsing, no resampling:
    // the capture contract guarantees 16 kHz mono s16le.
    const size_t nSamples = raw.size() / 2;
    std::vector<float> pcm(nSamples);
    const auto * s16 = reinterpret_cast<const int16_t *>(raw.data());
    for (size_t i = 0; i < nSamples; ++i) {
        pcm[i] = static_cast<float>(s16[i]) / 32768.0f;
    }
    // Release raw bytes before inference.
    raw.clear();
    raw.shrink_to_fit();

    struct whisper_context_params cparams = whisper_context_default_params();
    // Default backends (GPU where available), exactly like whisper-cli:
    // without ggml_backend_load_all() the device registry is empty and
    // the first encode aborts on a null device. Same behavior as the
    // reference CLI, no more and no less.
    ggml_backend_load_all();
    struct whisper_context * ctx = whisper_init_from_file_with_params(modelPath, cparams);
    if (ctx == nullptr) {
        std::fprintf(stderr, "model load failed\n");
        return 1;
    }
    // State allocation is the caller's responsibility (#523):
    // backends/devices initialize here. Skipping it aborts inside
    // ggml-backend on the first encode.
    struct whisper_state * state = whisper_init_state(ctx);
    if (state == nullptr) {
        std::fprintf(stderr, "state allocation failed\n");
        whisper_free(ctx);
        return 1;
    }

    struct whisper_full_params wparams = whisper_full_default_params(WHISPER_SAMPLING_GREEDY);
    wparams.language = "en";
    wparams.n_threads = kThreads;
    wparams.print_progress = false;
    wparams.print_special = false;
    wparams.print_realtime = false;
    wparams.print_timestamps = false;
    wparams.no_timestamps = true;
    wparams.single_segment = false;

    int rc = 0;
    if (whisper_full(ctx, wparams, pcm.data(), static_cast<int>(nSamples)) != 0) {
        std::fprintf(stderr, "inference failed\n");
        rc = 4;
    } else {        const int nSegments = whisper_full_n_segments(ctx);
        for (int i = 0; i < nSegments; ++i) {
            const char * text = whisper_full_get_segment_text(ctx, i);
            if (text != nullptr) {
                std::string line(text);
                while (!line.empty() && (line.back() == '\n' || line.back() == '\r' || line.back() == ' ')) {
                    line.pop_back();
                }
                if (!line.empty()) {
                    std::fputs(line.c_str(), stdout);
                    std::fputc('\n', stdout);
                }
            }
        }
    }
    whisper_free_state(state);
    whisper_free(ctx);
    return rc;
}
