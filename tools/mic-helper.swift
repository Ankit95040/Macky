// mic-helper: first-party macOS microphone capture for Macky M14.
//
// Reads the default input device via AVAudioEngine, converts to
// 16 kHz mono 16-bit PCM, and writes RAW little-endian samples to
// stdout (no WAV header — the native STT adapter consumes raw PCM,
// so no format assembly or parsing exists on either side).
// No arguments are parsed: sample rate, channels, format, and the
// 30-second cap are compiled-in trusted constants — no planner,
// transcript, or caller data can configure capture.
//
// Exit codes (trusted contract, mirrored in src/voice/capture.ts):
//   0  finished (key released, duration cap, or clean stop)
//   1  audio failure, including microphone permission denial
//
// Recording stops on: SIGTERM/SIGINT (exits 0, emitting whatever was
// captured), 30-second internal cap, or engine failure. Whatever was
// captured up to that point is emitted; nothing is written to disk.

import AVFoundation
import Foundation

// Trusted constants. Not flags, not environment, not stdin.
let targetSampleRate: Double = 16000
let targetChannels: AVAudioChannelCount = 1
let maxRecordingSeconds: Double = 30

var shouldStop = false
signal(SIGTERM) { _ in shouldStop = true }
signal(SIGINT) { _ in shouldStop = true }

func fail(_ message: String) -> Never {
    if let data = (message + "\n").data(using: .utf8) {
        FileHandle.standardError.write(data)
    }
    Darwin.exit(1)
}

let engine = AVAudioEngine()
let input = engine.inputNode
let deviceFormat = input.outputFormat(forBus: 0)
guard deviceFormat.sampleRate > 0, deviceFormat.channelCount > 0 else {
    fail("no input device")
}
guard let converterFormat = AVAudioFormat(
    commonFormat: .pcmFormatInt16,
    sampleRate: targetSampleRate,
    channels: targetChannels,
    interleaved: true
) else {
    fail("cannot describe target format")
}
guard let converter = AVAudioConverter(from: deviceFormat, to: converterFormat) else {
    fail("cannot create converter")
}

var pcm = Data()
let lock = NSLock()
let startedAt = Date()

do {
    try engine.start()
} catch {
    fail("engine start failed (microphone unavailable or denied)")
}

input.installTap(onBus: 0, bufferSize: 4096, format: deviceFormat) { buffer, _ in
    let capacity = AVAudioFrameCount(
        Double(buffer.frameLength) * targetSampleRate / deviceFormat.sampleRate + 16
    )
    guard let converted = AVAudioPCMBuffer(pcmFormat: converterFormat, frameCapacity: capacity) else {
        return
    }
    var error: NSError?
    converter.convert(to: converted, error: &error) { _, outStatus in
        outStatus.pointee = .haveData
        return buffer
    }
    guard error == nil else {
        return
    }
    let bytes = Data(
        bytes: converted.int16ChannelData![0],
        count: Int(converted.frameLength) * MemoryLayout<Int16>.size
    )
    lock.lock()
    pcm.append(bytes)
    lock.unlock()
}

while !shouldStop {
    Thread.sleep(forTimeInterval: 0.05)
    if Date().timeIntervalSince(startedAt) >= maxRecordingSeconds {
        break
    }
}

input.removeTap(onBus: 0)
engine.stop()

lock.lock()
let body = pcm
lock.unlock()

// Raw PCM to stdout: no header, no file, no parsing surface.
FileHandle.standardOutput.write(body)
Darwin.exit(0)
