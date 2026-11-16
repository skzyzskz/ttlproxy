// TTLProxyApp.swift
// iPhone'da 127.0.0.1:8080 uzerinde HTTP/HTTPS proxy calistirir.
// Disari acilan her TCP baglantisinin TTL/hop limit degeri 65'tir,
// Android hotspot'tan gecince operatore 64 olarak ulasir.
//
// Kurulum:
//  1. Xcode > New Project > iOS App (SwiftUI). Olusan tum .swift dosyalarini silip bu dosyayi ekle.
//  2. Signing & Capabilities > Team: kisisel (ucretsiz) Apple ID.
//  3. + Capability > Background Modes > "Audio, AirPlay, and Picture in Picture" isaretle.
//  4. iPhone'a yukle, uygulamada "Baslat"a bas.
//  5. iPhone: Ayarlar > Wi-Fi > hotspot (i) > Proxy'yi Yapilandir > Elle > 127.0.0.1 : 8080

import SwiftUI
import Network
import AVFoundation

// MARK: - App

@main
struct TTLProxyApp: App {
    @StateObject private var proxy = ProxyServer(port: 8080, ttl: 65)

    var body: some Scene {
        WindowGroup {
            ContentView().environmentObject(proxy)
        }
    }
}

struct ContentView: View {
    @EnvironmentObject var proxy: ProxyServer

    var body: some View {
        VStack(spacing: 16) {
            Text(proxy.running ? "Calisiyor  127.0.0.1:\(proxy.port)" : "Durdu")
                .font(.headline)
            Text("TTL: \(proxy.ttl)   Aktif baglanti: \(proxy.active)")
                .font(.subheadline)
            if let err = proxy.lastError {
                Text(err).font(.footnote).foregroundColor(.red)
            }
            Button(proxy.running ? "Durdur" : "Baslat") {
                proxy.running ? proxy.stop() : proxy.start()
            }
            .buttonStyle(.borderedProminent)
        }
        .padding()
    }
}

// MARK: - Proxy server

final class ProxyServer: ObservableObject {
    let port: UInt16
    let ttl: UInt8

    @Published var running = false
    @Published var active = 0
    @Published var lastError: String?

    private var listener: NWListener?
    private let queue = DispatchQueue(label: "ttlproxy", qos: .userInitiated, attributes: .concurrent)
    private let keepAlive = SilentAudio()

    init(port: UInt16, ttl: UInt8) {
        self.port = port
        self.ttl = ttl
    }

    func start() {
        guard listener == nil else { return }
        let params = NWParameters.tcp
        params.allowLocalEndpointReuse = true
        // Sadece loopback: hotspot agindaki baska cihazlar bu proxy'yi kullanamaz.
        params.requiredLocalEndpoint = .hostPort(host: "127.0.0.1", port: NWEndpoint.Port(rawValue: port)!)

        do {
            let l = try NWListener(using: params)
            l.newConnectionHandler = { [weak self] conn in self?.accept(conn) }
            l.stateUpdateHandler = { [weak self] state in
                DispatchQueue.main.async {
                    switch state {
                    case .ready:
                        self?.running = true
                        self?.lastError = nil
                    case .failed(let e):
                        self?.lastError = "Listener hatasi: \(e)"
                        self?.stop()
                    default: break
                    }
                }
            }
            l.start(queue: queue)
            listener = l
            keepAlive.start()
        } catch {
            lastError = "Listener acilamadi: \(error)"
        }
    }

    func stop() {
        listener?.cancel()
        listener = nil
        keepAlive.stop()
        running = false
    }

    private func accept(_ conn: NWConnection) {
        DispatchQueue.main.async { self.active += 1 }
        let s = Session(client: conn, ttl: ttl, queue: queue) { [weak self] in
            DispatchQueue.main.async { self?.active -= 1 }
        }
        s.start()
    }
}

// MARK: - Session (tek istemci baglantisi)

final class Session {
    private let client: NWConnection
    private var remote: NWConnection?
    private let ttl: UInt8
    private let queue: DispatchQueue
    private let onClose: () -> Void

    private let lock = NSLock()
    private var closed = false
    private var buffer = Data()
    private var selfRef: Session?   // kapanana kadar canli tut

    private static let headerEnd = Data("\r\n\r\n".utf8)
    private static let maxHeader = 64 * 1024

    init(client: NWConnection, ttl: UInt8, queue: DispatchQueue, onClose: @escaping () -> Void) {
        self.client = client
        self.ttl = ttl
        self.queue = queue
        self.onClose = onClose
    }

    func start() {
        selfRef = self
        client.stateUpdateHandler = { [weak self] state in
            switch state {
            case .failed, .cancelled: self?.close()
            default: break
            }
        }
        client.start(queue: queue)
        readHeader()
    }

    // Istek basligini "\r\n\r\n" gelene kadar oku.
    private func readHeader() {
        client.receive(minimumIncompleteLength: 1, maximumLength: 65536) { [weak self] data, _, done, err in
            guard let self else { return }
            if let data { self.buffer.append(data) }
            if let r = self.buffer.range(of: Session.headerEnd) {
                self.handle(headerEnd: r.upperBound)
            } else if done || err != nil || self.buffer.count > Session.maxHeader {
                self.close()
            } else {
                self.readHeader()
            }
        }
    }

    private func handle(headerEnd: Int) {
        guard
            let head = String(data: buffer.prefix(headerEnd), encoding: .utf8),
            let line = head.components(separatedBy: "\r\n").first
        else { return fail() }

        let parts = line.split(separator: " ")
        guard parts.count >= 3 else { return fail() }
        let method = parts[0].uppercased()
        let target = String(parts[1])

        if method == "CONNECT" {
            // HTTPS: ham TCP tuneli
            guard let hp = Session.splitHostPort(target, defaultPort: 443) else { return fail() }
            let rest = Data(buffer.suffix(from: headerEnd))
            connectRemote(hp.0, hp.1) { [weak self] in
                guard let self else { return }
                self.client.send(content: Data("HTTP/1.1 200 Connection Established\r\n\r\n".utf8),
                                 completion: .contentProcessed { _ in })
                if !rest.isEmpty {
                    self.remote?.send(content: rest, completion: .contentProcessed { _ in })
                }
                self.startPipes()
            }
        } else {
            // Duz HTTP: absolute-form istegi oldugu gibi ilet (RFC 9112: sunucular kabul etmek zorunda).
            guard let comps = URLComponents(string: target), let host = comps.host else { return fail() }
            let port = UInt16(comps.port ?? 80)
            let all = buffer
            connectRemote(host, port) { [weak self] in
                guard let self else { return }
                self.remote?.send(content: all, completion: .contentProcessed { _ in })
                self.startPipes()
            }
        }
        buffer.removeAll()
    }

    private func connectRemote(_ host: String, _ port: UInt16, ready: @escaping () -> Void) {
        guard let p = NWEndpoint.Port(rawValue: port) else { return fail() }

        let params = NWParameters.tcp
        params.preferNoProxies = true                       // kendi proxy'mize geri donmesin
        if let ip = params.defaultProtocolStack.internetProtocol as? NWProtocolIP.Options {
            ip.hopLimit = ttl                               // IPv4 TTL ve IPv6 hop limit
        }

        let r = NWConnection(host: NWEndpoint.Host(host), port: p, using: params)
        remote = r
        var fired = false
        r.stateUpdateHandler = { [weak self] state in
            switch state {
            case .ready:
                if !fired { fired = true; ready() }
            case .failed, .cancelled:
                if !fired { self?.fail() } else { self?.close() }
            case .waiting:
                // Hedefe ulasilamiyor (DNS, ag yok vb.)
                if !fired { self?.fail() }
            default: break
            }
        }
        r.start(queue: queue)
    }

    private func startPipes() {
        guard let remote else { return close() }
        pipe(from: client, to: remote)
        pipe(from: remote, to: client)
    }

    private func pipe(from: NWConnection, to: NWConnection) {
        from.receive(minimumIncompleteLength: 1, maximumLength: 65536) { [weak self] data, _, done, err in
            guard let self else { return }
            if let data, !data.isEmpty {
                to.send(content: data, completion: .contentProcessed { sendErr in
                    if sendErr != nil || done || err != nil {
                        self.close()
                    } else {
                        self.pipe(from: from, to: to)
                    }
                })
            } else if done || err != nil {
                self.close()
            } else {
                self.pipe(from: from, to: to)
            }
        }
    }

    private func fail() {
        client.send(content: Data("HTTP/1.1 502 Bad Gateway\r\nContent-Length: 0\r\nConnection: close\r\n\r\n".utf8),
                    completion: .contentProcessed { [weak self] _ in self?.close() })
    }

    private func close() {
        lock.lock()
        if closed { lock.unlock(); return }
        closed = true
        lock.unlock()

        client.cancel()
        remote?.cancel()
        onClose()
        selfRef = nil
    }

    static func splitHostPort(_ s: String, defaultPort: UInt16) -> (String, UInt16)? {
        // [IPv6]:port
        if s.hasPrefix("["), let end = s.firstIndex(of: "]") {
            let host = String(s[s.index(after: s.startIndex)..<end])
            let rest = s[s.index(after: end)...]
            if rest.isEmpty { return (host, defaultPort) }
            guard rest.hasPrefix(":"), let p = UInt16(rest.dropFirst()) else { return nil }
            return (host, p)
        }
        let parts = s.split(separator: ":", omittingEmptySubsequences: false)
        switch parts.count {
        case 1: return (s, defaultPort)
        case 2:
            guard let p = UInt16(parts[1]) else { return nil }
            return (String(parts[0]), p)
        default: return nil
        }
    }
}

// MARK: - Arka planda canli tutma (sessiz ses)

final class SilentAudio {
    private let engine = AVAudioEngine()
    private let player = AVAudioPlayerNode()
    private var observer: NSObjectProtocol?

    init() {
        engine.attach(player)
    }

    func start() {
        let session = AVAudioSession.sharedInstance()
        try? session.setCategory(.playback, options: [.mixWithOthers])
        try? session.setActive(true)

        let fmt = engine.mainMixerNode.outputFormat(forBus: 0)
        engine.connect(player, to: engine.mainMixerNode, format: fmt)
        engine.mainMixerNode.outputVolume = 0

        guard let buf = AVAudioPCMBuffer(pcmFormat: fmt, frameCapacity: AVAudioFrameCount(fmt.sampleRate)) else { return }
        buf.frameLength = buf.frameCapacity   // tamami sifir = sessizlik

        do { try engine.start() } catch { return }
        player.scheduleBuffer(buf, at: nil, options: .loops)
        player.play()

        // Arama vb. kesintiden sonra yeniden baslat
        observer = NotificationCenter.default.addObserver(
            forName: AVAudioSession.interruptionNotification, object: nil, queue: .main
        ) { [weak self] note in
            guard
                let raw = note.userInfo?[AVAudioSessionInterruptionTypeKey] as? UInt,
                AVAudioSession.InterruptionType(rawValue: raw) == .ended
            else { return }
            try? AVAudioSession.sharedInstance().setActive(true)
            try? self?.engine.start()
            self?.player.play()
        }
    }

    func stop() {
        if let observer { NotificationCenter.default.removeObserver(observer) }
        observer = nil
        player.stop()
        engine.stop()
        try? AVAudioSession.sharedInstance().setActive(false, options: .notifyOthersOnDeactivation)
    }
}
