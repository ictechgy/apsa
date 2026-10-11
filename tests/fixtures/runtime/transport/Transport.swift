// NEW CI-only synthetic fixture. Credentials stay in process memory.
import UIKit
import CryptoKit

@main
final class AppDelegate: UIResponder, UIApplicationDelegate {
    var session = "", account = "", token = "", backend = ""
    var after = false, retain = false
    var deliveryLifecycle = "unsupported"
    let queue = DispatchQueue(label: "apsa.synthetic.transport")
    var documents: URL { FileManager.default.urls(for: .documentDirectory, in: .userDomainMask)[0] }
    func sha(_ url: URL) throws -> String { SHA256.hash(data: try Data(contentsOf: url)).map { String(format: "%02x", $0) }.joined() }
    func build() throws -> String { try sha(Bundle.main.executableURL!) }
    func stage(_ value: String) {
        // Fixed lifecycle labels only; never URLs, prompts, tokens or error text.
        try? FileManager.default.createDirectory(at: documents, withIntermediateDirectories: true)
        try? Data(value.utf8).write(to: documents.appendingPathComponent("stage.txt"), options: [.atomic])
    }
    func emit(_ value: [String: Any]) throws {
        var output = value
        output.merge(["package": Bundle.main.bundleIdentifier!, "executable_sha256": try build(),
                      "info_plist_sha256": try sha(Bundle.main.bundleURL.appendingPathComponent("Info.plist")),
                      "session": session, "account": account, "state": account.isEmpty ? "logged_out" : "authenticated",
                      "delivery": after ? "target-observed" : "baseline", "delivery_transport": "ios-os-url-context",
                      "delivery_lifecycle": deliveryLifecycle]) { _, new in new }
        try FileManager.default.createDirectory(at: documents, withIntermediateDirectories: true)
        try JSONSerialization.data(withJSONObject: output, options: [.sortedKeys]).write(to: documents.appendingPathComponent("response.json"), options: [.atomic])
        if value["action"] as? String != "fixture-error" { stage("response-written") }
    }
    func http(_ route: String) throws -> [String: Any] {
        stage(route == "/issue" ? "http-issue" : "http-logout")
        var request = URLRequest(url: URL(string: backend + route)!)
        request.httpMethod = "POST"; request.timeoutInterval = 10
        request.setValue("application/json", forHTTPHeaderField: "Content-Type")
        if !token.isEmpty { request.setValue("Bearer " + token, forHTTPHeaderField: "Authorization") }
        request.httpBody = try JSONSerialization.data(withJSONObject: ["session": session, "package": Bundle.main.bundleIdentifier!, "build": try build()])
        let wait = DispatchSemaphore(value: 0)
        var result: Data?, status = 0
        let task = URLSession.shared.dataTask(with: request) { data, response, _ in
            result = data; status = (response as? HTTPURLResponse)?.statusCode ?? 0; wait.signal()
        }
        task.resume()
        guard wait.wait(timeout: .now() + 15) == .success, status == 200, let data = result,
              let output = try JSONSerialization.jsonObject(with: data) as? [String: Any] else { task.cancel(); throw FixtureError.invalid }
        return output
    }
    enum FixtureError: Error { case invalid }
    func receive(_ url: URL, lifecycle: String) {
        stage("url-received")
        queue.async {
            self.deliveryLifecycle = lifecycle
            self.stage("url-processing")
            var failure = "failure-url-shape"
            do {
                guard url.scheme == "apsatransport", url.host == "fixture", let items = URLComponents(url: url, resolvingAgainstBaseURL: false)?.queryItems else { throw FixtureError.invalid }
                failure = "failure-session-fields"
                var fields: [String: String] = [:]
                for item in items { guard fields[item.name] == nil, let value = item.value, value.utf8.count <= 512 else { throw FixtureError.invalid }; fields[item.name] = value }
                guard let challenge = fields["session"], challenge.range(of: "^[a-f0-9]{64}$", options: .regularExpression) != nil else { throw FixtureError.invalid }
                if fields["action"] == "session" {
                    failure = "failure-session-policy"
                    guard self.session.isEmpty, let backend = fields["backend"], backend.range(of: "^http://127\\.0\\.0\\.1:[0-9]+$", options: .regularExpression) != nil else { throw FixtureError.invalid }
                    self.session = challenge; self.backend = backend; self.account = "a"; self.retain = fields["retain"] == "true"
                    try FileManager.default.createDirectory(at: self.documents, withIntermediateDirectories: true)
                    failure = "failure-http-issue"
                    guard let credential = try self.http("/issue")["credential"] as? String else { throw FixtureError.invalid }
                    self.token = credential
                    failure = "failure-store-write"
                    try "synthetic-unique-a synthetic-unique-login_a".write(to: self.documents.appendingPathComponent("state.dat"), atomically: true, encoding: .utf8)
                    try self.emit(["action": "session", "fresh_store": true])
                } else {
                    failure = "failure-session-binding"
                    guard self.session == challenge else { throw FixtureError.invalid }
                    if fields["action"] == "transition" {
                        failure = "failure-transition-fields"
                        guard !self.after, fields["kind"] == "logout" else { throw FixtureError.invalid }
                        failure = "failure-http-logout"
                        _ = try self.http("/logout"); self.account = ""; self.token = ""; self.after = true
                        failure = "failure-store-write"
                        try ("synthetic-unique-state synthetic-unique-delivery" + (self.retain ? " synthetic-unique-a" : "")).write(to: self.documents.appendingPathComponent("state.dat"), atomically: true, encoding: .utf8)
                        try self.emit(["action": "transition", "kind": "logout"])
                    } else if fields["action"] == "capture" {
                        failure = "failure-capture-fields"
                        guard let nonce = fields["nonce"], nonce.range(of: "^[a-f0-9]{64}$", options: .regularExpression) != nil, let snapshot = fields["snapshot"], fields["account"] == self.account,
                              fields["state"] == (self.account.isEmpty ? "logged_out" : "authenticated"), fields["transition"] == (self.after ? "logout" : "") else { throw FixtureError.invalid }
                        failure = "failure-store-read-or-response"
                        try self.emit(["action": "capture", "nonce": nonce, "snapshot": snapshot, "transition": self.after ? "logout" : "", "completeness": "complete",
                                       "storage": try String(contentsOf: self.documents.appendingPathComponent("state.dat"), encoding: .utf8)])
                    } else { throw FixtureError.invalid }
                }
            } catch { self.stage(failure); try? self.emit(["action": "fixture-error", "code": failure]) }
        }
    }
    func application(_ application: UIApplication, didFinishLaunchingWithOptions options: [UIApplication.LaunchOptionsKey: Any]?) -> Bool { stage("startup-app"); return true }
    func application(_ application: UIApplication, configurationForConnecting session: UISceneSession, options: UIScene.ConnectionOptions) -> UISceneConfiguration {
        let configuration = UISceneConfiguration(name: "Default", sessionRole: session.role)
        configuration.delegateClass = SceneDelegate.self
        return configuration
    }
    func application(_ app: UIApplication, open url: URL, options: [UIApplication.OpenURLOptionsKey: Any] = [:]) -> Bool { stage("os-app-url-received"); receive(url, lifecycle: "application-url-callback"); return true }
}

final class SceneDelegate: UIResponder, UIWindowSceneDelegate {
    var window: UIWindow?
    func scene(_ scene: UIScene, willConnectTo session: UISceneSession, options: UIScene.ConnectionOptions) {
        guard let scene = scene as? UIWindowScene else { return }
        (UIApplication.shared.delegate as? AppDelegate)?.stage("startup-scene")
        let window = UIWindow(windowScene: scene); window.rootViewController = UIViewController(); self.window = window; window.makeKeyAndVisible()
        if !options.urlContexts.isEmpty { (UIApplication.shared.delegate as? AppDelegate)?.stage("os-cold-url-context-received") }
        for context in options.urlContexts { (UIApplication.shared.delegate as? AppDelegate)?.receive(context.url, lifecycle: "cold-url-context") }
    }
    func sceneDidBecomeActive(_ scene: UIScene) {
        let delegate = UIApplication.shared.delegate as? AppDelegate
        // Only the initial empty session emits readiness, never overwrite an acquisition stage.
        if delegate?.session.isEmpty == true { delegate?.stage("scene-active") }
    }
    func scene(_ scene: UIScene, openURLContexts contexts: Set<UIOpenURLContext>) {
        (UIApplication.shared.delegate as? AppDelegate)?.stage("os-url-context-received")
        for context in contexts { (UIApplication.shared.delegate as? AppDelegate)?.receive(context.url, lifecycle: "warm-url-context") }
    }
}
