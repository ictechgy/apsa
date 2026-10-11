// Owned fresh simulator fixture. No UI inspection, backend or device proof.
import UIKit
import CryptoKit

@main
final class AppDelegate: UIResponder, UIApplicationDelegate {
    var session = ""
    var kind = ""
    var account: String? = nil
    var original: String? = nil
    var transitioned = false
    var retain = false
    var store: URL? = nil
    let files = FileManager.default
    var documents: URL { files.urls(for: .documentDirectory, in: .userDomainMask)[0] }
    func sha(_ path: URL) -> String {
        SHA256.hash(data: try! Data(contentsOf: path)).map { String(format: "%02x", $0) }.joined()
    }
    var build: String { sha(Bundle.main.executableURL!) }
    var plist: String { sha(Bundle.main.bundleURL.appendingPathComponent("Info.plist")) }
    func labels() -> String {
        var labels: [String] = []
        if let account = account { labels += ["synthetic-unique-" + account, "synthetic-unique-login_" + account] }
        else if !transitioned { labels += ["synthetic-unique-baseline"] }
        if transitioned { labels += ["synthetic-unique-state", "synthetic-unique-delivery"] }
        return labels.joined(separator: " ")
    }
    func response(_ value: [String: Any]) {
        try! files.createDirectory(at: documents, withIntermediateDirectories: true)
        try! JSONSerialization.data(withJSONObject: value, options: [.sortedKeys]).write(to: documents.appendingPathComponent("response.json"), options: [.atomic])
    }
    func saveState() {
        let value: [String: Any] = ["kind": kind, "account": account ?? "", "original": original ?? "", "transitioned": transitioned, "retain": retain]
        try! JSONSerialization.data(withJSONObject: value, options: [.sortedKeys]).write(to: store!.deletingLastPathComponent().appendingPathComponent("metadata.json"), options: [.atomic])
    }
    func application(_ app: UIApplication, didFinishLaunchingWithOptions options: [UIApplication.LaunchOptionsKey: Any]?) -> Bool {
        response(["action": "ready", "package": Bundle.main.bundleIdentifier!, "executable_sha256": build, "info_plist_sha256": plist])
        // Explicit fixture instrumentation bridge, not an OS deep-link routing claim.
        if let argument = ProcessInfo.processInfo.arguments.first(where: { $0.hasPrefix("apsacompiled://fixture?") }), let url = URL(string: argument) {
            _ = application(app, open: url)
        }
        return true
    }
    func application(_ app: UIApplication, open url: URL, options: [UIApplication.OpenURLOptionsKey: Any] = [:]) -> Bool {
        response(["action": "url-received"])
        func reject(_ code: String) -> Bool { response(["action": "fixture-error", "code": code]); return false }
        guard url.scheme == "apsacompiled", let query = URLComponents(url: url, resolvingAgainstBaseURL: false)?.queryItems else { return reject("url-shape") }
        var fields: [String: String] = [:]
        for item in query {
            guard fields[item.name] == nil, let value = item.value, value.utf8.count < 256 else { return reject("field-shape") }
            fields[item.name] = value
        }
        guard let action = fields["action"], let challenge = fields["session"], challenge.count == 64,
              challenge.allSatisfy({ $0.isHexDigit }) else { return reject("challenge") }
        if action != "session", session.isEmpty {
            let directory = documents.appendingPathComponent(challenge, isDirectory: true)
            let metadata = directory.appendingPathComponent("metadata.json")
            guard let data = try? Data(contentsOf: metadata), let value = try? JSONSerialization.jsonObject(with: data) as? [String: Any],
                  let storedKind = value["kind"] as? String, ["login", "account_switch", "logout"].contains(storedKind),
                  let storedAccount = value["account"] as? String, ["", "a", "b"].contains(storedAccount),
                  let storedOriginal = value["original"] as? String, ["", "a"].contains(storedOriginal),
                  let storedTransition = value["transitioned"] as? Bool, let storedRetain = value["retain"] as? Bool else { return reject("store") }
            session = challenge; kind = storedKind; account = storedAccount.isEmpty ? nil : storedAccount
            original = storedOriginal.isEmpty ? nil : storedOriginal; transitioned = storedTransition; retain = storedRetain
            store = directory.appendingPathComponent("state.dat")
        }
        if action == "session" {
            guard session.isEmpty, let requestedKind = fields["kind"], ["login", "account_switch", "logout"].contains(requestedKind) else { return reject("session-state") }
            let initial = fields["account"] ?? ""
            guard initial.isEmpty || initial == "a" else { return reject("account") }
            session = challenge; kind = requestedKind; account = initial.isEmpty ? nil : initial; original = account
            retain = fields["retain"] == "true"
            let directory = documents.appendingPathComponent(session, isDirectory: true)
            guard !files.fileExists(atPath: directory.path) else { return reject("store") }
            try! files.createDirectory(at: directory, withIntermediateDirectories: false)
            store = directory.appendingPathComponent("state.dat")
            try! labels().write(to: store!, atomically: true, encoding: .utf8)
            saveState()
            response(["action": "session", "session": session, "package": Bundle.main.bundleIdentifier!, "executable_sha256": build, "info_plist_sha256": plist, "fresh_store": true])
        } else if action == "transition" {
            guard challenge == session, fields["kind"] == kind, !transitioned else { return false }
            account = kind == "logout" ? nil : kind == "account_switch" ? "b" : "a"; transitioned = true
            let residual = retain && original != nil ? " synthetic-unique-" + original! : ""
            try! (labels() + residual).write(to: store!, atomically: true, encoding: .utf8)
            saveState()
            response(["action": "transition", "session": session, "kind": kind, "account": account ?? "", "delivery": "target-observed", "executable_sha256": build])
        } else if action == "capture" {
            guard challenge == session, let nonce = fields["nonce"], nonce.count == 64,
                  nonce.allSatisfy({ $0.isHexDigit }), let snapshot = fields["snapshot"],
                  fields["account"] == (account ?? ""),
                  fields["state"] == (account == nil ? "logged_out" : "authenticated"),
                  fields["transition"] == (transitioned ? kind : "") else { return false }
            response(["action": "capture", "session": session, "nonce": nonce, "snapshot": snapshot,
                      "account": account ?? "", "state": account == nil ? "logged_out" : "authenticated",
                      "transition": transitioned ? kind : "", "delivery": transitioned ? "target-observed" : "baseline",
                      "executable_sha256": build, "info_plist_sha256": plist,
                      "storage": try! String(contentsOf: store!, encoding: .utf8), "completeness": "complete"])
        } else { return false }
        return true
    }
}

final class SceneDelegate: UIResponder, UIWindowSceneDelegate {
    var window: UIWindow?
    func scene(_ scene: UIScene, willConnectTo session: UISceneSession, options: UIScene.ConnectionOptions) {
        guard let scene = scene as? UIWindowScene else { return }
        let window = UIWindow(windowScene: scene)
        window.rootViewController = UIViewController()
        self.window = window
        window.makeKeyAndVisible()
        if let delegate = UIApplication.shared.delegate as? AppDelegate {
            for context in options.urlContexts { _ = delegate.application(UIApplication.shared, open: context.url) }
        }
    }
    func scene(_ scene: UIScene, openURLContexts contexts: Set<UIOpenURLContext>) {
        guard let delegate = UIApplication.shared.delegate as? AppDelegate else { return }
        for context in contexts { _ = delegate.application(UIApplication.shared, open: context.url) }
    }
}
