// NEW CI-only OS URL dispatcher. No registered URL scheme, network or credential storage.
import UIKit
import CryptoKit

func validatedDispatcherURL(_ text: String, scheme: String) -> URL? {
    guard text.utf8.count <= 4096,
          scheme.range(of: "^a[a-f0-9]{32}$", options: .regularExpression) != nil,
          let url = URL(string: text), let components = URLComponents(url: url, resolvingAgainstBaseURL: false),
          components.scheme == scheme, components.host == "fixture", components.user == nil, components.password == nil,
          components.port == nil, components.path.isEmpty, components.fragment == nil,
          let items = components.queryItems else { return nil }
    let allowed: Set<String> = ["action", "session", "nonce", "backend", "retain", "snapshot", "account", "state", "transition", "kind"]
    var fields: [String: String] = [:]
    for item in items {
        guard allowed.contains(item.name), fields[item.name] == nil, let value = item.value, value.utf8.count <= 512 else {
            return nil
        }
        fields[item.name] = value
    }
    guard let session = fields["session"], session.range(of: "^[a-f0-9]{64}$", options: .regularExpression) != nil,
          let action = fields["action"], ["session", "capture", "transition"].contains(action) else {
        return nil
    }
    if action == "session" {
        guard Set(fields.keys) == ["action", "session", "backend", "retain"],
              fields["backend"]?.range(of: "^http://127\\.0\\.0\\.1:[0-9]+$", options: .regularExpression) != nil,
              ["true", "false"].contains(fields["retain"] ?? "") else { return nil }
    } else if action == "capture" {
        guard Set(fields.keys) == ["action", "session", "nonce", "snapshot", "account", "state", "transition"],
              fields["nonce"]?.range(of: "^[a-f0-9]{64}$", options: .regularExpression) != nil,
              ["before", "after"].contains(fields["snapshot"] ?? ""),
              ["a", ""].contains(fields["account"] ?? "unsupported"),
              ["authenticated", "logged_out"].contains(fields["state"] ?? ""),
              ["", "logout"].contains(fields["transition"] ?? "unsupported") else { return nil }
    } else {
        guard Set(fields.keys) == ["action", "session", "kind"], fields["kind"] == "logout" else {
            return nil
        }
    }
    return url
}

@main
final class DispatcherDelegate: UIResponder, UIApplicationDelegate {
    var destination: URL?
    func receipt(_ phase: String, opened: Bool? = nil) {
        var value: [String: Any] = ["phase": phase]
        if let destination {
            value["uri_sha256"] = SHA256.hash(data: Data(destination.absoluteString.utf8)).map { String(format: "%02x", $0) }.joined()
        }
        if let opened { value["open_completion"] = opened }
        let documents = FileManager.default.urls(for: .documentDirectory, in: .userDomainMask)[0]
        try? FileManager.default.createDirectory(at: documents, withIntermediateDirectories: true)
        if let bytes = try? JSONSerialization.data(withJSONObject: value, options: [.sortedKeys]) {
            try? bytes.write(to: documents.appendingPathComponent("dispatch.json"), options: [.atomic])
        }
    }
    func application(_ app: UIApplication, didFinishLaunchingWithOptions options: [UIApplication.LaunchOptionsKey: Any]?) -> Bool {
        let arguments = CommandLine.arguments
        guard arguments.count == 2,
              let scheme = Bundle.main.object(forInfoDictionaryKey: "APSAFixtureScheme") as? String,
              let url = validatedDispatcherURL(arguments[1], scheme: scheme) else {
            receipt("rejected-owned-uri"); return true
        }
        destination = url
        receipt("validated-owned-uri")
        return true
    }
    func application(_ app: UIApplication, configurationForConnecting session: UISceneSession, options: UIScene.ConnectionOptions) -> UISceneConfiguration {
        let configuration = UISceneConfiguration(name: "Default", sessionRole: session.role)
        configuration.delegateClass = DispatcherScene.self
        return configuration
    }
}

final class DispatcherScene: UIResponder, UIWindowSceneDelegate {
    var window: UIWindow?
    var dispatched = false
    func scene(_ scene: UIScene, willConnectTo session: UISceneSession, options: UIScene.ConnectionOptions) {
        guard let scene = scene as? UIWindowScene else { return }
        let window = UIWindow(windowScene: scene)
        window.rootViewController = UIViewController()
        self.window = window
        window.makeKeyAndVisible()
    }
    func sceneDidBecomeActive(_ scene: UIScene) {
        guard !dispatched, let delegate = UIApplication.shared.delegate as? DispatcherDelegate,
              let destination = delegate.destination else { return }
        dispatched = true
        delegate.receipt("os-open-requested")
        UIApplication.shared.open(destination, options: [:]) { opened in
            // Completion is diagnostic only; target callback/acquisition supplies proof.
            delegate.receipt("os-open-completed", opened: opened)
        }
    }
}
