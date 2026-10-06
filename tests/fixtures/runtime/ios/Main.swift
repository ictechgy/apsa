import UIKit

func fixtureFile(_ name: String) -> URL {
    let directory = FileManager.default.urls(for: .documentDirectory, in: .userDomainMask)[0]
    try! FileManager.default.createDirectory(at: directory, withIntermediateDirectories: true)
    return directory.appendingPathComponent(name)
}

@main
class AppDelegate: UIResponder, UIApplicationDelegate {
    func application(_ application: UIApplication, didFinishLaunchingWithOptions options: [UIApplication.LaunchOptionsKey: Any]?) -> Bool {
        try! "mobile-audit-account-A-2026-canary".write(to: fixtureFile("account-cache.txt"), atomically: true, encoding: .utf8)
        try! "Account A active".write(to: fixtureFile("state.txt"), atomically: true, encoding: .utf8)
        return true
    }
}

class SceneDelegate: UIResponder, UIWindowSceneDelegate {
    var window: UIWindow?
    let label = UILabel()
    func scene(_ scene: UIScene, willConnectTo session: UISceneSession, options: UIScene.ConnectionOptions) {
        guard let scene = scene as? UIWindowScene else { return }
        let controller = UIViewController()
        controller.view.backgroundColor = .systemBackground
        label.text = "Owned Mobile Audit fixture: Account A active"
        label.frame = CGRect(x: 20, y: 150, width: 350, height: 120)
        label.numberOfLines = 0
        controller.view.addSubview(label)
        window = UIWindow(windowScene: scene)
        window?.rootViewController = controller
        window?.makeKeyAndVisible()
        // Deterministic owned fixture transition; not a general UI automation claim.
        DispatchQueue.main.asyncAfter(deadline: .now() + 4) { self.transition() }
        for context in options.urlContexts { handle(context.url) }
    }
    func scene(_ scene: UIScene, openURLContexts contexts: Set<UIOpenURLContext>) {
        for context in contexts { handle(context.url) }
    }
    func handle(_ url: URL) {
        if url.scheme == "mobileauditfixture", url.host == "transition" {
            try! "Target received deep link".write(to: fixtureFile("url-delivery.txt"), atomically: true, encoding: .utf8)
            transition()
        }
    }
    func transition() {
        let retain = Bundle.main.object(forInfoDictionaryKey: "AuditFixtureRetainCanary") as? Bool ?? false
        let switching = Bundle.main.object(forInfoDictionaryKey: "AuditFixtureSwitchAccount") as? Bool ?? false
        if !retain { try? FileManager.default.removeItem(at: fixtureFile("account-cache.txt")) }
        let state = switching ? "Account B active" : "Signed out state"
        try! state.write(to: fixtureFile("state.txt"), atomically: true, encoding: .utf8)
        label.text = "Owned Mobile Audit fixture: " + state
    }
}
