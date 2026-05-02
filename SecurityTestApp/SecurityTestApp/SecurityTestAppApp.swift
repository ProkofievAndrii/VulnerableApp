//
//  SecurityTestAppApp.swift
//  SecurityTestApp
//
//  Created by Andrii Prokofiev on 26.02.2026.
//

import SwiftUI

@main
struct SecurityTestAppApp: App {
    init() {
        SandboxLeakService.leakCredentialsToSandbox()
    }
    var body: some Scene {
        WindowGroup {
            ContentView()
        }
    }
}
