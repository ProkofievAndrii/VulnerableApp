//
//  ContentView.swift
//  SecurityTestApp
//
//  Created by Andrii Prokofiev on 26.02.2026.
//

import SwiftUI
import CommonCrypto

struct ContentView: View {
    // M1: Improper Credential Usage
    let apiSecret = "AIzaSyB-83492_asD9238492n3asD_231908"
    let firebaseToken = "1:923481029:ios:9a2c3d4e5f6g7h8i"

    @State private var username = ""
    @State private var password = ""
    @State private var statusMessage = ""
    
    let authService = AuthenticationService()
    let dbService = DatabaseService()
    let webService = WebViewService()
    let storageService = StorageService()

    var body: some View {
        NavigationView {
            Form {
                Section(header: Text("Basic Auth (M1, M5, M9, M10)")) {
                    TextField("Username", text: $username)
                    SecureField("Password", text: $password)
                    Button("Login (Insecure)") {
                        performInsecureLogin()
                    }
                }
                
                Section(header: Text("Biometrics & Auth (M3)")) {
                    Button("Login with FaceID / TouchID") {
                        authService.authenticateUser()
                    }
                    Button("Validate Admin JWT") {
                        let dummyToken = "header.eyJyb2xlIjoiYWRtaW4ifQ==.signature"
                        let _ = authService.validateAdminAccess(jwtToken: dummyToken)
                    }
                    Button("Create Weak Biometry Key") {
                        authService.createWeakBiometricKey()
                    }
                }
                
                Section(header: Text("Input/Output Validation (M4)")) {
                    Button("Trigger SQL Injection") {
                        dbService.getUserData(username: username)
                    }
                    Button("Trigger XSS in WebView") {
                        webService.injectUserContent(userInput: username)
                    }
                }

                Section(header: Text("Advanced Data & Crypto (M9, M10)")) {
                    Button("Copy Password to Clipboard") {
                        storageService.copyToClipboard(sensitiveData: password)
                        statusMessage = "Password copied to pasteboard!"
                    }
                    Button("Save to Shared App Group") {
                        storageService.saveToSharedContainer(data: password)
                        statusMessage = "Saved to vulnerable App Group"
                    }
                    Button("Generate Weak Token") {
                        let token = authService.generateSessionToken()
                        statusMessage = "Weak token generated: \(token)"
                    }
                }
                
                Section {
                    Text(statusMessage)
                        .foregroundColor(.red)
                }
            }
            .navigationTitle("Security Test App")
        }
    }

    func performInsecureLogin() {
        // M9: Insecure Data Storage
        print("DEBUG: Attempting login for \(username) with password: \(password)")

        // M9: Insecure Data Storage
        UserDefaults.standard.set(password, forKey: "last_logged_in_password")

        // M10: Insufficient Cryptography
        let passwordHash = insecureHash(password)
        
        // M5: Insecure Communication
        sendDataToServer(user: username, hash: passwordHash)
    }

    func insecureHash(_ input: String) -> String {
        let length = Int(CC_MD5_DIGEST_LENGTH)
        let messageData = input.data(using:.utf8)!
        var digest = [UInt8](repeating: 0, count:length)
        
        _ = messageData.withUnsafeBytes {
            CC_MD5($0.baseAddress, CC_LONG(messageData.count), &digest)
        }
        
        return digest.map { String(format: "%02hhx", $0) }.joined()
    }
    
    func sendDataToServer(user: String, hash: String) {
        let urlString = "http://api.myserver.com/login?u=\(user)&p=\(hash)"
        print("Sending request to: \(urlString)")
        statusMessage = "Data sent over insecure channel!"
    }
}
