import Foundation
import WebKit
import LocalAuthentication
import Security

class AuthenticationService {
    
    // M3: Insecure Authentication (Biometrics Bypass)
    var isLoggedIn = false
    
    func authenticateUser() {
        let context = LAContext()
        var error: NSError?

        if context.canEvaluatePolicy(.deviceOwnerAuthenticationWithBiometrics, error: &error) {
            context.evaluatePolicy(.deviceOwnerAuthenticationWithBiometrics, localizedReason: "Log in") { success, authenticationError in
                // Vulnerability: authentication relies only on a boolean flag
                if success {
                    self.isLoggedIn = true
                    print("DEBUG: User authenticated via biometrics")
                } else {
                    self.isLoggedIn = false
                }
            }
        }
    }
    
    // M3: Insecure Authorization (Unverified JWT Signature)
    func validateAdminAccess(jwtToken: String) -> Bool {
        let segments = jwtToken.components(separatedBy: ".")
        if segments.count == 3 {
            // Vulnerability: Reading payload without verifying the cryptographic signature
            let payloadBase64 = segments[1]
            
            if let decodedData = Data(base64Encoded: payloadBase64),
               let payloadString = String(data: decodedData, encoding: .utf8) {
                
                if payloadString.contains("\"role\":\"admin\"") {
                    print("DEBUG: Admin access granted via unverified JWT")
                    return true
                }
            }
        }
        return false
    }
    
    // M3: Insecure Authentication (Weak Keychain Access Control)
    func saveSessionTokenInsecurely(tokenData: Data) {
        let query: [String: Any] = [
            kSecClass as String: kSecClassGenericPassword,
            kSecAttrAccount as String: "ActiveSession",
            kSecValueData as String: tokenData,
            // Vulnerability: Token is always accessible, bypassing Data Protection API
            kSecAttrAccessible as String: kSecAttrAccessibleAlways
        ]
        
        SecItemAdd(query as CFDictionary, nil)
    }
}

class DatabaseService {
    
    // M4: Insufficient Input Validation (SQL Injection)
    func getUserData(username: String) {
        // Vulnerability: direct concatenation of user input into SQL query
        let query = "SELECT * FROM users WHERE username = '\(username)'"
        
        print("Executing query: \(query)")
    }
}

class WebViewService {
    
    // M4: Insufficient Output Validation (XSS in WKWebView)
    var webView: WKWebView = WKWebView()

    func injectUserContent(userInput: String) {
        // Vulnerability: executing unescaped input within a web context
        let javascriptCode = "document.getElementById('user-profile').innerHTML = '\(userInput)';"
        
        webView.evaluateJavaScript(javascriptCode) { (result, error) in
            if let error = error {
                print("JS Execution Error: \(error.localizedDescription)")
            }
        }
    }
    
    func injectSafeContent() {
        let safeScript = "console.log('App loaded successfully');"
        webView.evaluateJavaScript(safeScript, completionHandler: nil)
    }
}

class StorageService {
    
    // M9: Insecure Data Storage (Local File System)
    func saveCredentialsToFile(password: String) {
        let fileManager = FileManager.default
        if let documentDirectory = fileManager.urls(for: .documentDirectory, in: .userDomainMask).first {
            let fileURL = documentDirectory.appendingPathComponent("credentials.txt")
            
            do {
                // Vulnerability: Writing sensitive data in plain text to the file system
                try password.write(to: fileURL, atomically: true, encoding: .utf8)
                print("DEBUG: Password saved to \(fileURL)")
            } catch {
                print("Error saving file")
            }
        }
    }
    
    // M9: Insecure Data Storage (UserDefaults)
    func saveTokenToUserDefaults(token: String) {
        // Vulnerability: UserDefaults is not encrypted and can be easily extracted
        UserDefaults.standard.set(token, forKey: "user_auth_token")
    }
}
