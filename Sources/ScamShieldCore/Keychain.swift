import Foundation
import Security

// MARK: - Integration secrets
//
// Provider keys are stored as generic passwords in the user's login Keychain, not in
// settings.json. Nothing in this file logs a key or includes it in an error message.

public enum KeychainStore {
    public static let service = "com.scamshield.integrations"

    @discardableResult
    public static func set(_ value: String, for account: String) -> Bool {
        let data = Data(value.utf8)
        let query: [String: Any] = [
            kSecClass as String: kSecClassGenericPassword,
            kSecAttrService as String: service,
            kSecAttrAccount as String: account,
        ]
        let attributes: [String: Any] = [
            kSecValueData as String: data,
            kSecAttrAccessible as String: kSecAttrAccessibleAfterFirstUnlock,
        ]
        let status = SecItemUpdate(query as CFDictionary, attributes as CFDictionary)
        if status == errSecSuccess { return true }
        if status == errSecItemNotFound || status == errSecParam {
            // errSecParam can mean the existing item was created with different
            // attributes; replace it rather than silently keeping a stale key.
            SecItemDelete(query as CFDictionary)
            var insert = query
            insert.merge(attributes) { current, _ in current }
            return SecItemAdd(insert as CFDictionary, nil) == errSecSuccess
        }
        return false
    }

    public static func get(_ account: String) -> String? {
        let query: [String: Any] = [
            kSecClass as String: kSecClassGenericPassword,
            kSecAttrService as String: service,
            kSecAttrAccount as String: account,
            kSecReturnData as String: true,
            kSecMatchLimit as String: kSecMatchLimitOne,
        ]
        var item: CFTypeRef?
        guard SecItemCopyMatching(query as CFDictionary, &item) == errSecSuccess,
              let data = item as? Data,
              let value = String(data: data, encoding: .utf8) else { return nil }
        return value
    }

    @discardableResult
    public static func delete(_ account: String) -> Bool {
        let query: [String: Any] = [
            kSecClass as String: kSecClassGenericPassword,
            kSecAttrService as String: service,
            kSecAttrAccount as String: account,
        ]
        let status = SecItemDelete(query as CFDictionary)
        return status == errSecSuccess || status == errSecItemNotFound
    }

    public static func has(_ account: String) -> Bool {
        guard let value = get(account) else { return false }
        return !value.trimmingCharacters(in: .whitespacesAndNewlines).isEmpty
    }
}

/// Stable Keychain account names. Kept separate from user-facing provider names so a
/// rename never orphans a stored key.
public enum SecretAccount {
    public static let virusTotal = "provider.virustotal"
    public static let safeBrowsing = "provider.safe-browsing"
    public static let hibp = "provider.hibp"
    public static let ai = "provider.ai"
}
