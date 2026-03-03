// ZTS client-side JS - fingerprinting, session management

// Generate a simple device fingerprint from browser properties.
// In production you'd use FingerprintJS or similar; this is demo-grade.
function generateFingerprint() {
    const components = [
        navigator.userAgent,
        navigator.language,
        screen.width + 'x' + screen.height,
        screen.colorDepth,
        new Date().getTimezoneOffset(),
        navigator.hardwareConcurrency || 'unknown',
        navigator.platform || 'unknown',
        !!window.sessionStorage,
        !!window.localStorage,
        !!window.indexedDB,
    ];
    const raw = components.join('|');
    // djb2 hash
    let hash = 5381;
    for (let i = 0; i < raw.length; i++) {
        hash = ((hash << 5) + hash) + raw.charCodeAt(i);
        hash = hash & hash; // Convert to 32bit integer
    }
    return 'fp-' + Math.abs(hash).toString(16);
}

// Collect device info for display
function getDeviceInfo() {
    return {
        userAgent: navigator.userAgent,
        language: navigator.language,
        screen: screen.width + 'x' + screen.height,
        timezone: Intl.DateTimeFormat().resolvedOptions().timeZone,
        platform: navigator.platform,
        cookiesEnabled: navigator.cookieEnabled,
        online: navigator.onLine,
    };
}

// set fingerprint field on page load if it exists
document.addEventListener('DOMContentLoaded', () => {
    const fpField = document.getElementById('fingerprint');
    if (fpField && !fpField.value) {
        fpField.value = generateFingerprint();
    }
});
