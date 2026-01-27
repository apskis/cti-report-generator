# Cursor AI Development Rules - Chrome Extensions

These rules are specific to Chrome Extension development. Also reference CURSOR_RULES_UNIVERSAL.md, CURSOR_RULES_JAVASCRIPT.md, CURSOR_RULES_REACT.md, CURSOR_RULES_SECURITY.md, and CURSOR_RULES_ARCHITECTURE.md.

## Manifest Version

1. **Always use Manifest V3** (not V2, which is deprecated). Manifest V3 is required for new extensions and has better security.

2. Structure your manifest.json properly with all required fields: name, version, manifest_version, description, icons, action (for popup), permissions, host_permissions, background (service worker), content_scripts.

3. Follow Chrome Extension manifest.json schema exactly. Use proper permission strings. Check documentation: https://developer.chrome.com/docs/extensions/mv3/manifest/

## Project Structure for Chrome Extension
```
my-extension/
├── public/                         # Static assets
│   ├── icons/
│   │   ├── icon16.png
│   │   ├── icon48.png
│   │   └── icon128.png
│   └── manifest.json              # Extension manifest
├── src/
│   ├── background/                # Background service worker
│   │   ├── index.ts               # Main background script
│   │   ├── messaging.ts           # Message handling
│   │   ├── storage.ts             # Storage operations
│   │   └── api.ts                 # API calls
│   ├── content/                   # Content scripts
│   │   ├── index.ts               # Main content script
│   │   ├── dom-manipulation.ts    # DOM operations
│   │   └── messaging.ts           # Communication with background
│   ├── popup/                     # Extension popup
│   │   ├── Popup.tsx              # Main popup component
│   │   ├── components/            # Popup-specific components
│   │   ├── hooks/                 # Popup-specific hooks
│   │   ├── index.tsx              # Popup entry point
│   │   └── index.html             # Popup HTML
│   ├── options/                   # Options/settings page
│   │   ├── Options.tsx
│   │   ├── components/
│   │   ├── index.tsx
│   │   └── index.html
│   ├── shared/                    # Shared across extension parts
│   │   ├── types/
│   │   │   ├── messages.ts        # Message type definitions
│   │   │   ├── storage.ts         # Storage type definitions
│   │   │   └── api.ts             # API type definitions
│   │   ├── utils/
│   │   │   ├── storage.ts         # Storage helper functions
│   │   │   ├── messaging.ts       # Message helper functions
│   │   │   └── auth.ts            # Auth helper functions
│   │   └── constants/
│   │       ├── messages.ts        # Message type constants
│   │       ├── storage-keys.ts    # Storage key constants
│   │       └── config.ts          # Configuration
│   └── lib/                       # Third-party configurations
│       └── api-client.ts          # API client setup
├── dist/                          # Build output (gitignored)
├── .env.example                    # (or local.settings.json.template for Azure Functions)
├── .gitignore
├── package.json
├── tsconfig.json
├── webpack.config.js              # Or vite.config.ts
├── README.md
└── CHANGES.md
```

## Background Service Worker (Manifest V3)

4. **Background scripts are now service workers** in Manifest V3. They don't have DOM access and must be event-driven.

5. **Service workers are ephemeral**: They start on events and stop when idle. Don't rely on global state persisting. Use chrome.storage for persistence.

6. **Use chrome.alarms for scheduled tasks**: Don't use setInterval or setTimeout for long-running tasks (service worker may stop).
```typescript
// ❌ BAD - setInterval doesn't work reliably in service workers
setInterval(() => {
  checkForUpdates();
}, 60000);

// ✅ GOOD - Use chrome.alarms
chrome.alarms.create('checkUpdates', { periodInMinutes: 1 });

chrome.alarms.onAlarm.addListener((alarm) => {
  if (alarm.name === 'checkUpdates') {
    checkForUpdates();
  }
});
```

7. **Register event listeners at top level**: Don't register listeners inside async functions or conditionally.
```typescript
// ❌ BAD - Conditional listener registration
async function init() {
  const user = await getUser();
  if (user) {
    chrome.runtime.onMessage.addListener(handleMessage); // Too late!
  }
}

// ✅ GOOD - Top-level registration
chrome.runtime.onMessage.addListener((message, sender, sendResponse) => {
  handleMessage(message, sender, sendResponse);
  return true; // Required for async responses
});

async function handleMessage(message, sender, sendResponse) {
  const user = await getUser();
  if (user) {
    // Handle message
  }
}
```

8. **Return true from message listeners for async responses**: If you use sendResponse asynchronously, return true from the listener.
```typescript
chrome.runtime.onMessage.addListener((message, sender, sendResponse) => {
  if (message.type === 'GET_USER') {
    fetchUser().then(user => {
      sendResponse({ user });
    });
    return true; // REQUIRED for async sendResponse
  }
});
```

## Content Scripts

9. **Content scripts run in isolated world**: They share the DOM with the page but have separate JavaScript context. They cannot access page variables directly.

10. **Content scripts have limited Chrome API access**: Only chrome.runtime, chrome.storage, chrome.i18n. For other APIs, message the background script.

11. **Inject content scripts declaratively when possible** (in manifest.json) rather than programmatically.
```json
// manifest.json
{
  "content_scripts": [
    {
      "matches": ["https://*.example.com/*"],
      "js": ["content/index.js"],
      "run_at": "document_idle"
    }
  ]
}
```

12. **Use run_at carefully**:
- `document_start`: Before any DOM is constructed (rare, for critical modifications)
- `document_end`: After DOM complete, before images/subframes load (common)
- `document_idle`: After page fully loaded (default, safest)

13. **Clean up content script modifications**: If you modify the DOM, provide a way to undo changes when extension is disabled.

14. **Communicate via window.postMessage to access page context** (if absolutely necessary):
```typescript
// Content script → Page context
window.postMessage({ type: 'FROM_EXTENSION', data: 'hello' }, '*');

// Page context → Content script
window.addEventListener('message', (event) => {
  if (event.source !== window) return;
  if (event.data.type === 'FROM_PAGE') {
    // Handle message
  }
});
```

⚠️ **Security Warning**: Be very careful with postMessage - validate all data received from the page.

## Message Passing

15. **Use typed messages**: Define message types and payloads in TypeScript.
```typescript
// shared/types/messages.ts
export enum MessageType {
  GET_USER = 'GET_USER',
  UPDATE_SETTINGS = 'UPDATE_SETTINGS',
  FETCH_DATA = 'FETCH_DATA',
}

export interface GetUserMessage {
  type: MessageType.GET_USER;
}

export interface GetUserResponse {
  user: User | null;
}

export type Message = GetUserMessage | UpdateSettingsMessage | FetchDataMessage;
```

16. **Create message helper functions** to abstract chrome.runtime API:
```typescript
// shared/utils/messaging.ts
export async function sendMessage<T>(message: Message): Promise<T> {
  return new Promise((resolve, reject) => {
    chrome.runtime.sendMessage(message, (response) => {
      if (chrome.runtime.lastError) {
        reject(chrome.runtime.lastError);
      } else {
        resolve(response);
      }
    });
  });
}

// Usage
const { user } = await sendMessage<GetUserResponse>({
  type: MessageType.GET_USER
});
```

17. **Handle message routing in background script**:
```typescript
// background/messaging.ts
chrome.runtime.onMessage.addListener((message: Message, sender, sendResponse) => {
  handleMessage(message, sender)
    .then(sendResponse)
    .catch(error => sendResponse({ error: error.message }));
  return true; // Async response
});

async function handleMessage(message: Message, sender: chrome.runtime.MessageSender) {
  switch (message.type) {
    case MessageType.GET_USER:
      return handleGetUser();
    case MessageType.UPDATE_SETTINGS:
      return handleUpdateSettings(message.settings);
    default:
      throw new Error(`Unknown message type: ${message.type}`);
  }
}
```

18. **Message from content script to background**:
```typescript
chrome.runtime.sendMessage({ type: 'SOME_TYPE' }, response => {});
```

19. **Message from background to specific tab**:
```typescript
chrome.tabs.sendMessage(tabId, { type: 'SOME_TYPE' }, response => {});
```

20. **Broadcast to all tabs**:
```typescript
chrome.tabs.query({}, (tabs) => {
  tabs.forEach(tab => {
    if (tab.id) {
      chrome.tabs.sendMessage(tab.id, { type: 'SOME_TYPE' });
    }
  });
});
```

## Storage

21. **Use chrome.storage, not localStorage**: chrome.storage works in all contexts (background, popup, content scripts) and syncs across devices with chrome.storage.sync.

22. **Choose the right storage area**:
- `chrome.storage.local`: Local to the machine (10 MB limit)
- `chrome.storage.sync`: Syncs across user's devices (100 KB limit, 8 KB per item)
- `chrome.storage.session`: Cleared when browser closes (10 MB limit, Manifest V3 only)

23. **Create storage helper functions**:
```typescript
// shared/utils/storage.ts
import { StorageKeys } from '@/shared/constants/storage-keys';

export const storage = {
  async get<T>(key: StorageKeys): Promise<T | null> {
    const result = await chrome.storage.local.get(key);
    return result[key] ?? null;
  },

  async set<T>(key: StorageKeys, value: T): Promise<void> {
    await chrome.storage.local.set({ [key]: value });
  },

  async remove(key: StorageKeys): Promise<void> {
    await chrome.storage.local.remove(key);
  },

  async clear(): Promise<void> {
    await chrome.storage.local.clear();
  },

  onChanged(callback: (changes: Record<string, chrome.storage.StorageChange>) => void) {
    chrome.storage.onChanged.addListener((changes, areaName) => {
      if (areaName === 'local') {
        callback(changes);
      }
    });
  },
};
```

24. **Use storage keys constants**:
```typescript
// shared/constants/storage-keys.ts
export enum StorageKeys {
  AUTH_TOKEN = 'auth_token',
  USER_DATA = 'user_data',
  SETTINGS = 'settings',
}
```

25. **Listen to storage changes** to keep UI in sync:
```typescript
chrome.storage.onChanged.addListener((changes, areaName) => {
  if (areaName === 'local' && changes.user_data) {
    const newUser = changes.user_data.newValue;
    updateUI(newUser);
  }
});
```

## Authentication & Security

26. **NEVER store auth tokens in chrome.storage.sync**: Tokens shouldn't sync across devices for security. Use chrome.storage.local or chrome.storage.session.

27. **Use chrome.identity API for OAuth** when possible (works with Google, GitHub, etc.):
```typescript
chrome.identity.getAuthToken({ interactive: true }, (token) => {
  if (chrome.runtime.lastError) {
    console.error(chrome.runtime.lastError);
  } else {
    // Use token for API calls
  }
});
```

28. **For custom authentication**: Store JWT tokens securely in chrome.storage.local, not in popup's localStorage.
```typescript
// ✅ GOOD - Background script handles auth
// background/auth.ts
export async function login(email: string, password: string) {
  const response = await fetch('https://api.example.com/auth/login', {
    method: 'POST',
    headers: { 'Content-Type': 'application/json' },
    body: JSON.stringify({ email, password }),
  });
  
  const { token, user } = await response.json();
  
  // Store in chrome.storage (accessible everywhere)
  await chrome.storage.local.set({
    [StorageKeys.AUTH_TOKEN]: token,
    [StorageKeys.USER_DATA]: user,
  });
}

// popup/Popup.tsx
async function handleLogin(email: string, password: string) {
  await sendMessage({ type: MessageType.LOGIN, email, password });
}
```

29. **Validate Content Security Policy (CSP)**: Manifest V3 has strict CSP. No inline scripts, no eval, no remote code execution.
```json
// manifest.json
{
  "content_security_policy": {
    "extension_pages": "script-src 'self'; object-src 'self'"
  }
}
```

30. **Use host_permissions sparingly**: Only request access to domains you actually need.
```json
{
  "host_permissions": [
    "https://api.example.com/*"
  ]
}
```

31. **Make API calls from background script**, not content scripts (better for security and CORS):
```typescript
// ❌ BAD - API call from content script (CORS issues)
// content/index.ts
fetch('https://api.example.com/data');

// ✅ GOOD - API call from background script
// background/api.ts
export async function fetchData() {
  const token = await storage.get(StorageKeys.AUTH_TOKEN);
  const response = await fetch('https://api.example.com/data', {
    headers: { Authorization: `Bearer ${token}` },
  });
  return response.json();
}

// content/index.ts
const data = await sendMessage({ type: MessageType.FETCH_DATA });
```

## Permissions

32. **Request minimum necessary permissions**: Users are wary of extensions with excessive permissions.

33. **Use optional permissions** for features users may not need:
```json
{
  "permissions": ["storage"],
  "optional_permissions": ["tabs", "downloads"]
}
```
```typescript
// Request optional permission when needed
async function enableFeature() {
  const granted = await chrome.permissions.request({
    permissions: ['tabs']
  });
  
  if (granted) {
    // Use tabs API
  }
}
```

34. **Common permissions**:
- `storage`: chrome.storage API (almost always needed)
- `tabs`: Access tab URLs and inject scripts (use sparingly, privacy concern)
- `activeTab`: Temporary access to current tab (better than tabs)
- `alarms`: Schedule tasks
- `notifications`: Show notifications
- `webRequest`: Intercept/modify network requests (powerful, use carefully)
- `cookies`: Access cookies
- `identity`: OAuth authentication

35. **Use activeTab instead of tabs when possible**: activeTab only gives access to current tab when user invokes the extension (less invasive).

## Popup

36. **Popup is ephemeral**: It closes when user clicks away. Don't store state in popup's memory - use chrome.storage.

37. **Popup has no background processes**: When closed, popup's JavaScript stops. Use background script for ongoing tasks.

38. **Keep popup lightweight**: Users expect popups to open instantly. Lazy load heavy components.

39. **Communicate with background script for data**:
```typescript
// popup/Popup.tsx
function Popup() {
  const [user, setUser] = useState<User | null>(null);
  
  useEffect(() => {
    // Get data from background/storage
    sendMessage<GetUserResponse>({ type: MessageType.GET_USER })
      .then(response => setUser(response.user));
  }, []);
  
  return <div>{user?.name}</div>;
}
```

40. **Set popup dimensions in manifest**:
```json
{
  "action": {
    "default_popup": "popup/index.html",
    "default_icon": {
      "16": "icons/icon16.png",
      "48": "icons/icon48.png",
      "128": "icons/icon128.png"
    }
  }
}
```

## Options Page

41. **Use options page for settings**: Separate page for extension configuration (chrome://extensions → Details → Extension options).
```json
{
  "options_page": "options/index.html",
  "options_ui": {
    "page": "options/index.html",
    "open_in_tab": true
  }
}
```

42. **Save options to chrome.storage**: So they're accessible everywhere.
```typescript
// options/Options.tsx
function Options() {
  const [settings, setSettings] = useState<Settings | null>(null);
  
  useEffect(() => {
    storage.get<Settings>(StorageKeys.SETTINGS).then(setSettings);
  }, []);
  
  async function handleSave(newSettings: Settings) {
    await storage.set(StorageKeys.SETTINGS, newSettings);
    // Notify other parts of extension
    await sendMessage({ type: MessageType.SETTINGS_UPDATED });
  }
  
  return <SettingsForm settings={settings} onSave={handleSave} />;
}
```

## Building & Development

43. **Use proper build tools**: Webpack, Vite, or Parcel configured for Chrome extensions.

44. **Separate builds for different parts**:
- Background script → single JS file
- Content script → single JS file (or multiple if needed)
- Popup → HTML + JS + CSS
- Options page → HTML + JS + CSS

45. **Hot reload for development**: Use tools like webpack-ext-reloader or crx-hotreload for faster development.

46. **Load unpacked extension for testing**: chrome://extensions → Enable Developer mode → Load unpacked

47. **Check for errors in multiple places**:
- Background script: chrome://extensions → inspect service worker
- Content script: Regular DevTools on the page
- Popup: Right-click popup → Inspect

## React-Specific Tips

48. **Use React for popup and options page**, not for content scripts (content scripts should be lightweight).

49. **Handle popup re-renders**: Popup unmounts when closed, so use chrome.storage for persistence.
```typescript
// Custom hook for persisted state
function usePersistedState<T>(storageKey: StorageKeys, defaultValue: T) {
  const [value, setValue] = useState<T>(defaultValue);
  const [loaded, setLoaded] = useState(false);
  
  useEffect(() => {
    storage.get<T>(storageKey).then(stored => {
      if (stored !== null) setValue(stored);
      setLoaded(true);
    });
  }, [storageKey]);
  
  const setPersistedValue = async (newValue: T) => {
    setValue(newValue);
    await storage.set(storageKey, newValue);
  };
  
  return [value, setPersistedValue, loaded] as const;
}
```

50. **Use Tailwind or styled-components** for styling (not separate CSS files that might conflict with page styles in content scripts).

## Testing

51. **Test in multiple scenarios**:
- Fresh install
- Update from previous version
- After browser restart
- With slow/offline network
- In incognito mode (if allowed)
- On different websites

52. **Test message passing**: Ensure background ↔ popup ↔ content script communication works.

53. **Test permissions**: What happens when permissions are denied?

54. **Unit test business logic**: Extract business logic from Chrome APIs so it's testable.
```typescript
// ✅ Testable
export function processUserData(user: User): ProcessedUser {
  // Pure function, easy to test
}

// Extension code calls this
async function handleGetUser() {
  const user = await storage.get(StorageKeys.USER_DATA);
  return processUserData(user);
}
```

## Publishing & Distribution

55. **Prepare for Chrome Web Store**:
- Icons: 16x16, 48x48, 128x128
- Screenshots: 1280x800 or 640x400
- Promotional images: 440x280
- Privacy policy (required if collecting data)
- Detailed description

56. **Version your extension properly**: Use semantic versioning (1.0.0).

57. **Test thoroughly before publishing**: Can't easily roll back once users have updated.

58. **Monitor reviews and bug reports**: Respond to user feedback on Chrome Web Store.

## Common Pitfalls

59. **Don't assume background script is always running**: It's a service worker, it stops when idle.

60. **Don't use synchronous chrome.storage**: Always use async methods (.get(), .set()).

61. **Don't forget to handle chrome.runtime.lastError**: Check after every Chrome API call.

62. **Don't store large data in chrome.storage.sync**: 100 KB limit total, 8 KB per item.

63. **Don't use alert(), confirm(), prompt() in background script**: They don't work in service workers.

64. **Don't access DOM in background script**: No DOM access in service workers.

65. **Don't rely on window or document in background**: Not available in service workers.

## Debugging Tips

66. **Log message flow**: Log in sender and receiver to debug message passing.
```typescript
console.log('[Content] Sending message:', message);
chrome.runtime.sendMessage(message, response => {
  console.log('[Content] Received response:', response);
});

chrome.runtime.onMessage.addListener((message, sender, sendResponse) => {
  console.log('[Background] Received message:', message, 'from:', sender);
  // ...
  console.log('[Background] Sending response:', response);
  sendResponse(response);
});
```

67. **Use chrome.runtime.lastError consistently**:
```typescript
function checkError() {
  if (chrome.runtime.lastError) {
    console.error('Chrome error:', chrome.runtime.lastError);
    return true;
  }
  return false;
}

chrome.storage.local.get('key', (result) => {
  if (checkError()) return;
  // Use result
});
```

68. **Inspect service worker**: chrome://extensions → Find your extension → "Inspect views: service worker"

69. **Check extension errors**: chrome://extensions → Click "Errors" button for your extension

---

## Quick Reference - Chrome Extensions

### Manifest V3 Essentials
- Service worker background scripts (not persistent)
- Declarative content scripts when possible
- Strict CSP (no inline scripts, no eval)
- Minimum necessary permissions

### Project Structure
```
src/
  background/     # Service worker
  content/        # Content scripts
  popup/          # Extension popup
  options/        # Settings page
  shared/         # Types, utils, constants
```

### Message Passing
- Typed messages with TypeScript enums
- Helper functions for sendMessage
- Return true for async sendResponse
- Handle errors with chrome.runtime.lastError

### Storage
- Use chrome.storage, not localStorage
- chrome.storage.local for tokens (don't sync)
- chrome.storage.sync for user preferences
- Helper functions for type-safe access

### Security
- API calls from background (not content scripts)
- Validate all messages
- Minimal permissions
- No inline scripts (CSP)
- Don't store tokens in sync storage

### Common Patterns
- usePersistedState hook for popup state
- Message routing in background
- Storage change listeners
- Optional permissions when appropriate

### Testing
- Test fresh install, updates, restarts
- Test offline, slow network
- Test message passing
- Test in incognito
- Unit test business logic

### Debugging
- Inspect service worker for background
- Regular DevTools for content scripts
- Right-click popup → Inspect
- Check chrome://extensions for errors
- Log message flow