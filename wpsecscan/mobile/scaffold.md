# Mobile scaffolds — Round-64 #98

Two thin clients that talk to the WPSecScan daemon's REST API. Neither
is bundled in the .exe distribution; both are reference scaffolds for
contributors who want to build a mobile companion.

## React Native (Expo)

```bash
npx create-expo-app wpsecscan-mobile
cd wpsecscan-mobile
npm i axios react-native-async-storage zustand
```

Minimum viable client:

```tsx
// src/api.ts
import axios from "axios";

export const api = axios.create({
  baseURL: process.env.EXPO_PUBLIC_WPSECSCAN_URL || "http://localhost:8080",
  headers: { Authorization: `Bearer ${process.env.EXPO_PUBLIC_WPSECSCAN_TOKEN}` },
});

export const startScan = (url: string) => api.post("/scans", { target: url });
export const getReport = (id: string) => api.get(`/scans/${id}`);
export const listSites = () => api.get("/sites");
```

```tsx
// src/screens/Scan.tsx
import { useState } from "react";
import { View, TextInput, Button, Text } from "react-native";
import { startScan } from "../api";

export default function Scan() {
  const [url, setUrl] = useState("");
  const [status, setStatus] = useState("");
  return (
    <View style={{ padding: 16 }}>
      <TextInput value={url} onChangeText={setUrl} placeholder="https://example.com" />
      <Button title="Scan" onPress={async () => {
        const r = await startScan(url);
        setStatus(`Started scan ${r.data.scan_id}`);
      }} />
      <Text>{status}</Text>
    </View>
  );
}
```

## Capacitor (web-app -> native shell)

```bash
npm i -g @capacitor/cli
npx cap init "WPSecScan" "com.wpsecscan.mobile"
npx cap add android
npx cap add ios
```

The web build is just a Vite/Next.js SPA that calls the same daemon REST
API as the React Native client. Capacitor wraps it as an APK/IPA.

## Endpoints expected on the daemon

These need to exist for the mobile clients. See
`openapi/wpsecscan-api.yaml` for full schema:

| Method | Path | Purpose |
|--------|------|---------|
| POST | /scans | Start a scan; body `{target}` |
| GET | /scans/:id | Fetch report |
| GET | /sites | List configured sites |
| POST | /sites | Add a site |
| GET | /findings?severity=critical | Filter findings |

## Auth

JWT bearer issued by `wpsecscan daemon login` CLI. The daemon enforces
RBAC via `wpsecscan/auth/rbac.py`.

## Out of scope

- Push notifications (different per platform; OneSignal/Expo Push
  recommended)
- Offline scan mode (mobile devices shouldn't scan directly; use the
  daemon)
- App Store submission process (project per contributor)
