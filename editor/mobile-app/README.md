# WPSecScan mobile companion app

Read-only iOS / Android client that talks to your local WPSecScan API
server (or a remote one over a tailnet / VPN).

**Status:** scaffold / blueprint. The reference implementation below is
Expo + React Native; you can also build native (Swift / Kotlin) against
the same REST API.

## What it does

- List sites configured in `wpsecscan sites list`
- Show last scan risk score + critical/high/medium/low counts
- Drill into individual findings with evidence + remediation
- Push notifications when a scheduled scan turns up a new critical
- Star findings for follow-up
- No write actions — you cannot trigger remediation from the phone

## REST API endpoints used

| Endpoint | Purpose |
|----------|---------|
| `GET /sites` | List configured sites |
| `GET /sites/<urlhash>/report` | Latest report for one site |
| `GET /reports/<id>/finding/<n>` | Single finding detail |
| `POST /push-token` | Register the device for push notifications |

The endpoints live in `wpsecscan/api_server.py` — currently expose
read-only via `--read-only` flag.

## Reference Expo scaffold

`expo init wpsecscan-mobile` then:

```bash
npx expo install react-native expo-notifications expo-secure-store \
                 @react-navigation/native @react-navigation/native-stack
```

`App.tsx`:

```tsx
import React from "react";
import { NavigationContainer } from "@react-navigation/native";
import { createNativeStackNavigator } from "@react-navigation/native-stack";
import { SitesScreen } from "./screens/Sites";
import { ReportScreen } from "./screens/Report";

const Stack = createNativeStackNavigator();
export default () => (
  <NavigationContainer>
    <Stack.Navigator>
      <Stack.Screen name="Sites" component={SitesScreen} />
      <Stack.Screen name="Report" component={ReportScreen} />
    </Stack.Navigator>
  </NavigationContainer>
);
```

Set the API base URL in `app.json` (`extra.apiUrl`) — defaults to
`http://localhost:8765` for emulator use.

## Privacy

- No data leaves your devices — direct phone ↔ your WPSecScan server
- Use Tailscale / WireGuard if scanning from outside your LAN
- The mobile app does NOT store creds — it pulls the read-only report cache only

## Build

```
eas build --platform ios       # TestFlight
eas build --platform android   # internal APK
```

Reference repo coming once the API surface stabilises in WPSecScan 2.0.
