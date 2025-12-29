# Archero Protocol Analysis

Protocol documentation based on Frida discovery captures.

## Keys

| Purpose | Value |
|---------|-------|
| RC4/DES Key | `4ptjerlkgjlk34jylkej4rgklj4klyj` |
| SHA256 API Key | `A63B6DBE18D84CA29887198B4ACBDEE9` |

## Servers

| Server | URL |
|--------|-----|
| Game API | `https://game-archero-v1.archerosvc.com` |
| Config | `https://config-archero.archerosvc.com` |
| Hot Update | `https://hotupdate-archero.habby.com` |

## HTTP Request Format

### Headers

```
HabbyTime: 1766952861          # Unix timestamp
HabbyCheck: <SHA256_HASH>      # Request signature (see below)
HabbyVersion: 210              # Client version
HabbyType: <ENDPOINT_ID>       # Endpoint identifier
```

### Request Signing (HabbyCheck)

```typescript
const apiKey = "A63B6DBE18D84CA29887198B4ACBDEE9";
const timestamp = Math.floor(Date.now() / 1000);
const body = requestBodyBytes;

const input = Buffer.concat([
  Buffer.from(apiKey),              // 32 bytes
  Buffer.from(timestamp.toString()), // timestamp as string
  body                               // request body
]);

const signature = crypto.createHash('sha256')
  .update(input)
  .digest('hex')
  .toUpperCase();
```

### Response Format

- Header: `Habby: archero_zip` (indicates encrypted)
- Body: DES-encrypted Base64 JSON

## Encryption Methods

### NetEncrypt::Encrypt_UTF8

Encrypts strings to Base64:

```typescript
NetEncrypt.Encrypt_UTF8("data", key)   => "7xO2FPqnGWQRyD7cuv4N2g=="
NetEncrypt.Encrypt_UTF8("excel", key)  => "HtQO30qUbxTUzvYx2kXRYQ=="
NetEncrypt.Encrypt_UTF8("config", key) => "VxPovHKkuIXNOEv+h0pVZA=="
```

### NetEncrypt::DesDecrypt

Decrypts server responses:

```typescript
// Server sends: "HbSKz32QdUhY5EGUTWAvKGSYnIMPF3se..."
// Client decrypts to Base64 JSON: "WwogICAgewogICAgICAgICJUYWci..."
// Which decodes to: [{ "Tag": 1, "MinVer": 114, ... }]
```

### RC4Encrypter::Encrypt

Decrypts Unity asset bundles (`.bytes` files):

```typescript
// Input: encrypted asset bytes
// Output: "UnityFS\0..." (decrypted Unity asset)
```

## Endpoint IDs (HabbyType)

| ID | Purpose |
|----|---------|
| 8 | Device/platform info |
| 255 | Initial sync |
| 171 | TBD |
| 218 | TBD |
| 228 | TBD |
| 260 | TBD |

## Config Files

Fetched from `https://config-archero.archerosvc.com/data/config/`:

- `game_config.json` - Main game settings
- `dailySeasonData.json` - Season rewards
- `pvp_season.json` - PVP seasons
- `camp_season_time.json` - Camp battle timing
- `ship_battle_season_time.json` - Ship battle timing
- `game_activity_*.json` - Activity configs

## Sandbox Implementation

### Verify Request

```typescript
function verifyRequest(headers: Headers, body: Buffer): boolean {
  const apiKey = "A63B6DBE18D84CA29887198B4ACBDEE9";
  const timestamp = headers.get("HabbyTime");
  const check = headers.get("HabbyCheck");
  
  const input = Buffer.concat([
    Buffer.from(apiKey),
    Buffer.from(timestamp),
    body
  ]);
  
  const expected = crypto.createHash('sha256')
    .update(input)
    .digest('hex')
    .toUpperCase();
    
  return check === expected;
}
```

### Encrypt Response

```typescript
import * as crypto from 'crypto';

const KEY = "4ptjerlkgjlk34jylkej4rgklj4klyj";

function desEncrypt(plaintext: string): string {
  const keyBuffer = Buffer.from(KEY.slice(0, 8));
  const iv = Buffer.alloc(8, 0);
  const cipher = crypto.createCipheriv('des-cbc', keyBuffer, iv);
  let encrypted = cipher.update(plaintext, 'utf8', 'base64');
  encrypted += cipher.final('base64');
  return encrypted;
}

function sendResponse(res: Response, data: object): void {
  const json = JSON.stringify(data);
  const base64Json = Buffer.from(json).toString('base64');
  const encrypted = desEncrypt(base64Json);
  
  res.setHeader("Habby", "archero_zip");
  res.send(encrypted);
}
```