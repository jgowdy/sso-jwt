# sso-jwt-napi

Node.js native addon for sso-jwt, built with [napi-rs](https://napi.rs).

All the security benefits of the Rust implementation (Secure Enclave / TPM caching, proactive refresh, memory zeroing) are available to Node.js consumers.

## Installation

```bash
npm install sso-jwt
```

Or build from source:

```bash
npm install
npm run build
```

## Usage

```javascript
const { getJwt } = require('sso-jwt');

// Minimal -- uses defaults from config file
const jwt = await getJwt();

// With options
const jwt = await getJwt({
  server: 'myserver',
  env: 'dev',
  cacheName: 'my-app',
  riskLevel: 3,
});
```

### TypeScript

Type definitions are included:

```typescript
import { getJwt, JwtOptions } from 'sso-jwt';

const options: JwtOptions = {
  server: 'myserver',
  env: 'prod',
  cacheName: 'default',
};

const jwt: string = await getJwt(options);
```

## API

### `getJwt(options?): Promise<string>`

Returns an SSO JWT. Uses cached tokens when available, proactively refreshes tokens approaching expiration, and falls back to browser-based OAuth Device Code authentication when necessary.

#### Options

| Field | Type | Default | Description |
|---|---|---|---|
| `server` | `string` | `"default"` | Server profile name from config |
| `env` | `string` | (default env) | Environment within the server profile |
| `oauthUrl` | `string` | (from config) | Override OAuth service URL |
| `cacheName` | `string` | `"default"` | Cache name for the encrypted token |
| `riskLevel` | `number` | `2` | Risk level 1-3 (1=low/24h, 2=medium/12h, 3=high/1h) |
| `biometric` | `boolean` | `false` | Require Touch ID / Windows Hello for each use |
| `noOpen` | `boolean` | `false` | Don't auto-open browser |

## How It Works

The napi-rs binding calls the same Rust core library (`sso-jwt-lib`) used by the CLI. The blocking Rust code (HTTP requests, Secure Enclave/TPM operations) runs on a separate thread via `tokio::task::spawn_blocking`, so the Node.js event loop is never blocked.

```
Node.js event loop
  |
  +- getJwt()  ->  Promise
  |     |
  |     +- tokio thread pool
  |           |
  |           +- Check encrypted cache (Secure Enclave / TPM decrypt)
  |           +- Heartbeat refresh if approaching expiration
  |           +- OAuth Device Code flow if no valid cache
  |
  +- resolved Promise  <-  JWT string
```

## Supported Platforms

| Platform | Architecture | Native File |
|---|---|---|
| macOS | x86_64 | `sso-jwt.darwin-x64.node` |
| macOS | arm64 (Apple Silicon) | `sso-jwt.darwin-arm64.node` |
| Linux | x86_64 | `sso-jwt.linux-x64-gnu.node` |
| Linux | arm64 | `sso-jwt.linux-arm64-gnu.node` |
| Windows | x86_64 | `sso-jwt.win32-x64-msvc.node` |

## Building

Requires Rust toolchain and Node.js >= 18.

```bash
# Debug build
npm run build:debug

# Release build
npm run build

# Publish to registry
npm publish
```

## License

MIT
