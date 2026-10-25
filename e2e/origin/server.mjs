import { createHash } from 'node:crypto'
import { readFileSync } from 'node:fs'
import { createServer as createHttpServer } from 'node:http'
import { createServer as createHttpsServer } from 'node:https'
import { brotliCompressSync, gzipSync } from 'node:zlib'

const NAME = process.env.ORIGIN_NAME ?? 'a'
const PORT = Number(process.env.PORT ?? 8080)
const TLS_PORT = Number(process.env.TLS_PORT ?? 0)
const requests = new Map()
let sequence = 0

const large = Buffer.alloc(2 * 1024 * 1024, 'x')
const repetitive = Buffer.from('The quick brown fox jumps over the lazy dog.\n'.repeat(8_000))

function count(path) {
  const next = (requests.get(path) ?? 0) + 1
  requests.set(path, next)
  return next
}

function headersFor(path, extra = {}) {
  return {
    'content-type': 'application/json',
    'x-origin-name': NAME,
    'x-origin-path': path,
    'x-origin-requests': String(count(path)),
    'cache-control': 'no-store',
    ...extra,
  }
}

function bodyFor(path, method, body) {
  if (path === '/a') return { origin: NAME, route: 'a' }
  if (path === '/b') return { origin: NAME, route: 'b' }
  if (path === '/cache') {
    return {
      origin: NAME,
      cachedAt: new Date().toISOString(),
      sequence: sequence++,
      path,
    }
  }
  if (path === '/headers') {
    return {
      origin: NAME,
      method,
      path,
      headers: Object.fromEntries(
        Object.entries(arguments[3] ?? {}).map(([key, value]) => [
          key,
          Array.isArray(value) ? value.join(',') : value,
        ]),
      ),
    }
  }
  if (path === '/echo') {
    const value = Buffer.isBuffer(body) ? body : Buffer.from(body ?? '')
    return {
      origin: NAME,
      bytes: value.length,
      sha256: createHash('sha256').update(value).digest('hex'),
    }
  }
  return {
    origin: NAME,
    method,
    path,
    sequence: sequence++,
    bodyBytes: Buffer.isBuffer(body) ? body.length : 0,
  }
}

function sendJson(res, status, value, extra) {
  const body = Buffer.from(JSON.stringify(value))
  res.writeHead(status, {
    ...headersFor(new URL(res.req.url, 'http://origin').pathname, extra),
    'content-length': body.length,
  })
  res.end(body)
}

async function handler(req, res) {
  const url = new URL(req.url, `http://${req.headers.host ?? 'origin'}`)
  const path = url.pathname
  if (req.method === 'GET' && path === '/ws') {
    return websocket(req, res)
  }
  if (req.method === 'GET' && path === '/big') {
    res.writeHead(200, headersFor(path, { 'content-type': 'application/octet-stream', 'content-length': large.length }))
    return res.end(large)
  }
  if (req.method === 'GET' && path === '/gzip') {
    const body = gzipSync(repetitive)
    res.writeHead(200, headersFor(path, { 'content-type': 'text/plain', 'content-encoding': 'gzip', 'content-length': body.length }))
    return res.end(body)
  }
  if (req.method === 'GET' && path === '/br') {
    const body = brotliCompressSync(repetitive)
    res.writeHead(200, headersFor(path, { 'content-type': 'text/plain', 'content-encoding': 'br', 'content-length': body.length }))
    return res.end(body)
  }
  if (path === '/slow') {
    await new Promise((resolve) => setTimeout(resolve, 20_000))
    return sendJson(res, 200, { origin: NAME, slow: true })
  }
  if (path === '/status') {
    return sendJson(res, Number(url.searchParams.get('code') ?? 500), bodyFor('/status', req.method, Buffer.alloc(0)))
  }
  if (req.method === 'GET' && path === '/count') {
    return sendJson(res, 200, { origin: NAME, counts: Object.fromEntries(requests) })
  }
  const chunks = []
  for await (const chunk of req) chunks.push(chunk)
  const body = Buffer.concat(chunks)
  const value = bodyFor(path, req.method, body, req.headers)
  sendJson(res, 200, value)
}

function websocket(req, res) {
  const key = req.headers['sec-websocket-key']
  if (!key) {
    res.writeHead(400)
    return res.end('missing websocket key')
  }
  const accept = createHash('sha1')
    .update(`${key}258EAFA5-E914-47DA-95CA-C5AB0DC85B11`)
    .digest('base64')
  res.writeHead(101, {
    Upgrade: 'websocket',
    Connection: 'Upgrade',
    'Sec-WebSocket-Accept': accept,
  })

  let buffer = Buffer.alloc(0)
  req.on('data', (chunk) => {
    buffer = Buffer.concat([buffer, chunk])
    while (buffer.length >= 2) {
      const second = buffer[1]
      const masked = (second & 0x80) !== 0
      let length = second & 0x7f
      let offset = 2
      if (length === 126) {
        if (buffer.length < 4) return
        length = buffer.readUInt16BE(2)
        offset = 4
      } else if (length === 127) {
        if (buffer.length < 10) return
        length = Number(buffer.readBigUInt64BE(2))
        offset = 10
      }
      const maskOffset = offset
      if (masked) offset += 4
      if (buffer.length < offset + length) return
      const mask = masked ? buffer.subarray(maskOffset, maskOffset + 4) : null
      const payload = Buffer.from(buffer.subarray(offset, offset + length))
      if (mask) for (let i = 0; i < payload.length; i++) payload[i] ^= mask[i % 4]
      const opcode = buffer[0] & 0x0f
      buffer = buffer.subarray(offset + length)
      if (opcode === 0x8) return res.end()
      if (opcode === 0x9) return res.write(frame(0xA, payload))
      if (opcode === 0x1 || opcode === 0x2) res.write(frame(opcode, Buffer.concat([Buffer.from('echo:'), payload])))
    }
  })
  req.on('end', () => res.end())
}

function frame(opcode, payload) {
  const length = payload.length
  let header
  if (length < 126) {
    header = Buffer.from([0x80 | opcode, length])
  } else if (length < 65536) {
    header = Buffer.from([0x80 | opcode, 126, 0, 0])
    header.writeUInt16BE(length, 2)
  } else {
    header = Buffer.alloc(10)
    header[0] = 0x80 | opcode
    header[1] = 127
    header.writeBigUInt64BE(BigInt(length), 2)
  }
  return Buffer.concat([header, payload])
}

const http = createHttpServer(handler)
http.listen(PORT, '0.0.0.0', () => console.log(`origin ${NAME} http ${PORT}`))

if (TLS_PORT) {
  const cert = readFileSync(process.env.TLS_CERT)
  const key = readFileSync(process.env.TLS_KEY)
  const https = createHttpsServer({ cert, key }, handler)
  https.listen(TLS_PORT, '0.0.0.0', () => console.log(`origin ${NAME} https ${TLS_PORT}`))
}
