
import { Buffer } from 'node:buffer'
import { assertEquals as eq } from 'https://deno.land/std/assert/mod.ts'
import { ready, createAesGcmEncryptStream, createAesGcmDecryptStream } from './aes-gcm.js'
import { toReadable, toBuffer } from './bind.js'

const { subtle } = crypto
const { from } = ReadableStream
const concatBuffer = (data) => toBuffer(from(data))
const hex = (data) => data != null ? Buffer.from(data).toString('hex').replace(/.{128}/g, '$&\n') : ''

const encryptWeb = async (msg, key, iv) => {
  const data = new Uint8Array(await subtle.encrypt({
    name: 'AES-GCM', iv
  }, await subtle.importKey(
    'raw', key, 'AES-GCM', false, ['encrypt']
  ), msg))
  return data
}

await ready
for (const keyLength of [16, 32, 16, 32]) {
  Deno.test(`AES-${keyLength * 8}-GCM`, async (t) => {
    const key = new Uint8Array(keyLength)
    const iv = new Uint8Array(12)
    const data = [
      new Uint8Array(65536),
      new Uint8Array(65536),
      new Uint8Array(65536),
      new Uint8Array(255),
      new Uint8Array(255),
      new Uint8Array(255),
    ]
    crypto.getRandomValues(key)
    crypto.getRandomValues(iv)
    for (const $ of data) {
      crypto.getRandomValues($)
    }
    const concatedData = new Uint8Array(await concatBuffer(data))
    const dataHex = hex(concatedData)
    const encWeb = await encryptWeb(
      concatedData, key, iv
    )
    const encWebHex = hex(encWeb)
    let enc
    await t.step('encrypt-stream', async () => {
      enc = await toBuffer(from(data).pipeThrough(
        createAesGcmEncryptStream(key, iv)
      ))
      eq(hex(enc), encWebHex)
    })
    await t.step('encrypt', async () => {
      const enc2 = await toBuffer(from([concatedData]).pipeThrough(
        createAesGcmEncryptStream(key, iv)
      ))
      eq(hex(enc2), encWebHex)
    })
    await t.step('decrypt-stream', async () => {
      const dec = await toBuffer(toReadable(enc).pipeThrough(
        createAesGcmDecryptStream(key, iv)
      ))
      eq(hex(dec), dataHex)
    })
    await t.step('decrypt', async () => {
      const dec2 = await toBuffer(from([new Uint8Array(enc)]).pipeThrough(
        createAesGcmDecryptStream(key, iv)
      ))
      eq(hex(dec2), dataHex)
    })
  })
}