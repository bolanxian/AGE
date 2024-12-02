
import { argon2id } from 'hash-wasm'
import { createStruct, pack, from, write, read } from './zip.js'
const { log, error } = console, { now } = Date

export const AgeHeader = createStruct([
  ['magic', 'u32'],
  ['m', 'u32'],
  ['t', 'u16'],
  ['p', 'u8'],
  ['salt_len', 'u8']
], {
  magic: 0x20454741
})

export const kdf = async (password, salt, m, t, p) => {
  const start = now()
  log("Argon2 启动");
  const ret = await argon2id({
    password, salt,
    parallelism: p,
    iterations: t,
    memorySize: m,
    hashLength: 32,
    outputType: 'binary'
  })
  const dur = now() - start
  log(`Argon2 完成: ${dur / 1000}s`);
  return ret
}

export const encrypt = async (msg, password, salt, m, t, p) => {
  const derived = await kdf(password, salt, m, t, p)
  return [
    pack(AgeHeader, { m, t, p, salt_len: salt.byteLength }),
    salt,
    new Uint8Array(await crypto.subtle.encrypt({
      name: 'AES-GCM', iv: derived.subarray(16, 28)
    }, await crypto.subtle.importKey(
      'raw', derived.subarray(0, 16),
      'AES-GCM', false, ['encrypt']
    ), msg))
  ]
}

export const decrypt = async (data, password) => {
  const header = from(AgeHeader, data.buffer, data.byteOffset)
  const offset0 = AgeHeader.byteLength
  const offset1 = offset0 + header.salt_len
  const salt = data.subarray(offset0, offset1)
  const derived = await kdf(password, salt, header.m, header.t, header.p)
  return {
    header,
    data: new Uint8Array(await crypto.subtle.decrypt({
      name: 'AES-GCM', iv: derived.subarray(16, 28),
    }, await crypto.subtle.importKey(
      'raw', derived.subarray(0, 16),
      'AES-GCM', false, ['decrypt']
    ), data.subarray(offset1)))
  }
}

if (import.meta.main) {
  const [arg0, filename, password] = Deno.args
  let input, output
  try {
    if (arg0 == 'enc') {
      const { mtime } = await Deno.stat(filename)
      const data = await Deno.readFile(filename)
      output = await Deno.open(`${filename}.zip`, { create: true, write: true })
      const salt = crypto.getRandomValues(new Uint8Array(16))
      await write(
        output, "!encrypted.txt", "本文件已加密", mtime,
        await encrypt(data, password, salt, 512 * 1024, 5, 4)
      )
    } else if (arg0 == 'dec') {
      input = await Deno.open(`${filename}.zip`, { read: true })
      const data = await read(input)
      const { data: msg } = await decrypt(data, password)
      await Deno.writeFile(filename, msg)
    } else {
      error(`error: unknown command: ${arg0}`)
    }
  } finally {
    input?.close()
    output?.close()
  }
}