
import { argon2id } from 'hash-wasm'
import { LocalFileHeader, pack, from, write, read } from './zip.js'
const { log } = console, { now } = Date

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
    pack(LocalFileHeader, {
      crc32: m, _3: t, _2: p,
      name_len: salt.byteLength, comp_size: 0, size: 0
    }),
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
  const header = from(LocalFileHeader, data.buffer, data.byteOffset)
  let offset = LocalFileHeader.byteLength
  const salt = data.subarray(offset, offset + header.name_len)
  const derived = await kdf(password, salt, header.crc32, header._3, header._2)
  return new Uint8Array(await crypto.subtle.decrypt({
    name: 'AES-GCM', iv: derived.subarray(16, 28),
  }, await crypto.subtle.importKey(
    'raw', derived.subarray(0, 16),
    'AES-GCM', false, ['decrypt']
  ), data.subarray(offset + header.name_len)))
}

if (import.meta.main) {
  const [arg0, filename, password] = Deno.args
  let input, output
  try {
    if (arg0 == 'enc') {
      const data = await Deno.readFile(filename)
      output = await Deno.open(`${filename}.zip`, { create: true, write: true })
      const salt = crypto.getRandomValues(new Uint8Array(16))
      await write(
        output, "!encrypted.txt", "本文件已加密",
        await encrypt(data, password, salt, 512 * 1024, 5, 4)
      )
    } else if (arg0 == 'dec') {
      input = await Deno.open(`${filename}.zip`, { read: true })
      const data = await read(input)
      await Deno.writeFile(filename, await decrypt(data, password))
    } else {
      console.error(`error: unknown command: ${arg0}`)
    }
  } finally {
    input?.close()
    output?.close()
  }
}