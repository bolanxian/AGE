
const modulePromise = WebAssembly.compileStreaming(fetch(import.meta.resolve('@/deps/ghash.wasm')))
const { instantiate } = WebAssembly, U8 = Uint8Array
export const create = async () => {
  const instance = await instantiate(await modulePromise, {
    env: {
      read(fd, ptr, len) {
        if (context[fd] == null) { return 0 }
        ptr >>>= 0
        len >>>= 0
        let data
        if (context[fd].length > len) {
          data = context[fd].subarray(0, len)
          context[fd] = context[fd].subarray(len)
        } else {
          data = context[fd]
          context[fd] = null
        }
        new U8(memory.buffer, ptr, len).set(data)
        return data.length
      },
      write(fd, ptr, len) {
        ptr >>>= 0
        len >>>= 0
        context[fd] = new U8(new U8(memory.buffer, ptr, len))
        return len
      }
    }
  })
  const { memory, Ghash_init, Ghash_update, Ghash_pad, Ghash_final } = instance.exports
  let context = { __proto__: null }
  return {
    init(key) {
      context[1] = key
      Ghash_init()
    },
    update(data) {
      context[2] = data
      Ghash_update()
    },
    pad: Ghash_pad,
    final() {
      Ghash_final()
      const ret = context[3]
      context[3] = null
      return ret
    }
  }
}

Deno.test('ghash', async () => {
  const { Buffer } = await import('node:buffer')
  const { assertEquals: eq } = await import('https://deno.land/std/assert/mod.ts')
  const hex = (data) => data != null ? Buffer.from(data).toString('hex') : ''

  const result = '889295fa746e8b174bf4ec80a65dea41'

  const hash = await create()
  const key = new Uint8Array(16).fill(0x42)
  const data = new Uint8Array(256).fill(0x69)
  hash.init(key)
  hash.update(data)
  eq(hex(hash.final()), result)

  hash.init(key)
  hash.update(data.subarray(0, 100))
  hash.update(data.subarray(100))
  eq(hex(hash.final()), result)
})