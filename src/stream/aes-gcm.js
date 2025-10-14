
import { $typedArray, getLength, $transformController } from './bind.js'
import { compileStreaming, instantiate, getMemoryBuffer, getInstanceExports } from './bind.js'
const { set, slice, subarray } = $typedArray
const { enqueue } = $transformController
const U8 = Uint8Array, Transform = TransformStream, Exception = DOMException

let modulePromise
export const init = () => {
  modulePromise ??= compileStreaming(fetch(import.meta.resolve('@/deps/aes-gcm.wasm')))
  return modulePromise
}
const create = (init_code, key, iv, aad) => {
  const importObject = {
    env: {
      read(fd, ptr, len) {
        if (context[fd] == null) { return 0 }
        ptr >>>= 0
        len >>>= 0
        let data, length = getLength(context[fd])
        if (length > len) {
          data = subarray(context[fd], 0, len)
          length = len
          context[fd] = subarray(context[fd], len)
        } else {
          data = context[fd]
          context[fd] = null
        }
        set(new U8(buffer, ptr, len), data)
        return length
      },
      write(fd, ptr, len) {
        ptr >>>= 0
        len >>>= 0
        context[fd] = slice(new U8(buffer, ptr, len))
        return len
      }
    }
  }
  let memory, buffer, Aes_init, Aes_update, Aes_final
  let context = { __proto__: null }
  switch (getLength(key)) {
    case 16: case 32: break
    default: throw new Exception('Invalid key length', 'DataError')
  }
  switch (getLength(iv)) {
    case 12: break
    default: throw new Exception('Invalid iv length', 'DataError')
  }
  return new Transform({
    async start() {
      const instance = await instantiate(await init(), importObject)
      !({ memory, Aes_init, Aes_update, Aes_final } = getInstanceExports(instance))
      buffer = getMemoryBuffer(memory)
      context[1] = key
      context[2] = iv
      context[3] = aad
      Aes_init(init_code)
    },
    transform(chunk, controller) {
      try {
        context[5] = chunk
        do {
          context[6] = null
          Aes_update()
          if (context[6] != null) {
            enqueue(controller, context[6])
          }
        } while (context[5] != null)
      } finally {
        context[6] = null
      }
    },
    flush(controller) {
      try {
        context[6] = null
        if (Aes_final() != 0) {
          throw new Exception('The operation failed for an operation-specific reason', 'OperationError')
        }
        if (context[6] != null) {
          enqueue(controller, context[6])
        }
      } finally {
        context[6] = null
      }
    }
  })
}

export const createAesGcmEncryptStream = (key, iv, aad) => create(0b11, key, iv, aad)
export const createAesGcmDecryptStream = (key, iv, aad) => create(0b10, key, iv, aad)
