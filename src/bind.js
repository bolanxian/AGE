
export const noop = () => { }
export const nextTick = queueMicrotask

export const { apply } = Reflect
const { bind: _bind, call: _call } = Function.prototype
const _bindCall = apply(_bind, _bind, [_call])

const bindMap = new WeakMap()
const { get: _get, set: _set } = WeakMap.prototype
const get = _bindCall(_get)
const set = _bindCall(_set)
set(bindMap, _get, get)
set(bindMap, _set, set)
export const bindCall = (fn) => {
  let bound = get(bindMap, fn)
  if (bound == null) {
    bound = _bindCall(fn)
    set(bindMap, fn, bound)
  }
  return bound
}

export const bind = bindCall(_bind)
export const call = bindCall(_call)
export { get as getWeakMap, set as setWeakMap }

const $Proxy = Proxy, handler = {
  get(target, key, receiver) {
    const value = target[key]
    if (typeof value === 'function') {
      return bindCall(value)
    }
  }
}
/**
 * @type {
    <T extends {}>(o: T) => {
      [K in Exclude<keyof T, T extends any[] ? number : never>]:
        T[K] extends (...args: infer A) => infer R
          ? (thisArg: T, ...args: A) => R
          : never
    }
  }
*/
const createBinder = (o) => new $Proxy(o, handler)

export const $number = createBinder(Number.prototype)
export const $string = createBinder(String.prototype)
export const $array = createBinder(Array.prototype)

export const { fromEntries, getOwnPropertyDescriptor: getPropDesc, freeze } = Object
const ObjectProto = Object.prototype
export const hasOwn = Object.hasOwn ?? bindCall(ObjectProto.hasOwnProperty)
export const getTypeString = bindCall(ObjectProto.toString)
export const isPlainObject = (o) => {
  o = getTypeString(o)
  return o === '[object Object]' || o === '[object Array]'
}

/** @type {Uint8ArrayConstructor} */
const TypedArray = Object.getPrototypeOf(Uint8Array)
export const $typedArray = createBinder(TypedArray.prototype)
export const $dataView = createBinder(DataView.prototype)
export const getBuffer = bindCall(getPropDesc(TypedArray.prototype, 'buffer').get)
export const getByteOffset = bindCall(getPropDesc(TypedArray.prototype, 'byteOffset').get)
export const getByteLength = bindCall(getPropDesc(TypedArray.prototype, 'byteLength').get)
export const getLength = bindCall(getPropDesc(TypedArray.prototype, 'length').get)

export const $transformController = createBinder(TransformStreamDefaultController.prototype)
export const $response = createBinder(Response.prototype)
export const getBody = bindCall(getPropDesc(Response.prototype, 'body').get)
const Resp = Response, { arrayBuffer } = $response
export const toReadable = (data) => getBody(new Resp(data))
export const toBuffer = (data) => arrayBuffer(new Resp(data))

export const { compileStreaming, instantiate, Memory, Module, Instance } = WebAssembly
export const getMemoryBuffer = bindCall(getPropDesc(Memory.prototype, 'buffer').get)
export const getInstanceExports = bindCall(getPropDesc(Instance.prototype, 'exports').get)
