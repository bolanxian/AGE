
import { crc32 } from 'hash-wasm'
const { assign } = Object

const typeLength = {
  'u8': 1, 'u16': 2,
  'u32': 4, 'u64': 8
}
const typeMethod = {
  'u8': 'Uint8', 'u16': 'Uint16',
  'u32': 'Uint32', 'u64': 'BigUint64'
}

export const createStruct = (fields, defaultValue) => {
  let length = 0
  return class {
    #view
    get $view() { return this.#view }
    constructor(buffer, byteOffset) {
      this.#view = new DataView(buffer, byteOffset, length)
    }
    static {
      for (const [key, type] of fields) {
        const offset = length
        const name = typeMethod[type]
        Object.defineProperty(this.prototype, key, {
          get() {
            return this.#view[`get${name}`](offset, true)
          },
          set(value) {
            return this.#view[`set${name}`](offset, value, true)
          }
        })
        length += typeLength[type]
      }
    }
    static byteLength = length
    static default = defaultValue
  }
}

export const packDate = (
  year = 1980,
  month = 1,
  date = 1,
  hours = 0,
  minutes = 0,
  seconds = 0,
) => {
  let ret = 0
  ret |= (seconds / 2 & 0x1F)
  ret |= (minutes & 0x3F) << 5
  ret |= (hours & 0x1F) << 11
  ret |= (date & 0x1F) << 16
  ret |= (month & 0xF) << 21
  ret |= (year - 1980 & 0x7F) << 25
  return ret >>> 0
}
export const defaultDate = packDate()

export const pack = (T, init) => {
  const buffer = new ArrayBuffer(T.byteLength)
  const self = new T(buffer, 0)
  assign(self, T.default, init)
  return new Uint8Array(buffer)
}
export const from = (T, buffer, byteOffset) => {
  const self = new T(buffer, byteOffset)
  if (T.default.magic !== self.magic) {
    throw new TypeError('InvalidMagicNumber')
  }
  return self
}

export const LocalFileHeader = createStruct([
  ['magic', 'u32'],
  ['version', 'u16'],
  ['_2', 'u16'],
  ['_3', 'u16'],
  ['date', 'u32'],
  ['crc32', 'u32'],
  ['comp_size', 'u32'],
  ['size', 'u32'],
  ['name_len', 'u16'],
  ['extra_len', 'u16'],
], {
  magic: 0x04034b50,
  version: 0x0A,
  date: defaultDate,
})
export const CentralDirectoryHeader = createStruct([
  ['magic', 'u32'],
  ['_1', 'u16'],
  ['version', 'u16'],
  ['_3', 'u16'],
  ['_4', 'u16'],
  ['date', 'u32'],
  ['crc32', 'u32'],
  ['comp_size', 'u32'],
  ['size', 'u32'],
  ['name_len', 'u16'],
  ['extra_len', 'u16'],
  ['comment_len', 'u16'],
  ['_12', 'u16'],
  ['_13', 'u16'],
  ['_14', 'u32'],
  ['offset', 'u32'],
], {
  magic: 0x02014b50,
  _1: 0x3F,
  version: 0x0A,
  date: defaultDate,
})
export const EndOfCentralDirectory = createStruct([
  ['magic', 'u32'],
  ['_1', 'u16'],
  ['_2', 'u16'],
  ['_3', 'u16'],
  ['_4', 'u16'],
  ['size', 'u32'],
  ['offset', 'u32'],
  ['_7', 'u16'],
], {
  magic: 0x06054b50,
  _3: 1,
  _4: 1,
})

const encoder = new TextEncoder()
export const write = async (file, name, content, _date, extra) => {
  const date = _date != null ? packDate(
    _date.getFullYear(), _date.getMonth() + 1, _date.getDate(),
    _date.getHours(), _date.getMinutes(), _date.getSeconds()
  ) : defaultDate
  name = typeof name == 'string' ? encoder.encode(name) : name
  content = typeof content == 'string' ? encoder.encode(content) : content
  const crc = parseInt(await crc32(content), 16)
  const size = content.byteLength
  const name_len = name.byteLength
  await file.write(pack(LocalFileHeader, {
    date,
    crc32: crc,
    comp_size: size,
    size,
    name_len,
  }))
  await file.write(name)
  await file.write(content)
  let extra_len = 0
  for (const data of extra) {
    extra_len += data.byteLength
    await file.write(data)
  }
  await file.write(pack(CentralDirectoryHeader, {
    date,
    crc32: crc,
    comp_size: size,
    size,
    name_len,
    offset: 0,
  }))
  await file.write(name)
  await file.write(pack(EndOfCentralDirectory, {
    size: CentralDirectoryHeader.byteLength + name.byteLength,
    offset: LocalFileHeader.byteLength + name.byteLength + content.byteLength + extra_len,
  }))
}

export const read = async (file) => {
  await file.seek(- EndOfCentralDirectory.byteLength, Deno.SeekMode.End)
  const _eocd = new Uint8Array(EndOfCentralDirectory.byteLength)
  await file.read(_eocd)
  const eocd = from(EndOfCentralDirectory, _eocd.buffer, 0)

  await file.seek(eocd.offset, Deno.SeekMode.Start)
  const _centrals = new Uint8Array(eocd.size)
  await file.read(_centrals)
  let offset = 0
  let i = 0, len = eocd.size
  while (i < len) {
    const central = from(CentralDirectoryHeader, _centrals.buffer, i)
    offset = central.offset + LocalFileHeader.byteLength + central.name_len + central.extra_len + central.comp_size;
    i += CentralDirectoryHeader.byteLength + central.name_len + central.extra_len + central.comment_len
  }

  const size = eocd.offset - offset;
  if (!(size > 0)) {
    return new TypeError('NoExtraData')
  }
  await file.seek(offset, Deno.SeekMode.Start)
  const data = new Uint8Array(size)
  await file.read(data)
  return data
}

if (import.meta.main) {
  const { log } = console
  const input = await Deno.open(Deno.args[0], { create: true, write: true })
  try {
    const data = crypto.getRandomValues(new Uint8Array(32))
    log(data)
    await write(input, 'name', 'content', [data])
  } finally {
    input.close()
  }
  const output = await Deno.open(Deno.args[0], { read: true })
  try {
    const data = await read(output)
    log(data)
  } finally {
    output.close()
  }
}
