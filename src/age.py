title = "AGE"
host, port = "127.0.0.1", 8080

from asyncio import create_subprocess_exec as spawn
from asyncio.subprocess import PIPE
from nicegui import ui


async def open():
    proc = await spawn("age", "o", stdout=PIPE, stderr=PIPE)
    stdout, stderr = await proc.communicate()
    if proc.returncode == 0:
        return None, stdout.decode()
    return stderr.decode(), None


async def age(*args):
    proc = await spawn("age", *args, stderr=PIPE)
    while data := await proc.stderr.readline():
        yield data.decode()
    await proc.wait()
    return


def encrypt(input_file, output_file, password):
    return age("e", input_file, output_file, password)


def decrypt(input_file, output_file, password):
    return age("d", input_file, output_file, password)


@ui.page("/")
def index():
    def set_enabled(value):
        for el in (input, output, button):
            el.set_enabled(value)
            el.set_enabled(value)
        spinner.set_visibility(not value)

    async def on_click():
        set_enabled(False)
        try:
            is_decrypt = input.value.endswith(".zip")
            async for line in age(
                "d" if is_decrypt else "e",
                input.value,
                output.value,
                password.value,
            ):
                print(line, end="")
        finally:
            set_enabled(True)

    def validation(x):
        validated = not not x
        button.set_enabled(validated)
        return None if validated else ""

    async def on_input():
        set_enabled(False)
        try:
            err, value = await open()
            if err is None:
                input.value = value
                is_decrypt = value.endswith(".zip")
                output.value = value[0:-4] if is_decrypt else f"{value}.zip"
                button.text = "解密" if is_decrypt else "加密"
        finally:
            set_enabled(True)

    with (col := ui.column()):
        col.style("margin:auto;")
        with ui.row():
            password = ui.input("密码")
            password.classes("w-96")
        with ui.row():
            input = ui.input("输入", validation=validation)
            input.on("click", on_input)
            input.props("readonly")
        with ui.row():
            button = ui.button("加密", on_click=on_click)
            button.set_enabled(False)
            spinner = ui.spinner(size="lg")
            spinner.set_visibility(False)
        with ui.row():
            output = ui.input("输出")
        for x in (input, output):
            x.classes("w-96")
            x.style("width:32rem")


def main():
    ui.run(
        host=host,
        port=port,
        title=title,
        show=False,
        native=True,
        window_size=(768, 640),
        reload=False,
    )


if __name__ == "__main__":
    main()
