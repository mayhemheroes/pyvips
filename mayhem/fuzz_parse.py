#! /usr/bin/env python3
import atheris
import sys

with atheris.instrument_imports(include=['pyvips', 'cffi']):
    import pyvips


def TestOneInput(data):
    try:
        image = pyvips.Image.new_from_buffer(data, "")
    except pyvips.Error:
        return -1


def main():
    atheris.Setup(sys.argv, TestOneInput)
    atheris.Fuzz()


if __name__ == "__main__":
    main()
