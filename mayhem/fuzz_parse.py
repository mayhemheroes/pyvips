#! /usr/bin/env python3
import atheris
import sys
import fuzz_helpers

with atheris.instrument_imports():
    import pyvips


def TestOneInput(data):
    try:
        fdp = fuzz_helpers.EnhancedFuzzedDataProvider(data)
        image = pyvips.Image.new_from_buffer(fdp.ConsumeRandomBytes(), "")
        arr = fuzz_helpers.build_fuzz_list(fdp, [int])
        mask = pyvips.Image.new_from_array(arr, scale=8)
        image = image.conv(mask, precision='integer')
    except pyvips.Error:
        return -1


def main():
    atheris.Setup(sys.argv, TestOneInput)
    atheris.Fuzz()


if __name__ == "__main__":
    main()
