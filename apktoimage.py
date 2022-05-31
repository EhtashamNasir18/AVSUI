import sys

from PIL import Image
from PyQt5.QtCore import QUrl, QFileInfo
from androguard.core.bytecodes.apk import APK


def get_dex_bytes(apk: APK) -> bytes:
    for f in apk.get_files():
        if f.endswith(".dex"):
            yield apk.get_file(f)


def generate_png(apk: APK, filename: str, folder: str):
    stream = bytes()
    for s in get_dex_bytes(apk):
        stream += s
    current_len = len(stream)
    image = Image.frombytes(mode='L', size=(1, current_len), data=stream)
    image.save(f"{folder}/{filename}.png")


if __name__ == "__main__":
    if len(sys.argv) < 3:
        raise Exception("[!] Usage: python3 apktoimage.py APK DESTINATION")
    else:
        filename = sys.argv[1]
        destination_folder = sys.argv[2]
    try:
        apk = APK(filename)
        url = QUrl.fromLocalFile(filename)
        file = QFileInfo(filename).fileName()
        generate_png(apk, file, destination_folder)
        print(f"Image successfully generated from {filename}")
    except Exception as e:
        print("[!] An exception occurred with: {}".format(filename))
        print("Exception: {}".format(e))
