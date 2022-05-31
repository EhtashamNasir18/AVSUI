import os

if __name__ == "__main__":
    files = os.listdir("./apks")
    for f in files:
        os.system("python3 apktoimage.py ./apks/" + f + " ./train_images")
