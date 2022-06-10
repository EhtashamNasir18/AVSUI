import csv
import json
import os
import sys
import time

import numpy as np
from PyQt5 import QtCore, QtWidgets
from PyQt5.QtCore import Qt
from PyQt5.QtWidgets import QFileDialog, QMessageBox, QProgressDialog
from androguard.core.bytecodes.apk import APK
from keras.constraints import maxnorm
from keras.layers import Dense
from keras.layers import Dropout
from keras.models import Sequential
from sklearn import metrics
from sklearn.model_selection import train_test_split

from constants import INTENTS, PERMISSIONS


def load_json(fp):
    with open(fp) as f:
        data = json.load(f)
    return data["permissions"], data["intents"]


def get_feature_vector(apk):
    fv = []  # feature vector
    for permission in PERMISSIONS:
        status = 1 if permission in apk['permissions'] else 0
        fv.append(status)
    for intent in INTENTS:
        status = 1 if intent in apk['intents'] else 0
        fv.append(status)
    return fv


def prepare_dataset():
    paths = ["./benign_2017_static/ApkMetaReport/", "./malware_2017_static/ApkMetaReport/"]
    apks = []
    for path in paths:
        files = os.listdir(path)
        for file in files:
            apk = {}
            filepath = path + file
            apk['permissions'], apk['intents'] = load_json(filepath)
            apk['Malicious'] = paths.index(path)
            apks.append(apk)
    return apks


def get_X_and_Y_matrices():
    print("Preparing dataset...")
    dataset = prepare_dataset()
    print("Dataset preparation completed.")
    print("Creating x and y matrices...")
    x = []
    y = []
    for apk in dataset:
        x.append(get_feature_vector(dataset[dataset.index(apk)]))
        y.append(apk['Malicious'])
    print("x and y matrices are created.")
    return np.array(x), np.array(y)


class Ui_MainWindow(object):

    def __init__(self):
        self.folder = None
        self.files = None
        self.data = []
        self.cons = None
        self.dataList = [[], []]

    def setupUi(self, MainWindow):
        MainWindow.setObjectName("MainWindow")
        MainWindow.resize(800, 205)
        self.centralwidget = QtWidgets.QWidget(MainWindow)
        self.centralwidget.setObjectName("centralwidget")
        self.selectFolder = QtWidgets.QPushButton(self.centralwidget)
        self.selectFolder.setGeometry(QtCore.QRect(40, 40, 201, 25))
        self.selectFolder.setObjectName("pushButton")
        self.selectFolder.clicked.connect(lambda: self.selectImageClicker())
        self.decodeAPKs = QtWidgets.QPushButton(self.centralwidget)
        self.decodeAPKs.setGeometry(QtCore.QRect(270, 40, 201, 25))
        self.decodeAPKs.setObjectName("pushButton_2")
        self.decodeAPKs.clicked.connect(lambda: self.decodeImageClicker())
        self.createImages = QtWidgets.QPushButton(self.centralwidget)
        self.createImages.setGeometry(QtCore.QRect(530, 40, 201, 25))
        self.createImages.setObjectName("pushButton_3")
        self.createImages.clicked.connect(lambda: self.displayImageClicker())
        self.createCSV = QtWidgets.QPushButton(self.centralwidget)
        self.createCSV.setGeometry(QtCore.QRect(40, 100, 201, 25))
        self.createCSV.setObjectName("pushButton_4")
        self.createCSV.clicked.connect(lambda: self.extractFeaturesClicked())
        self.graphicsView = QtWidgets.QGraphicsView(self.centralwidget)
        self.graphicsView.setGeometry(QtCore.QRect(25, 0, 721, 151))
        self.graphicsView.setObjectName("graphicsView")
        self.label = QtWidgets.QLabel(self.centralwidget)
        self.label.setGeometry(QtCore.QRect(40, 10, 67, 17))
        self.label.setObjectName("label")
        self.prediction = QtWidgets.QPushButton(self.centralwidget)
        self.prediction.setGeometry(QtCore.QRect(530, 100, 201, 25))
        self.prediction.setObjectName("pushButton_5")
        self.training = QtWidgets.QPushButton(self.centralwidget)
        self.training.setGeometry(QtCore.QRect(270, 100, 201, 25))
        self.training.setObjectName("pushButton_6")
        self.graphicsView.raise_()
        self.selectFolder.raise_()
        self.decodeAPKs.raise_()
        self.createImages.raise_()
        self.createCSV.raise_()
        self.label.raise_()
        self.prediction.raise_()
        self.training.raise_()
        MainWindow.setCentralWidget(self.centralwidget)
        self.menubar = QtWidgets.QMenuBar(MainWindow)
        self.menubar.setGeometry(QtCore.QRect(0, 0, 800, 22))
        self.menubar.setObjectName("menubar")
        MainWindow.setMenuBar(self.menubar)
        self.statusbar = QtWidgets.QStatusBar(MainWindow)
        self.statusbar.setObjectName("statusbar")
        MainWindow.setStatusBar(self.statusbar)

        self.retranslateUi(MainWindow)
        QtCore.QMetaObject.connectSlotsByName(MainWindow)

    def retranslateUi(self, MainWindow):
        _translate = QtCore.QCoreApplication.translate
        MainWindow.setWindowTitle(_translate("MainWindow", "MainWindow"))
        self.selectFolder.setText(_translate("MainWindow", "Select APK folder"))
        self.decodeAPKs.setText(_translate("MainWindow", "Decode APKs"))
        self.createImages.setText(_translate("MainWindow", "Create Images"))
        self.createCSV.setText(_translate("MainWindow", "Create CSV"))
        self.label.setText(_translate("MainWindow", "Testing"))
        self.prediction.setText(_translate("MainWindow", "Predict Classes"))
        self.training.setText(_translate("MainWindow", "Train on the Dataset CSVs"))

    def selectImageClicker(self):
        print("Select Image clicked")
        self.openFileNameDialog()
        msg = QMessageBox()
        msg.setIcon(QMessageBox.Information)
        msg.setText(str(len(self.files))+" APK files selected")
        msg.setWindowTitle("APK count")
        msg.setStandardButtons(QMessageBox.Ok)
        msg.exec_()

    def decodeImageClicker(self):
        prgr_dialog = QProgressDialog()
        prgr_dialog.setWindowTitle('Please wait')
        prgr_dialog.setLabelText("Decoding files")
        prgr_dialog.setWindowModality(Qt.WindowModal)
        prgr_dialog.setMaximum(len(self.files))
        i = 0
        prgr_dialog.setValue(i)
        for file in self.files:
            a = APK("./apks/" + file)
            data = [a.get_app_name(), a.get_permissions(), a.get_activities(), a.get_certificates()]
            self.dataList.append(data)
            i += 1
            prgr_dialog.setValue(i)
        prgr_dialog.close()
        print("Decode Image clicked")
        time.sleep(2.4)
        msg = QMessageBox()
        msg.setIcon(QMessageBox.Information)
        msg.setText("APk Decoding Complete. Now you can create Images from bytecode")
        msg.setWindowTitle("APK decoding")
        msg.setStandardButtons(QMessageBox.Ok)
        msg.exec_()

    def openFileNameDialog(self):
        options = QFileDialog.Options()
        options |= QFileDialog.DontUseNativeDialog
        self.folder = str(QFileDialog.getExistingDirectory(self.selectFolder, "Select Directory"))
        self.files = os.listdir(self.folder)

    def classsification(self):
        time.sleep(2.4)


    def displayImageClicker(self):
        prgr_dialog = QProgressDialog()
        prgr_dialog.setWindowTitle('Please wait')
        prgr_dialog.setLabelText("Generating images")
        prgr_dialog.setWindowModality(Qt.WindowModal)
        prgr_dialog.setMaximum(len(self.files))
        i = 0
        prgr_dialog.setValue(i)
        for f in self.files:
            os.system("python3 apktoimage.py ./apks/" + f + " ./images")
            i += 1
            prgr_dialog.setValue(i)
        prgr_dialog.close()
        msg = QMessageBox()
        msg.setIcon(QMessageBox.Information)
        msg.setText("Image creation complete check folder ./images")
        msg.setWindowTitle("Image creation")
        msg.setStandardButtons(QMessageBox.Ok)
        msg.exec_()

    def extractFeaturesClicked(self):
        with open("./csvs/features.csv", "w", newline="") as f:
            writer = csv.writer(f)
            writer.writerows(self.dataList)
        msg = QMessageBox()
        msg.setIcon(QMessageBox.Information)
        msg.setText("CSV generation complete check folder ./csvs")
        msg.setWindowTitle("Image creation")
        msg.setStandardButtons(QMessageBox.Ok)
        msg.exec_()
        print("function called")

    def combiningPermissionsAndIntents(self):
        pfile = open("all_permissions.txt", "r")
        perms = pfile.readlines()
        for i in range(len(perms)):
            perms[i] = perms[i].replace('\n', '')
        ifile = open("all_intents.txt", "r")
        intents = ifile.readlines()
        for i in range(len(intents)):
            intents[i] = intents[i].replace('\n', '')
        with open("constants.py", "w") as self.cons:
            self.cons.write("PERMISSIONS=(")
            for p in perms[:-1]:
                if p != "":
                    self.cons.write("'" + str(p) + "'")
                    self.cons.write(",\n")
            self.cons.write("'")
            self.cons.write(str(perms[-1]))
            self.cons.write("'")
            self.cons.write(")")
            self.cons.write("\n")
            self.cons.write("INTENTS=(")
            for i in intents[:-1]:
                if i != "":
                    self.cons.write("'" + str(i) + "'")
                    self.cons.write(",\n")
            self.cons.write("'")
            self.cons.write(str(intents[-1]))
            self.cons.write("'")
            self.cons.write(")\n")
        ifile.close()
        pfile.close()

    def classification(self):
        print("Fetching X and Y matrices...")
        X, Y = get_X_and_Y_matrices()
        print("X and Y matrices are fetched.")
        print(len(Y))
        print("Splitting the dataset...")
        x_train, x_test, y_train, y_test = train_test_split(X, Y, test_size=0.2, random_state=42)
        print(len(y_train))
        print(len(y_test))
        model = Sequential()
        model.add(Dense(30, activation='relu', input_dim=2000, kernel_initializer='lecun_uniform',
                        kernel_constraint=maxnorm(2)))
        model.add(Dropout(0.2))
        model.add(Dense(1, kernel_initializer='lecun_uniform', activation='sigmoid'))
        model.compile(optimizer='rmsprop',
                      loss='binary_crossentropy',
                      metrics=['accuracy'])
        model.fit(x_train, y_train, epochs=100, batch_size=20)

        _, accuracy = model.evaluate(x_test, y_test)
        print('Accuracy: %.2f' % (accuracy * 100))

        predictions = list((model.predict(x_test) > 0.5).astype("int32"))
        self.imageLable.setText("Accuracy: " + str(metrics.accuracy_score(y_test, predictions) * 100) + "%")


if __name__ == "__main__":
    app = QtWidgets.QApplication(sys.argv)
    Form = QtWidgets.QMainWindow()
    ui = Ui_MainWindow()
    ui.setupUi(Form)
    Form.show()
    sys.exit(app.exec_())
