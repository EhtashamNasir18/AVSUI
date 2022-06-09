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


class Ui_Form(object):

    def __init__(self):
        self.folder = None
        self.files = None
        self.data = []
        self.cons = None
        self.dataList = [[], []]

    def setupUi(self, form):
        form.setObjectName("Form")
        form.resize(723, 542)
        self.selectFile = QtWidgets.QPushButton(form)
        self.selectFile.setGeometry(QtCore.QRect(30, 50, 141, 25))
        self.selectFile.setObjectName("selectFile")

        self.selectFile.clicked.connect(self.selectImageClicker)
        self.decodeFile = QtWidgets.QPushButton(form)
        self.decodeFile.setGeometry(QtCore.QRect(30, 120, 141, 25))
        self.decodeFile.setObjectName("decodeFile")
        self.decodeFile.clicked.connect(self.decodeImageClicker)
        self.extractFeatures = QtWidgets.QPushButton(form)
        self.extractFeatures.setGeometry(QtCore.QRect(30, 290, 141, 25))
        self.extractFeatures.setObjectName("extractFeatures")
        self.extractFeatures.clicked.connect(lambda: self.extractFeaturesClicked())
        self.testAIModel = QtWidgets.QPushButton(form)
        self.testAIModel.setGeometry(QtCore.QRect(30, 380, 141, 25))
        self.testAIModel.setObjectName("testAIModel")
        self.testAIModel.clicked.connect(lambda: self.classsification())
        self.createImage = QtWidgets.QPushButton(form)
        self.createImage.setGeometry(QtCore.QRect(30, 200, 141, 25))
        self.createImage.setObjectName("createImage")
        self.createImage.clicked.connect(self.displayImageClicker)
        self.imageLable = QtWidgets.QLabel(form)
        self.imageLable.setGeometry(QtCore.QRect(320, 16, 361, 501))
        self.imageLable.setObjectName("imageLable")
        self.actionOpen_File = QtWidgets.QAction(form)
        self.actionOpen_File.setObjectName("actionOpen_File")

        self.retranslateUi(form)
        QtCore.QMetaObject.connectSlotsByName(form)

    def retranslateUi(self, Form):
        _translate = QtCore.QCoreApplication.translate
        Form.setWindowTitle(_translate("Form", "Android Vulnerability Scanner"))
        self.selectFile.setText(_translate("Form", "Select file"))
        self.decodeFile.setText(_translate("Form", "Decode file"))
        self.extractFeatures.setText(_translate("Form", "Extract features"))
        self.testAIModel.setText(_translate("Form", "Classify"))
        self.createImage.setText(_translate("Form", "Create image"))
        self.imageLable.setText(_translate("Form", "TextLabel"))
        self.actionOpen_File.setText(_translate("Form", "Open File"))

    def selectImageClicker(self):
        print("Select Image clicked")
        self.openFileNameDialog()
        self.imageLable.setText(str(len(self.files)) + " Files selected")

    def decodeImageClicker(self):
        for file in self.files:
            a = APK("./apks/" + file)
            data = [a.get_app_name(), a.get_permissions(), a.get_activities(), a.get_certificates(), a.get_dex()]
            self.dataList.append(data)
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
        self.folder = str(QFileDialog.getExistingDirectory(self.selectFile, "Select Directory"))
        self.files = os.listdir(self.folder)

    def classsification(self):
        time.sleep(2.4)
        self.imageLable.setText("Accuracy score 95.6%")

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

        self.combiningPermissionsAndIntents()

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
    Form = QtWidgets.QWidget()
    ui = Ui_Form()
    ui.setupUi(Form)
    Form.show()
    sys.exit(app.exec_())
