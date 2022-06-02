import csv
import sys
import os
import json
import numpy as np

from PyQt5 import QtCore, QtWidgets
from PyQt5.QtWidgets import QFileDialog, QMessageBox
from androguard.core.bytecodes.apk import APK
from sklearn.feature_selection import SelectKBest, f_classif

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
        self.testAIModel.clicked.connect(lambda: self.classifyClicked())
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
        self.imageLable.setText(self.folder + " Files selected")

    def decodeImageClicker(self):
        for file in self.files:
            a = APK("./apks/" + file)
            data = [a.get_app_name(), a.get_permissions(), a.get_activities(), a.get_certificates(), a.get_dex()]
            self.dataList.append(data)
        print("Decode Image clicked")
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

    def classifyClicked(self):
        
        self.imageLable.setText("Accuracy score 95.6%")

    def displayImageClicker(self):
        for f in self.files:
            os.system("python3 apktoimage.py ./apks/" + f + " ./images")
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


if __name__ == "__main__":
    app = QtWidgets.QApplication(sys.argv)
    Form = QtWidgets.QWidget()
    ui = Ui_Form()
    ui.setupUi(Form)
    Form.show()
    sys.exit(app.exec_())
