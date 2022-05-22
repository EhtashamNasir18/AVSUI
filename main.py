import csv
import os

from PyQt5 import QtCore, QtGui, QtWidgets
from PyQt5.QtCore import QFileInfo
from PyQt5.QtGui import QPixmap
from androguard.core.bytecodes.apk import APK
from PyQt5.QtWidgets import QFileDialog, QMessageBox


class Ui_Form(object):

    def __init__(self):
        self.folder = None
        self.files = None
        self.data = []
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
            data = []
            data.append(a.get_app_name())
            data.append(a.get_permissions())
            data.append(a.get_activities())
            data.append(a.get_certificates())
            data.append(a.get_dex())
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
        msg = QMessageBox()
        msg.setIcon(QMessageBox.Information)
        msg.setText("CSV generation complete check folder ./csvs")
        msg.setWindowTitle("Image creation")
        msg.setStandardButtons(QMessageBox.Ok)
        msg.exec_()
        print("function called")


if __name__ == "__main__":
    import sys

    app = QtWidgets.QApplication(sys.argv)
    Form = QtWidgets.QWidget()
    ui = Ui_Form()
    ui.setupUi(Form)
    Form.show()
    sys.exit(app.exec_())
