# -*- coding: utf-8 -*-

# Form implementation generated from reading ui file 'cryptographyProjectGUI.ui'
#
# Created by: PyQt5 UI code generator 5.14.1
#
# WARNING! All changes made in this file will be lost!


from PyQt5 import QtCore, QtGui, QtWidgets


class Ui_MainWindow(object):
    def setupUi(self, MainWindow):
        MainWindow.setObjectName("MainWindow")
        MainWindow.resize(1097, 514)
        self.centralwidget = QtWidgets.QWidget(MainWindow)
        self.centralwidget.setObjectName("centralwidget")
        self.algorithm = QtWidgets.QGroupBox(self.centralwidget)
        self.algorithm.setGeometry(QtCore.QRect(20, 20, 181, 101))
        self.algorithm.setObjectName("algorithm")
        self.rc5RadioButton = QtWidgets.QRadioButton(self.algorithm)
        self.rc5RadioButton.setEnabled(True)
        self.rc5RadioButton.setGeometry(QtCore.QRect(10, 30, 133, 27))
        self.rc5RadioButton.setTabletTracking(False)
        self.rc5RadioButton.setAcceptDrops(False)
        self.rc5RadioButton.setAutoFillBackground(False)
        self.rc5RadioButton.setChecked(True)
        self.rc5RadioButton.setObjectName("rc5RadioButton")
        self.rc6RadioButton = QtWidgets.QRadioButton(self.algorithm)
        self.rc6RadioButton.setGeometry(QtCore.QRect(10, 60, 133, 27))
        self.rc6RadioButton.setObjectName("rc6RadioButton")
        self.uploadButton = QtWidgets.QPushButton(self.centralwidget)
        self.uploadButton.setGeometry(QtCore.QRect(20, 330, 181, 30))
        self.uploadButton.setObjectName("uploadButton")
        self.runButton = QtWidgets.QPushButton(self.centralwidget)
        self.runButton.setGeometry(QtCore.QRect(20, 370, 181, 30))
        self.runButton.setObjectName("runButton")
        self.groupBox_2 = QtWidgets.QGroupBox(self.centralwidget)
        self.groupBox_2.setGeometry(QtCore.QRect(20, 140, 181, 101))
        self.groupBox_2.setObjectName("groupBox_2")
        self.encryptRadioButton = QtWidgets.QRadioButton(self.groupBox_2)
        self.encryptRadioButton.setGeometry(QtCore.QRect(10, 30, 133, 27))
        self.encryptRadioButton.setChecked(True)
        self.encryptRadioButton.setObjectName("encryptRadioButton")
        self.decryptRadioButton = QtWidgets.QRadioButton(self.groupBox_2)
        self.decryptRadioButton.setGeometry(QtCore.QRect(10, 60, 133, 27))
        self.decryptRadioButton.setObjectName("decryptRadioButton")
        self.groupBox = QtWidgets.QGroupBox(self.centralwidget)
        self.groupBox.setGeometry(QtCore.QRect(240, 20, 371, 411))
        self.groupBox.setObjectName("groupBox")
        self.scrollArea = QtWidgets.QScrollArea(self.groupBox)
        self.scrollArea.setGeometry(QtCore.QRect(0, 30, 371, 381))
        self.scrollArea.setWidgetResizable(True)
        self.scrollArea.setObjectName("scrollArea")
        self.scrollAreaWidgetContents = QtWidgets.QWidget()
        self.scrollAreaWidgetContents.setGeometry(QtCore.QRect(0, 0, 369, 379))
        self.scrollAreaWidgetContents.setObjectName("scrollAreaWidgetContents")
        self.verticalLayout = QtWidgets.QVBoxLayout(self.scrollAreaWidgetContents)
        self.verticalLayout.setObjectName("verticalLayout")
        self.inputImage = QtWidgets.QLabel(self.scrollAreaWidgetContents)
        self.inputImage.setText("")
        self.inputImage.setScaledContents(True)
        self.inputImage.setWordWrap(True)
        self.inputImage.setObjectName("inputImage")
        self.verticalLayout.addWidget(self.inputImage)
        self.scrollArea.setWidget(self.scrollAreaWidgetContents)
        self.groupBox_3 = QtWidgets.QGroupBox(self.centralwidget)
        self.groupBox_3.setGeometry(QtCore.QRect(670, 20, 371, 411))
        self.groupBox_3.setObjectName("groupBox_3")
        self.scrollArea_2 = QtWidgets.QScrollArea(self.groupBox_3)
        self.scrollArea_2.setGeometry(QtCore.QRect(0, 30, 371, 381))
        self.scrollArea_2.setWidgetResizable(True)
        self.scrollArea_2.setObjectName("scrollArea_2")
        self.scrollAreaWidgetContents_2 = QtWidgets.QWidget()
        self.scrollAreaWidgetContents_2.setGeometry(QtCore.QRect(0, 0, 369, 379))
        self.scrollAreaWidgetContents_2.setObjectName("scrollAreaWidgetContents_2")
        self.verticalLayout_2 = QtWidgets.QVBoxLayout(self.scrollAreaWidgetContents_2)
        self.verticalLayout_2.setObjectName("verticalLayout_2")
        self.outputImage = QtWidgets.QLabel(self.scrollAreaWidgetContents_2)
        self.outputImage.setText("")
        self.outputImage.setScaledContents(True)
        self.outputImage.setWordWrap(True)
        self.outputImage.setObjectName("outputImage")
        self.verticalLayout_2.addWidget(self.outputImage)
        self.scrollArea_2.setWidget(self.scrollAreaWidgetContents_2)
        self.saveOutput = QtWidgets.QPushButton(self.centralwidget)
        self.saveOutput.setGeometry(QtCore.QRect(20, 410, 181, 30))
        self.saveOutput.setObjectName("saveOutput")
        self.keyTextEdit = QtWidgets.QTextEdit(self.centralwidget)
        self.keyTextEdit.setGeometry(QtCore.QRect(20, 280, 181, 31))
        self.keyTextEdit.setObjectName("keyTextEdit")
        self.label = QtWidgets.QLabel(self.centralwidget)
        self.label.setGeometry(QtCore.QRect(20, 260, 80, 21))
        self.label.setObjectName("label")
        MainWindow.setCentralWidget(self.centralwidget)
        self.menubar = QtWidgets.QMenuBar(MainWindow)
        self.menubar.setGeometry(QtCore.QRect(0, 0, 1097, 26))
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
        self.algorithm.setTitle(_translate("MainWindow", "Algorithm"))
        self.rc5RadioButton.setText(_translate("MainWindow", "RC5"))
        self.rc6RadioButton.setText(_translate("MainWindow", "RC6"))
        self.uploadButton.setText(_translate("MainWindow", "upload"))
        self.runButton.setText(_translate("MainWindow", "run"))
        self.groupBox_2.setTitle(_translate("MainWindow", "Mode"))
        self.encryptRadioButton.setText(_translate("MainWindow", "Encrypt"))
        self.decryptRadioButton.setText(_translate("MainWindow", "Decrypt"))
        self.groupBox.setTitle(_translate("MainWindow", "Input"))
        self.groupBox_3.setTitle(_translate("MainWindow", "output"))
        self.saveOutput.setText(_translate("MainWindow", "save output"))
        self.keyTextEdit.setHtml(_translate("MainWindow", "<!DOCTYPE HTML PUBLIC \"-//W3C//DTD HTML 4.0//EN\" \"http://www.w3.org/TR/REC-html40/strict.dtd\">\n"
"<html><head><meta name=\"qrichtext\" content=\"1\" /><style type=\"text/css\">\n"
"p, li { white-space: pre-wrap; }\n"
"</style></head><body style=\" font-family:\'Ubuntu\'; font-size:11pt; font-weight:400; font-style:normal;\">\n"
"<p style=\"-qt-paragraph-type:empty; margin-top:0px; margin-bottom:0px; margin-left:0px; margin-right:0px; -qt-block-indent:0; text-indent:0px;\"><br /></p></body></html>"))
        self.label.setText(_translate("MainWindow", "Key"))


if __name__ == "__main__":
    import sys
    app = QtWidgets.QApplication(sys.argv)
    MainWindow = QtWidgets.QMainWindow()
    ui = Ui_MainWindow()
    ui.setupUi(MainWindow)
    MainWindow.show()
    sys.exit(app.exec_())
