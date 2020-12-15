from PyQt5 import QtWidgets, QtCore, QtGui
from cryptographyProjectGUI import Ui_MainWindow
from Algorithms.RC5 import RC5
from Algorithms.RC6 import RC6
import sys, os


class ApplicationWindow(QtWidgets.QMainWindow):
    inputImagePath = ""
    outputImagePath = ""

    def __init__(self):
        super(ApplicationWindow, self).__init__()

        self.ui = Ui_MainWindow()
        self.ui.setupUi(self)

        self.ui.uploadButton.clicked.connect(self.browse)
        self.ui.runButton.clicked.connect(self.runAlgorithm)
        self.ui.saveOutput.clicked.connect(self.saveFileDialog)

    def browse(self):
        directory, _ = QtWidgets.QFileDialog.getOpenFileName(
            self, "Select Image", ".", "All Files(*.*)"
        )

        if directory:
            if self.ui.encryptRadioButton.isChecked():
                self.ui.inputImage.setPixmap(QtGui.QPixmap(directory))
            else:
                inputText = open(self.outputImagePath, "rb")
                inputdata = inputText.read()
                self.ui.inputImage.setText(str(inputdata))
                inputText.close()
            self.inputImagePath = directory

    def runAlgorithm(self):
        key = self.ui.keyTextEdit.toPlainText()
        algorithmType = (
            "RC5" if self.ui.rc5RadioButton.isChecked() else "RC6"
        )  # RC5 or RC6
        algorithmMode = (
            "Encrypt" if self.ui.encryptRadioButton.isChecked() else "Decrypt"
        )  # Encrypt or Decrypt

        if self.inputImagePath == "":
            return
        if algorithmType == "RC5":
            if algorithmMode == "Encrypt":
                self.RC5Encrypt(self.inputImagePath, key)
                self.showOutput(False)
            else:
                self.RC5Decrypt(self.inputImagePath, key)
                self.showOutput(True)
        else:
            if algorithmMode == "Encrypt":
                self.RC6Encrypt(self.inputImagePath, key)
                self.showOutput(False)
            else:
                self.RC6Decrypt(self.inputImagePath, key)
                self.showOutput(True)

    def RC5Encrypt(self, inputImagePath, key):
        blockSize = 32
        roundSize = 12
        _, file_extension = os.path.splitext(inputImagePath)
        self.outputImagePath = "output" + file_extension
        rc5 = RC5(blockSize, roundSize, key)
        rc5.encryptImageFile(inputImagePath, self.outputImagePath)

    def RC5Decrypt(self, inputImagePath, key):
        blockSize = 32
        roundSize = 12
        _, file_extension = os.path.splitext(inputImagePath)
        self.outputImagePath = "output2" + file_extension
        rc5 = RC5(blockSize, roundSize, key)
        rc5.decryptImageFile(inputImagePath, self.outputImagePath)

    def RC6Encrypt(self, inputImagePath, key):
        _, file_extension = os.path.splitext(inputImagePath)
        self.outputImagePath = "output" + file_extension
        rc6 = RC6()
        rc6.encryptImage(inputImagePath, self.outputImagePath, key)

    def RC6Decrypt(self, inputImagePath, key):
        _, file_extension = os.path.splitext(inputImagePath)
        self.outputImagePath = "output2" + file_extension
        rc6 = RC6()
        rc6.decryptImage(inputImagePath, self.outputImagePath, key)

    def showOutput(self, isImage):
        output = open(self.outputImagePath, "rb")
        outputdata = output.read()
        if isImage:
            self.ui.outputImage.setPixmap(QtGui.QPixmap(self.outputImagePath))
        else:
            self.ui.outputImage.setText(str(outputdata))
        output.close()

    def saveFileDialog(self):
        options = QtWidgets.QFileDialog.Options()
        # options |= QtWidgets.QFileDialog.DontUseNativeDialog
        fileName, _ = QtWidgets.QFileDialog.getSaveFileName(
            self, "QFileDialog.getSaveFileName()", "", "All Files (*)", options=options,
        )
        if fileName:
            inp = open(self.outputImagePath, "rb")
            out = open(fileName, "wb")
            out.write(inp.read())
            inp.close()
            out.close()


def main():
    app = QtWidgets.QApplication(sys.argv)
    application = ApplicationWindow()
    application.show()
    sys.exit(app.exec_())


if __name__ == "__main__":
    main()
