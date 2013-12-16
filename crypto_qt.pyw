# -*- coding: utf-8 -*-
from __future__ import absolute_import, print_function, unicode_literals
from crypto_qt_ui import Ui_Crypto
import sys
import base64
import hashlib
import M2Crypto.EVP
try:
    from PySide import QtGui
except ImportError:
    from PyQt4 import QtGui
try:
    import chardet
except ImportError:
    chardet = None


def EVP_BytesToKey(password, key_len, iv_len):
    # equivalent to OpenSSL's EVP_BytesToKey() with count 1
    # so that we make the same key and iv as nodejs version
    # TODO: cache the results
    m = []
    i = 0
    while len(b''.join(m)) < key_len:
        md5 = hashlib.md5()
        data = password
        if i > 0:
            data = m[i - 1] + password
        md5.update(data)
        m.append(md5.digest())
        i += 1
    ms = b''.join(m)
    key = ms[:key_len]
    iv = M2Crypto.Rand.rand_bytes(iv_len)
    return (key, iv)


method_supported = {
    'aes-128-cfb': (16, 16),
    'aes-192-cfb': (24, 16),
    'aes-256-cfb': (32, 16),
    'bf-cfb': (16, 8),
    'cast5-cfb': (16, 8),
    'des-cfb': (8, 8),
    'rc4': (16, 0),
}


class ControlMainWindow(QtGui.QMainWindow):
    def __init__(self, parent=None):
        super(ControlMainWindow, self).__init__(parent)
        self.ui = Ui_Crypto()
        self.ui.setupUi(self)
        self.ui.encryptButton.clicked.connect(self.do_encrypt)
        self.ui.decryptButton.clicked.connect(self.do_decrypt)
        methodList = method_supported.keys()
        methodList.sort()
        methodList.insert(0, 'base64')
        self.ui.methodBox.addItems(methodList)
        self.ui.keyEdit.setText('password')

    def _get_cipher_len(self, method):
        method = method.lower()
        m = method_supported.get(method, None)
        return m

    def do_encrypt(self):
        msg = self.ui.textEdit.toPlainText().encode('utf-8')
        password = self.ui.keyEdit.text().encode('utf-8')
        method = self.ui.methodBox.currentText()
        m = self._get_cipher_len(method)
        if m:
            key, iv = EVP_BytesToKey(password, m[0], m[1])
            cipher = M2Crypto.EVP.Cipher(method.replace('-', '_'), key, iv, 1, key_as_bytes=0, d='md5', salt=None, i=1, padding=1)
            msg = iv + cipher.update(msg)
        self.ui.cipherEdit.setPlainText(base64.b64encode(msg))

    def do_decrypt(self):
        msg = base64.b64decode(self.ui.cipherEdit.toPlainText())
        password = self.ui.keyEdit.text().encode('utf-8')
        method = self.ui.methodBox.currentText()
        m = self._get_cipher_len(method)
        if m:
            key, _ = EVP_BytesToKey(password, m[0], m[1])
            iv = msg[:m[1]]
            decipher = M2Crypto.EVP.Cipher(method.replace('-', '_'), key, iv, 0, key_as_bytes=0, d='md5', salt=None, i=1, padding=1)
            msg = decipher.update(msg[m[1]:])
        encoding = chardet.detect(msg).get('encoding') if chardet else 'utf-8'
        self.ui.textEdit.setPlainText(msg.decode(encoding or 'utf-8'))


if __name__ == "__main__":
    app = QtGui.QApplication(sys.argv)
    win = ControlMainWindow()
    win.show()
    sys.exit(app.exec_())
