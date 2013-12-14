#!/usr/bin/env python
# coding:utf-8
# Copyright (c) 2013 v3aqb
# inspired by shadowsocks

from __future__ import print_function, division

__version__ = '0.1'

import wx
import base64
import hashlib
import M2Crypto.EVP
import M2Crypto.Rand
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
    while len(''.join(m)) < key_len:
        md5 = hashlib.md5()
        data = password
        if i > 0:
            data = m[i - 1] + password
        md5.update(data)
        m.append(md5.digest())
        i += 1
    ms = ''.join(m)
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


class Frame(wx.Frame):
    def __init__(
            self, parent=None, id=wx.ID_ANY, title='Crypto', pos=wx.DefaultPosition,
            size=wx.DefaultSize, style=wx.DEFAULT_FRAME_STYLE):
        wx.Frame.__init__(self, parent, id, title, pos, size, style)
        self.SetClientSize(wx.Size(632, 480))
        panel = wx.Panel(self, wx.ID_ANY)

        self.msgText = wx.TextCtrl(panel, style=wx.TE_MULTILINE)
        self.msgText.SetFont(wx.Font(9, wx.SWISS, wx.NORMAL, wx.NORMAL, False, 'monospace'))
        self.msgText.ChangeValue(u'明文')
        self.cipherText = wx.TextCtrl(panel, style=wx.TE_MULTILINE)
        self.cipherText.SetFont(wx.Font(9, wx.SWISS, wx.NORMAL, wx.NORMAL, False, 'monospace'))
        self.cipherText.ChangeValue(u'5piO5paH')
        self.cryptoKeyText = wx.TextCtrl(panel)
        self.cryptoKeyText.SetFont(wx.Font(9, wx.SWISS, wx.NORMAL, wx.NORMAL, False, 'monospace'))
        self.cryptoKeyText.ChangeValue(u'password')

        methodList = method_supported.keys()
        methodList.sort()
        methodList.insert(0, 'base64')
        self.cryptoMethodChoice = wx.Choice(panel, wx.ID_ANY, (85, 18), choices=methodList)

        encbutton = wx.Button(panel, wx.ID_ANY, u'加密↓')
        decbutton = wx.Button(panel, wx.ID_ANY, u'解密↑')

        box1 = wx.BoxSizer(wx.HORIZONTAL)
        box1.Add(self.cryptoMethodChoice, 1, wx.EXPAND)
        box1.Add(encbutton, 0)
        box1.Add(decbutton, 0)

        box = wx.BoxSizer(wx.VERTICAL)
        box.Add(self.msgText, 1, wx.EXPAND)
        box.Add(self.cipherText, 1, wx.EXPAND)
        box.Add(self.cryptoKeyText, 0, wx.EXPAND)
        box.Add(box1, 0, wx.EXPAND)
        panel.SetSizer(box)

        # bind event
        self.Bind(wx.EVT_BUTTON, self.do_encrypt, encbutton)
        self.Bind(wx.EVT_BUTTON, self.do_decrypt, decbutton)

    def _get_cipher_len(self, method):
        method = method.lower()
        m = method_supported.get(method, None)
        return m

    def do_encrypt(self, event):
        msg = self.msgText.GetValue().encode('utf-8')
        password = self.cryptoKeyText.GetValue().encode('utf-8')
        method = self.cryptoMethodChoice.GetStringSelection()
        m = self._get_cipher_len(method)
        if m:
            key, iv = EVP_BytesToKey(password, m[0], m[1])
            cipher = M2Crypto.EVP.Cipher(method.replace('-', '_'), key, iv, 1, key_as_bytes=0, d='md5', salt=None, i=1, padding=1)
            msg = iv + cipher.update(msg)
        self.cipherText.ChangeValue(base64.b64encode(msg))

    def do_decrypt(self, event):
        msg = base64.b64decode(self.cipherText.GetValue())
        password = self.cryptoKeyText.GetValue().encode('utf-8')
        method = self.cryptoMethodChoice.GetStringSelection()
        m = self._get_cipher_len(method)
        if m:
            key, _ = EVP_BytesToKey(password, m[0], m[1])
            iv = msg[:m[1]]
            decipher = M2Crypto.EVP.Cipher(method.replace('-', '_'), key, iv, 0, key_as_bytes=0, d='md5', salt=None, i=1, padding=1)
            msg = decipher.update(msg[m[1]:])
        encoding = chardet.detect(msg).get('encoding') if chardet else 'utf-8'
        self.msgText.ChangeValue(msg.decode(encoding or 'utf-8'))


def main():
    app = wx.App()
    win = Frame()
    win.Show()
    app.MainLoop()


if __name__ == '__main__':
    main()
