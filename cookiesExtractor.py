# -*- coding: utf-8 -*-
from burp import IBurpExtender, IHttpListener, IContextMenuFactory, IContextMenuInvocation
from java.util import List, ArrayList
from javax.swing import JMenuItem
import json

class BurpExtender(IBurpExtender, IHttpListener, IContextMenuFactory):
    def registerExtenderCallbacks(self, callbacks):
        self._callbacks = callbacks
        self._helpers = callbacks.getHelpers()
        callbacks.setExtensionName("Cookie and Header Extractor")
        callbacks.registerHttpListener(self)
        callbacks.registerContextMenuFactory(self)

    def createMenuItems(self, invocation):
        self._invocation = invocation
        menuList = ArrayList()
        
        # Opción para extraer solo cookies
        menuItemCookies = JMenuItem("Extraer Cookies", actionPerformed=self.menuItemExtractCookies)
        menuList.add(menuItemCookies)
        
        # Opción para extraer solo headers
        menuItemHeaders = JMenuItem("Extraer Headers", actionPerformed=self.menuItemExtractHeaders)
        menuList.add(menuItemHeaders)
        
        return menuList

    def menuItemExtractCookies(self, event):
        # Obtener la información de la petición seleccionada
        messages = self._invocation.getSelectedMessages()
        for messageInfo in messages:
            request = messageInfo.getRequest()
            if request:
                analyzedRequest = self._helpers.analyzeRequest(request)
                headers = analyzedRequest.getHeaders()
                cookies_dict = {}
                request_url = ""

                # Recorremos todos los headers
                for header in headers:
                    if ":" in header:
                        name, value = header.split(":", 1)
                        if name.strip().lower() == "cookie":
                            cookies = value.strip().split(";")
                            for cookie in cookies:
                                cookie_name, cookie_value = cookie.split("=", 1)
                                cookies_dict[cookie_name.strip()] = cookie_value.strip()
                        elif name.strip().lower() == "host":
                            request_url = value.strip()  # Guardamos el valor del Host

                # Estructura de datos para guardar en JSON
                data = {
                    "url": request_url,
                    "cookies": cookies_dict
                }

                # Guardar en un archivo JSON (cambia la ruta a donde quieras guardar)
                with open("cookies.json", "a") as file:
                    json.dump(data, file, indent=4)
                    file.write("\n")  # Añadir una nueva línea para separar entradas

                print("Cookies guardadas en cookies.json")

    def menuItemExtractHeaders(self, event):
        # Obtener la información de la petición seleccionada
        messages = self._invocation.getSelectedMessages()
        for messageInfo in messages:
            request = messageInfo.getRequest()
            if request:
                analyzedRequest = self._helpers.analyzeRequest(request)
                headers = analyzedRequest.getHeaders()
                headers_dict = {}
                request_url = ""

                # Recorremos todos los headers
                for header in headers:
                    if ":" in header:
                        name, value = header.split(":", 1)
                        if name.strip().lower() == "host":
                            request_url = value.strip()  # Guardamos el valor del Host
                        else:
                            headers_dict[name.strip()] = value.strip()

                # Estructura de datos para guardar en JSON
                data = {
                    "url": request_url,
                    "headers": headers_dict
                }

                # Guardar en un archivo JSON (cambia la ruta a donde quieras guardar)
                with open("headers.json", "a") as file:
                    json.dump(data, file, indent=4)
                    file.write("\n")  # Añadir una nueva línea para separar entradas

                print("Headers guardados en headers.json")
