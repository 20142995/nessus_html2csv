#!/usr/bin/env python3
# -*- coding: UTF-8 -*-

import csv
import os

from lxml import etree
        
def parse_nessus_html(html_file):
    
    vul_list = []
    Plugin_ID,CVE,CVSS,Risk,Host,Protocol,Port,Name,Synopsis,Description,Solution,See_Also,Plugin_Output = "None","None","None","None","None","None","None","None","None","None","None","None","None"
    html = etree.parse(html_file,etree.HTMLParser())
    for div in html.xpath('/html/body/div[1]/div[3]/div'):
        if div.xpath('@style') == ["font-size: 22px; font-weight: bold; padding: 10px 0;"]:
            Host = div.text
            print(Host)
        elif div.xpath('@onmouseover') == ["this.style.cursor='pointer'"]:
            Plugin_ID,Name = div.text.split('-',1)
        elif div.xpath('@class') == ["section-wrapper"]:
            try:
                Synopsis = div.xpath('div[contains(text(),"Synopsis")]/following-sibling::*[1]/text()')[0].strip()
            except Exception as e:
                print(e)
            try:
                Description = div.xpath('div[contains(text(),"Description")]/following-sibling::*[1]/text()')[0].strip()
            except Exception as e:
                print(e)
            try:
                See_Also = div.xpath('string(div[contains(text(),"See Also")]/following-sibling::*[1])').strip()
            except Exception as e:
                print(e)
            try:
                Solution = div.xpath('div[contains(text(),"Solution")]/following-sibling::*[1]/text()')[0].strip()
            except Exception as e:
                print(e)    
            try:
                Risk = div.xpath('div[contains(text(),"Risk Factor")]/following-sibling::*[1]/text()')[0].strip()
            except Exception as e:
                print(e)  
            try:
                Protocol,Port = div.xpath("h2/text()")[0].strip().split("/")
            except Exception as e:
                print(e)
            try:
                Plugin_Output = div.xpath('string(div[@style="box-sizing: border-box; width: 100%; background: #eee; font-family: monospace; padding: 20px; margin: 5px 0 20px 0;"])').strip()
            except Exception as e:
                print(e)  
            CVE = "\n".join([cve.xpath('string(following-sibling::*[1])') for cve in div.xpath('div[contains(text(),"References")]/following-sibling::*[1]/table/tbody/tr/td[contains(text(),"CVE")]')])
            vul_list.append([Plugin_ID,CVE,CVSS,Risk,Host,Protocol,Port,Name,Synopsis,Description,Solution,See_Also,Plugin_Output])
    return vul_list
    
def deal_report(html_file):
    print("open {}".format(html_file))
    vul_list = parse_nessus_html(html_file)
    vul_title = ['Plugin ID','CVE','CVSS','Risk','Host','Protocol','Port','Name','Synopsis','Description','Solution','See Also','Plugin Output']
    rows = [vul_title,] + vul_list
    
    csv_file = os.path.join("report",html_file.replace(".html",".csv"))
    if not os.path.exists("report"):
        os.mkdir("report")

    with open(csv_file, 'w',newline='') as csvfile:
        csvwriter = csv.writer(csvfile,dialect='excel')
        csvwriter.writerows(rows)
    print("write {}".format(csv_file))
    
if __name__ == '__main__':
    for file in os.listdir():
        if not file.endswith('.html'):continue
        try:
            deal_report(file)
        except Exception as e:
            print(e)

    
