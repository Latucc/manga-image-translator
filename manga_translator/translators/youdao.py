
# -*- coding: utf-8 -*-
# import uuid
# import hashlib
import aiohttp
import hashlib
import base64
import time
import json
import requests
from Crypto.Cipher import AES
from Crypto.Util.Padding import unpad

from .common import CommonTranslator, InvalidServerResponse, MissingAPIKeyException
# from .keys import YOUDAO_APP_KEY, YOUDAO_SECRET_KEY
headers = {
    'Accept': 'application/json, text/plain, */*'
    ,'Accept-Encoding': 'gzip, deflate, br'
    ,'Accept-Language': 'zh-CN,zh;q=0.9'
    ,'Connection': 'keep-alive'
    ,'Content-Length': '252'
    ,'Content-Type': 'application/x-www-form-urlencoded'
    ,'Cookie': 'OUTFOX_SEARCH_USER_ID=-128580344@10.169.0.83; OUTFOX_SEARCH_USER_ID_NCOO=1344989105.8974342; _ntes_nnid=9b83b473d066e2e23751e2d758891587,1641266653081; search-popup-show=-1; __yadk_uid=Uby0XrclZI18dTgSjb55uEGqfHqTXOfo'
    ,'Host': 'dict.youdao.com'
    ,'Origin': 'https://fanyi.youdao.com'
    ,'Referer': 'https://fanyi.youdao.com/index.html'
    ,'Sec-Fetch-Dest': 'empty'
    ,'Sec-Fetch-Mode': 'cors'
    ,'Sec-Fetch-Site': 'same-site'
    ,'User-Agent': 'Mozilla/5.0 (Windows NT 6.3; WOW64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/86.0.4240.198 Safari/537.36'
}
def sha256_encode(signStr):
    hash_algorithm = hashlib.sha256()
    hash_algorithm.update(signStr.encode('utf-8'))
    return hash_algorithm.hexdigest()


def make_request(word, to = ''):
    form = {
        'from': 'auto'
        ,'to': to
        ,'dictResult': 'true'
        ,'keyid': 'webfanyi'
        ,'client': 'fanyideskweb'
        ,'product': 'webfanyi'
        ,'appVersion': '1.0.0'
        ,'vendor': 'web'
        ,'pointParam': 'client,mysticTime,product'
        ,'keyfrom': 'fanyi.web'
    }

    r = 'fanyideskweb'
    i = 'webfanyi'
    e = 'fsdsogkndfokasodnaso'
    t = int(round(time.time() * 1000))

    p = f"client={r}&mysticTime={t}&product={i}&key={e}"
    sign = hashlib.md5(p.encode('utf8')).hexdigest()

    form['i'] = word
    form['sign'] = sign
    form['mysticTime'] = t

    url = 'https://dict.youdao.com/webtranslate'

    res = requests.post(url=url, headers=headers, data=form)

    return res.text

def mytranslate(text):
    key = b'ydsecret://query/key/B*RGygVywfNBwpmBaZg*WT7SIOUP2T0C9WHMZN39j^DAdaZhAnxvGcCY6VYFwnHl'
    iv  = b'ydsecret://query/iv/C@lZe2YzHtZ2CYgaXKSVfsb7Y4QWHjITPPZ0nQp87fBeJ!Iv6v^6fvi2WN@bYpJ4'

    iv = hashlib.md5(iv).digest()
    key = hashlib.md5(key).digest()

    # CBC模式解密
    AES_decrypt = AES.new(key=key, mode=AES.MODE_CBC, iv=iv)
    # 返回数据转为byte
    t = base64.b64decode(text, b'-_')
    # 解码
    decrypted_data = AES_decrypt.decrypt(t)
    # 解码数据拆分
    unpadded_message = unpad(decrypted_data, AES.block_size).decode()
    # 解码数据转为json数据结构
    json_data = json.loads(unpadded_message)
    # res = json_data['dictResult']['ce']['word']['trs'][0]['#text']
    res=''
    for i in json_data['translateResult']:
        for j in i:
            res += j['tgt']
        # res+='\n'
    return res



class YoudaoTranslator(CommonTranslator):
    _LANGUAGE_CODE_MAP = {
        'CHS': 'zh-CHS',
        'JPN': "ja",
        'ENG': 'en',
        'KOR': 'ko',
        'VIN': 'vi',
        'CSY': 'cs',
        'NLD': 'nl',
        'FRA': 'fr',
        'DEU': 'de',
        'HUN': 'hu',
        'ITA': 'it',
        'PLK': 'pl',
        'PTB': 'pt',
        'ROM': 'ro',
        'RUS': 'ru',
        'ESP': 'es',
        'TRK': 'tr',
        'THA': 'th',
        'IND': 'id'
    }
    _API_URL = 'https://openapi.youdao.com/api'


    def __init__(self):
        super().__init__()
        # if not YOUDAO_APP_KEY or not YOUDAO_SECRET_KEY:
        #     raise MissingAPIKeyException('Please set the YOUDAO_APP_KEY and YOUDAO_SECRET_KEY environment variables before using the youdao translator.')

    async def _translate(self, from_lang, to_lang, queries):
        query_text = '\n'.join(queries)
        print(query_text)
        text = make_request(query_text, to='')
        # translate(text)
        rs=mytranslate(text)
        return rs.split('\n')


        # data = {}
        # query_text = '\n'.join(queries)
        # data['from'] = from_lang
        # data['to'] = to_lang
        # data['signType'] = 'v3'
        # curtime = str(int(time.time()))
        # data['curtime'] = curtime
        # salt = str(uuid.uuid1())
        # signStr = YOUDAO_APP_KEY + self._truncate(query_text) + salt + curtime + YOUDAO_SECRET_KEY
        # sign = sha256_encode(signStr)
        # data['appKey'] = YOUDAO_APP_KEY
        # data['q'] = query_text
        # data['salt'] = salt
        # data['sign'] = sign
        # #data['vocabId'] = "您的用户词表ID"
        #
        # result = await self._do_request(data)
        # result_list = []
        # if "translation" not in result:
        #     raise InvalidServerResponse(f'Youdao returned invalid response: {result}\nAre the API keys set correctly?')
        # for ret in result["translation"]:
        #     result_list.extend(ret.split('\n'))
        # return result_list

    def _truncate(self, q):
        if q is None:
            return None
        size = len(q)
        return q if size <= 20 else q[0:10] + str(size) + q[size - 10:size]



    async def _do_request(self, data):
        headers = {'Content-Type': 'application/x-www-form-urlencoded'}
        async with aiohttp.ClientSession() as session:
            async with session.post(self._API_URL, data=data, headers=headers) as resp:
                return await resp.json()



