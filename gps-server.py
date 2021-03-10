#!/bin/python

"""
TCP Server for multithreaded (asynchronous) application.


This server is based on the work from:
https://medium.com/swlh/lets-write-a-chat-app-in-python-f6783a9ac170

万位GPS定位器数据解析、存储
"""

from socket import AF_INET, socket, SOCK_STREAM
from threading import Thread
from datetime import datetime
# import datetime
import math
import os
# import time
import re
import datetime as dt
from gps import conf
import requests


GT370_Lookup = conf.GT370_Lookup
# 电量、电压字典

elect_dict = conf.elect_dict

protocol_dict = conf.protocol_dict

hex_dict = {
    'start': '78',
    'stop_1': '0D',
    'stop_2': '0A'
}

LBS2GPS_INFO = conf.LBS2GPS_INFO

BAIDU_API_INFO = conf.BAIDU_API_INFO
PLV8_API_INFO = conf.PLV8_API_INFO


class CRC_GT370:
    def __init__(self, preset=0xFFFF, good_crc=False):
        self._preset = preset
        self._tab = GT370_Lookup
        self._good_crc = good_crc

    def _update_crc(self, crc, c):
        """
        Perform byte width CRC calulation using the lookup table
        """
        cc = 0xff & c

        # tmp = (crc >> 8) ^ cc
        # crc = (crc << 8) ^ self._tab[tmp & 0xff]

        crc = (crc >> 8) ^ self._tab[(crc ^ cc) & 0xff]
        crc = crc & 0xffff
        # print (format(crc, '04x'))

        return crc

    def crc(self, str):
        """
        Calculate the CRC from an ascii string
        """
        if self._good_crc:
            str = '\0\0' + str
        crc = self._preset
        for c in str:
            crc = self._update_crc(crc, ord(c))
        crc = ~crc & 0xffff
        print("CRC:", crc.to_bytes(2, byteorder='big'))
        return crc.to_bytes(2, byteorder='big')

    def crcb(self, i):
        """
        Calculate CRC of a series of bytes
        """
        if self._good_crc:
            i = bytearray(i)
            i.insert(0, 0)
            i.insert(0, 0)
        crc = self._preset
        for c in i:
            crc = self._update_crc(crc, c)
        crc = ~crc & 0xffff
        print("crcb:", crc.to_bytes(2, byteorder='big'))
        return crc.to_bytes(2, byteorder='big')


crc_itu = CRC_GT370()



def time_now_hex():
    """
    返回当前时间（UTC时间格式），6bits 16进制表示 20 06 11 22 16 41 -> 14060b161029(string)
    """
    time_now = (dt.datetime.now() - dt.timedelta(hours=8)).strftime('%Y%m%d%H%M%S')[2:]
    # time_now = (dt.datetime.now()).strftime('%Y%m%d%H%M%S')[2:]
    tmp = []
    for i in re.findall(r".{2}", time_now):
        if len(hex(int(i))[2:]) > 1:
            a = str(hex(int(i))[2:])
        else:
            a = "0" + str(hex(int(i))[2:])
        tmp.append(a)
    # print("tmp", tmp)
    time_now_hex = "".join(tmp)
    print("服务器回复校时时间（UTC）", repr("{0}".format(time_now_hex)))

    return "{0}".format(time_now_hex)


def str_to_hex(s):
    """
    查询指令M转换为16进制输出，M=VERSION#，res=56455253494f4e23
    """
    res = ''.join([hex(ord(c)).replace('0x', '') for c in s])
    # print(res)
    return res


def lbs2gps(mcc, mnc, lac, ci):
    """
    基站定位，GPS坐标转换
    """
    url = LBS2GPS_INFO['url']
    data = {
        "mcc": mcc,
        "mnc": mnc,
        "lac": lac,
        "ci": ci,
        "output": "json",
    }
    try:
        req = requests.get(url, params=data)
        resp = req.json()

        if resp['errcode'] == 0:
            print("GPS定位数据: ", resp)
            return {"lat": resp['lat'], "lon": resp['lon'], "address": resp['address']}
        if resp['errcode'] == 10001:
            print("基站定位数据失败：", resp)
            return {"lat": None, "lon": None, "address": None}
    except Exception as e:
        print(e)
        return {"lat": None, "lon": None, "address": None}


def make_content_response(start, packet_len, protocol, message_id, crc_code, stop):
    """
    This is just a wrapper to generate the complete response
    to a query, goven its content.
    It will apply to all packets where response is of the format:
    start-start-length-protocol-content-stop_1-stop_2.
    Other specific packets where length is replaced by counters
    will be treated separately.
    """
    a = (start + packet_len + protocol + message_id + crc_code + stop)
    # print("response", a)

    return a


def send_response(client, response):
    """
    Function to send a response packet to the client.
    """
    LOGGER('info', 'server_log.txt', addresses[client]['address'][0], addresses[client]['imei'], 'OUT', response)
    print("server to device -> data, type(data)", type(response), response)

    client.send(bytes.fromhex(response))


def LOGGER(event, filename, ip, client, type, data):
    """
    A logging function to store all input packets,
    as well as output ones when they are generated.

    There are two types of logs implemented:
        - a general (info) logger that will keep track of all
            incoming and outgoing packets,
        - a position (location) logger that will write to a
            file contianing only results og GPS or LBS data.
    """

    with open(os.path.join('./logs/', filename), 'a+') as log:
        if (event == 'info'):
            # TSV format of: Timestamp, Client IP, IN/OUT, Packet
            logMessage = datetime.now().strftime('%Y/%m/%d %H:%M:%S') + '\t' + ip + '\t' + client + '\t' + type + '\t'.join(str(data)) + \
                         '\n'
        # elif (event == 'location'):
        #     # TSV format of: Timestamp, Client IP, Location DateTime, GPS/LBS, Validity, Nb Sat, Latitude, Longitude, Accuracy, Speed, Heading
        #     logMessage = datetime.now().strftime('%Y/%m/%d %H:%M:%S') + '\t' + ip + '\t' + client + '\t' + '\t'.join(list(str(x) for x in data.values())) + '\n'
        log.write(logMessage)


def accept_incoming_connections():
    """
    接收客户端数据，为每一个客户端建立一个线程
    """

    while True:
        client, client_address = SERVER.accept()
        print('%s:%s has connected.' % client_address)

        # Initialize the dictionaries
        addresses[client] = {}
        positions[client] = {}

        # Add current client address into adresses
        addresses[client]['address'] = client_address
        Thread(target=handle_client, args=(client,)).start()


def handle_client(client):
    """
    客户端套接字作为参数，
    监听、处理数据包
    """

    # Initialize dictionaries for that client
    positions[client]['wifi'] = []
    positions[client]['gsm-cells'] = []
    positions[client]['gsm-carrier'] = {}
    positions[client]['gps'] = {}

    # 保持接收、分析数据包，直到设备发送断开信号
    # keepAlive = True
    while (True):

        # Handle socket errors with a try/except approach
        try:
            packet = client.recv(BUFSIZ)
            # 只接收非空数据包
            # packet: =====> b'xx\x11\x01\x08h\x12\x020B\t\x180 2\x02\x00\x05\x94(\r\n', x->ascii->120->0x78
            print("initial packet：=====>", packet)
            if (len(packet) > 0):
                print(datetime.now().strftime('%Y/%m/%d %H:%M:%S'), '[', addresses[client]['address'][0], ']', 'IN Hex :', packet.hex(),
                      '(length in bytes =', len(packet), ')')
                # 分析接收的报文，处理报文，判断是否关闭线程
                keepAlive = read_incoming_packet(client, packet)

                print("keepAlive:", keepAlive)
                LOGGER('info', 'server_log.txt', addresses[client]['address'][0], addresses[client]['imei'], 'IN', packet.hex())

                # Disconnect if client sent disconnect signal
                if (keepAlive is False):
                    print('[', addresses[client]['address'][0], ']', 'DISCONNECTED: socket was closed by client.')
                    client.close()
                    break

            # Close socket if recv() returns 0 bytes, i.e. connection has been closed
            else:
                print('[', addresses[client]['address'][0], ']', 'DISCONNECTED: socket was closed for an unknown reason.')
                client.close()
                break

                # Something went sideways... close the socket so that it does not hang
        except Exception as e:
            print('[', addresses[client]['address'][0], ']', 'ERROR: socket was closed due to the following exception:')
            print(e)
            client.close()
            break
    print("This thread is now closed.")


def read_incoming_packet(client, packet):
    """
    1、处理传入的数据包，标识他们所关联的协议；gps device -> server;
    2、重定向到响应函数，将响应函数的数据包发送到GPS终端；server -> gps device;
    3、响应函数由外部函数完成;

    返回True,线程保持连接；返回False，线程断开；

    """
    # 截去包的起始位(0x78 0x78 )和停止位(end 0x0d 0x0a)，返回列表
    packet_list = [packet.hex()[i:i + 2] for i in range(4, len(packet.hex()) - 4, 2)]
    print(" start to read_incoming_packet...", "packet_list:", packet_list)

    # DEBUG: Print the role of current packet
    protocol_name = protocol_dict['protocol'][packet_list[1]]
    protocol_method = protocol_dict['response_method'][protocol_name]
    print('The current packet is for protocol:', protocol_name, "protocol_code is :", packet_list[1], 'which has method:', protocol_method)
    # Get the protocol name and react accordingly

    try:
        if (protocol_name == 'login'):
            # 登录包 01，需要回复
            r = answer_login(client, packet_list)
            send_response(client, r)

        elif (protocol_name == 'ntp'):
            # 校时包 8a，需要回复
            r = answer_ntp(client, packet_list)
            send_response(client, r)

        elif (protocol_name == 'heartbeat'):
            # 心跳包 23，需要回复
            r = answer_heartbeat(client, packet_list)
            send_response(client, r)
            return True

        elif (protocol_name == 'gps_positioning' or protocol_name == 'gps_offline_positioning'):
            # GPS定位包,不需要回复
            answer_gps(client, packet_list)
            return True

        elif (protocol_name == 'lbs_base_station_msg'):
            # LBS多基站扩展信息包 28，不需要回复
            answer_lbs_base_station_msg(client, packet_list)
            return True

        elif (protocol_name == 'lbs_alarm'):
            # LBS报警信息包 19，不需要回复
            answer_lbs_alarm(client, packet_list)
            return True


        elif (protocol_name == 'status'):
            # Status can sometimes carry signal strength and sometimes not
            if (packet_list[0] == '06'):
                print('[', addresses[client]['address'][0], ']', 'STATUS : Battery =', int(packet_list[2], base=16), '; Sw v. =',
                      int(packet_list[3], base=16), '; Status upload interval =', int(packet_list[4], base=16))
            elif (packet_list[0] == '07'):
                print('[', addresses[client]['address'][0], ']', 'STATUS : Battery =', int(packet_list[2], base=16), '; Sw v. =',
                      int(packet_list[3], base=16), '; Status upload interval =', int(packet_list[4], base=16), '; Signal strength =',
                      int(packet_list[5], base=16))
            # Exit function without altering anything
            return (True)

        elif (protocol_name == 'hibernation'):
            # Exit function returning False to break main while loop in handle_client()
            print('[', addresses[client]['address'][0], ']', 'STATUS : Sent hibernation packet. Disconnecting now.')
            return (False)

        # elif (protocol_name == 'setup'):
        #     # TODO: HANDLE NON-DEFAULT VALUES
        #     r = answer_setup(packet_list, '0300', '00110001', '000000', '000000', '000000', '00', '000000', '000000', '000000', '00',
        #                      '0000',
        #                      '0000', ['', '', ''])
        #     send_response(client, r)

        elif (protocol_name == 'time'):
            r = answer_time(packet_list)
            send_response(client, r)

        elif (protocol_name == 'position_upload_interval'):
            r = answer_upload_interval(client, packet_list)
            send_response(client, r)

        else:
            return True
    except Exception as e:
        print(e)
        return False

    # r = online_command()

    # send_response(client, r)

    # Return True to avoid failing in main while loop in handle_client()
    # return True


# 登录包：01，需要回复
def answer_login(client, query):
    """
    协议号：01
    登录包回复
    起始位，包长度，协议号，信息序列号，错误校验（CRC），停止位
    78 78 |05 |01 | 00 05 |9f f8| 0D 0a
    包长度 = 协议号+信息内容（0）+信息序列号+错误校验
    """
    print("登录包 01")
    addresses[client]['imei'] = ''.join(query[2:10])[1:]
    addresses[client]['software_version'] = int(query[10], base=16)
    protocol = '01'

    # 信息序列号
    msg_id = ''.join(query[14:16])

    # 包长度
    packet_len_int = int(len(protocol) / 2 + len(msg_id) / 2 + 2)
    packet_len = [hex(packet_len_int)[2:] if len(hex(packet_len_int)[2:]) > 1 else '0' + hex(packet_len_int)[2:]][0]

    print("Detected IMEI :", addresses[client]['imei'], "and Sw v. :", addresses[client]['software_version'])

    # CRC校验
    crc_origi_code = str(packet_len) + str(protocol) + str(msg_id)
    crc_bytes = bytes.fromhex(crc_origi_code)

    # CRC 校验结果
    crc_code = crc_itu.crcb(i=crc_bytes).hex()
    print("登录包crc-response:", crc_code)

    r = hex_dict['start'] + hex_dict['start'] + packet_len + protocol + msg_id + crc_code + hex_dict['stop_1'] + hex_dict['stop_2']
    print("协议号：01，server to device response：", r)
    return r


# NTP校时包，8a，需要回复
def answer_ntp(client, query):
    """
    1、协议号：8a；
    2、用于开机终端向服务器自动请求时，解决开机未定位时间，时间定位错误
    3、device -> server:78 78 05 8A 00 06 88 29 0D 0A
    4、server -> device:78 78 0B 8A 0F 0C 1D 00 00 15 00 06 F0 86 0D 0A
    起始位，包长度，协议号，信息序列号，错误校验（CRC），停止位
    5、crc校验同 包长度 到 信息序列号的crc-itu值
    query: ['05', '8a', '00', '00', 'ed', '1f']
    """

    print("NTP 校时", client, query)
    protocol = '8a'
    # 包长度
    packet_len = '0b'

    # msg_time = '0f0c1d000015'
    # 服务器回复校时信息，UTC时间，年月日时分秒（转化为十进制）
    msg_time = time_now_hex()

    # 信息序列号
    msg_id = ''.join(query[2:4])
    print("msg_id:", msg_id)
    # msg_id = '0006'

    # CRC校验
    print(packet_len + protocol + msg_time + msg_id)
    crc_bytes = bytes.fromhex(packet_len + protocol + msg_time + msg_id)
    print("crc_bytes is:", crc_bytes)
    # s = str(bytes.fromhex(crc_str), encoding='gbk')

    crc_code = crc_itu.crcb(i=crc_bytes).hex()

    print("crc_bytes is:", crc_bytes, "crc_code:", crc_code)
    r = (hex_dict['start'] + hex_dict['start'] + packet_len + protocol + msg_time + msg_id + crc_code +
         hex_dict['stop_1'] + hex_dict['stop_2'])
    print("ntp response:", r)
    return r


# 心跳包，23，需要回复
def answer_heartbeat(client, query):
    print("心跳包，协议号23", "query:", query)
    print("当前系统时间：", datetime.now().strftime('%Y/%m/%d %H:%M:%S'))
    # 协议号
    protocol = '23'

    # 终端信息内容
    device_msg = format(int(''.join(query[2]), base=16), '0>8b')
    print(":终端信息内容,展示手机各种状态", device_msg)
    # 终端状态信息预期值为 11000000 表示GPS已定位

    # 电量等级
    power_level = round(int(''.join(query[3:5]), base=16) / 100, 2)
    print(type(power_level), power_level)
    print("电量等级(电压等级)", power_level, "V", "电量", elect_dict[str(power_level)], "%")

    # GSM 手机信号强度
    GSM_level = query[5]
    print("GSM手机信号强度：", GSM_level)

    msg_id = ''.join(query[8:10])
    print("信息序列号：", msg_id)

    # 包长度
    packet_len_int = int(len(msg_id) / 2 + 3)
    packet_len = [hex(packet_len_int)[2:] if len(hex(packet_len_int)[2:]) > 1 else '0' + hex(packet_len_int)[2:]][0]

    crc_bytes = bytes.fromhex(str(packet_len) + str(protocol) + str(msg_id))

    crc_code = crc_itu.crcb(i=crc_bytes).hex()

    print("CRC校验结果:", crc_code)
    # 心跳包回复

    r = (hex_dict['start'] + hex_dict['start'] + packet_len + protocol + msg_id + crc_code + hex_dict['stop_1'] + hex_dict['stop_2'])

    print("心跳包回复：", r)

    return r


# GPS定位包，22，不需要回复
def answer_gps(client, query):
    """
    GPS定位信号，协议号22，不需要回复
    """
    # query = packet_list
    # Read protocol
    # 协议号

    protocol = '22'

    # 当前时间
    print("Gps定位包")
    # date_now = ''.join([format(int(x, base=16), '02d') for x in query[2:8]])
    # print("定位包反馈当前时间：", date_now)
    # gps_data_length = int(query[8][0], base=16)
    # gps_nb_sat = int(query[8][1], base=16)

    gps_latitude = int(''.join(query[9:13]), base=16) / (30000 * 60)
    gps_longitude = int(''.join(query[13:17]), base=16) / (30000 * 60)
    print("经纬度：", gps_latitude, gps_longitude)

    # Speed is on the next byte
    gps_speed = int(query[17], base=16)
    print("当前速度：", gps_speed)
    # Last two bytes contain flags in binary that will be interpreted
    gps_flags = format(int(''.join(query[18:20]), base=16), '0>16b')
    print("gps_flags:", gps_flags)
    position_is_valid = gps_flags[3]
    # Flip sign of GPS latitude if South, longitude if West
    if (gps_flags[4] == '1'):
        gps_latitude = -gps_latitude
    if (gps_flags[5] == '0'):
        gps_longitude = -gps_longitude
    gps_heading = int(''.join(gps_flags[6:]), base=2)

    print("gps_heading:", gps_heading, gps_latitude, gps_longitude)
    print("全局imei:", addresses[client]['imei'])

    locations = str(gps_latitude) + ',' + str(gps_longitude)

    addresse = baidugps(locations)

    gpsdata = {"imei": addresses[client]['imei'], "gpstype": "gps", "lat": gps_latitude, "lon": gps_longitude,
               "address": addresse}
    print("*" * 20)
    print(gpsdata)

    # 线上环境使用，调用PLV函数，将GPS定位数据插入表中
    # insert_loaction(gpsdata)
    LOGGER('info', 'gps-locations.txt', addresses[client]['address'][0], addresses[client]['imei'], 'IN', gpsdata)

    return None


def baidugps(location):
    url = BAIDU_API_INFO['url']
    data = {
        "ak":BAIDU_API_INFO['ak'],
        "coordtype": "wgs84ll",
        "output": "json",
        "location": location,
    }
    try:
        req = requests.get(url, params=data)
        resp = req.json()
        print(resp['result']['formatted_address'])
        print(resp['result']['location'])
        return resp['result']['formatted_address']

    except Exception as e:
        print(e)


def insert_loaction(gpsdata):
    url = PLV8_API_INFO['url']
    payload = {
        "id": "1",
        "jsonrpc": "2.0",
        "method": "callrpc",
        "params": {
            "columns": gpsdata,
            "context": "",
            "method": PLV8_API_INFO['method'],
            "pkey": "",
            "table": ""
        }
    }
    try:
        req = requests.post(url, json=payload)
        resp = req.json()
        print(resp)
        if resp['result']['message'][0]["code"] == 1:
            print("定位数据插入成功！")
    except Exception as e:
        print(e)


# 基站定位包，不需要回复
def answer_lbs_base_station_msg(client, query):
    """
    协议号：28
    """
    protocol = query[1]

    # {"lat": None, "lon": None, "address": None}

    print("LBS基站信号：", query)
    mcc = int(''.join(query[8:10]), base=16)
    mnc = int(''.join(query[10]), base=16)
    lac = int(''.join(query[11:13]), base=16)
    ci = int(''.join(query[13:16]), base=16)
    print("基站定位，imei：", addresses[client]['imei'])

    lbsdata = lbs2gps(mcc, mnc, lac, ci)

    lbsdata.update({"imei": addresses[client]['imei'], "gpstype": "gps"})

    print("*" * 20)
    print(lbsdata)
    LOGGER('info', 'gps-locations.txt', addresses[client]['address'][0], addresses[client]['imei'], 'IN', lbsdata)
    # 定位类型:基站定位
    # insert_loaction(lbsdata)

    return None


# 基站报警包，不需要回复
def answer_lbs_alarm(client, query):
    """
    协议号：19
    """

    protocol = query[1]
    print(client)
    print("LBS报警包：", query)
    mcc = int(''.join(query[2:4]), base=16)
    mnc = int(''.join(query[4]), base=16)
    lac = int(''.join(query[5:7]), base=16)
    ci = int(''.join(query[7:10]), base=16)

    lbs2gps(mcc, mnc, lac, ci)

    lbsdata = lbs2gps(mcc, mnc, lac, ci)

    lbsdata.update({"imei": addresses[client]['imei'], "gpstype": "gps"})

    print("*" * 20)
    print(lbsdata)

    LOGGER('info', 'gps-locations.txt', addresses[client]['address'][0], addresses[client]['imei'], 'IN', lbsdata)
    return None


# def answer_setup(query, uploadIntervalSeconds, binarySwitch, alarm1, alarm2, alarm3, dndTimeSwitch, dndTime1, dndTime2, dndTime3,
#                  gpsTimeSwitch, gpsTimeStart, gpsTimeStop, phoneNumbers):
#     """
#     Synchronous setup is initiated by the device who asks the server for
#     instructions.
#     These instructions will consists of bits for different flags as well as
#     alarm clocks ans emergency phone numbers.
#     """
#
#     # Read protocol
#     protocol = query[1]
#
#     # Convert binarySwitch from byte to hex
#     binarySwitch = format(int(binarySwitch, base=2), '02X')
#
#     # Convert phone numbers to 'ASCII' (?) by padding each digit with 3's and concatenate
#     for n in range(len(phoneNumbers)):
#         phoneNumbers[n] = bytes(phoneNumbers[n], 'UTF-8').hex()
#     phoneNumbers = '3B'.join(phoneNumbers)
#
#     # Build response
#     response = uploadIntervalSeconds + binarySwitch + alarm1 + alarm2 + alarm3 + dndTimeSwitch + dndTime1 + dndTime2 + dndTime3 + gpsTimeSwitch + gpsTimeStart + gpsTimeStop + phoneNumbers
#     r = make_content_response(hex_dict['start'] + hex_dict['start'], protocol, response, hex_dict['stop_1'] + hex_dict['stop_2'])
#     return (r)


def answer_time(query):
    """
    Time synchronization is initiated by the device, which expects a response
    contianing current datetime over 7 bytes: YY YY MM DD HH MM SS.
    This function is a wrapper to generate the proper response
    """

    # Read protocol
    protocol = query[1]

    # Get current date and time into the pretty-fied hex format
    response = get_hexified_datetime(truncatedYear=False)

    # Build response
    r = make_content_response(hex_dict['start'] + hex_dict['start'], protocol, response, hex_dict['stop_1'] + hex_dict['stop_2'])
    return (r)


# 在线命令，主动发送
def online_command():
    """
    在线指令 服务器下发在线指令控制终端执行相应任务，终端接收后 回复执行结果给服务器；
    :return:78 78 0E 80 08 00 00 00 00 73 6F 73 23 00 01 6D 6A 0D 0A “M = sos#”

    """
    # 查询版本，M = 'VERSION#'
    # M = 'VERSION#'
    M = 'PARAM#'
    # M = 'MODE#'
    # M = 'WHERE#'

    M = 'WF,OFF#'
    M2hex = str_to_hex(M)
    # 指令长度
    Mlen = len(M)
    # 协议号
    protocol = '80'
    # 信息序列号
    msg_id = '0001'
    packet_len_int = int(1 + (5 + Mlen) + 2 + 2)
    commd_len_int = int(4 + len(M))
    # 包长度=协议号+信息内容+信息序列号+错误校验
    packet_len = [hex(packet_len_int)[2:] if len(hex(packet_len_int)[2:]) > 1 else '0' + hex(packet_len_int)[2:]][0]
    commd_len = [hex(commd_len_int)[2:] if len(hex(commd_len_int)[2:]) > 1 else '0' + hex(commd_len_int)[2:]][0]
    # 信息内容 = 指令长度+服务器标志位+指令内容，语言不要
    msg = commd_len + '00000000' + M2hex

    # CRC校验,包长度-协议号-信息内容-信息序列号的CRC-ITU值
    crc_origi_code = str(packet_len) + str(protocol) + str(msg) + str(msg_id)
    crc_bytes = bytes.fromhex(crc_origi_code)

    # CRC 校验结果
    crc_code = crc_itu.crcb(i=crc_bytes).hex()
    print("***", packet_len_int, "***", packet_len, "***", msg)
    print("在线指令crc校验结果: ", crc_code)

    r = hex_dict['start'] + hex_dict['start'] + packet_len + protocol + msg + msg_id + crc_code + hex_dict['stop_1'] + hex_dict['stop_2']
    print("r", r)
    # M = 'VERSION#'
    # r = '787812800c0000000056455253494f4e23000164a50D0A'
    # r = '78780E800800000000736F732300016D6A0D0A'
    print("在线指令：", r)

    return r


def answer_upload_interval(client, query):
    """
    Whenever the device received an SMS that changes the value of an upload interval,
    it sends this information to the server.
    The server should answer with the exact same content to acknowledge the packet.
    """

    # Read protocol
    protocol = query[1]

    # Response is new upload interval reported by device (HEX formatted, no need to alter it)
    response = ''.join(query[2:4])

    r = make_content_response(hex_dict['start'] + hex_dict['start'], protocol, response, hex_dict['stop_1'] + hex_dict['stop_2'])
    return (r)


def get_hexified_datetime(truncatedYear):
    """
    Make a fancy function that will return current GMT datetime as hex
    concatenated data, using 2 bytes for year and 1 for the rest.
    The returned string is YY YY MM DD HH MM SS if truncatedYear is False,
    or just YY MM DD HH MM SS if truncatedYear is True.
    """

    # Get current GMT time into a list
    if (truncatedYear):
        dt = datetime.utcnow().strftime('%y-%m-%d-%H-%M-%S').split("-")
    else:
        dt = datetime.utcnow().strftime('%Y-%m-%d-%H-%M-%S').split("-")

    # Then convert to hex with 2 bytes for year and 1 for the rest
    dt = [format(int(x), '0' + str(len(x)) + 'X') for x in dt]
    return (''.join(dt))


# Details about host server
HOST = '0.0.0.0'
PORT = 5060
BUFSIZ = 4096
ADDR = (HOST, PORT)

# Initialize socket
SERVER = socket(AF_INET, SOCK_STREAM)
SERVER.bind(ADDR)

# Store client data into dictionaries
addresses = {}
positions = {}

if __name__ == '__main__':
    SERVER.listen(5)
    print("Waiting for connection...")
    ACCEPT_THREAD = Thread(target=accept_incoming_connections)
    ACCEPT_THREAD.start()
    ACCEPT_THREAD.join()
    SERVER.close()
