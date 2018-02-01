#!/usr/bin/python
# -*- coding: UTF-8 -*-
# 目的用于分析学习mysqlbinlog文件的结构，学习mysql 验证是不是commit后才写binlog文件 @author:ryan0003
# 重写自 read_binlog.py @author: xiaozhong
#
import struct,time,datetime
import sys,decimal,getopt

'''column type '''
class column_type_dict:
    MYSQL_TYPE_DECIMAL=0
    MYSQL_TYPE_TINY=1
    MYSQL_TYPE_SHORT=2
    MYSQL_TYPE_LONG=3
    MYSQL_TYPE_FLOAT=4
    MYSQL_TYPE_DOUBLE=5
    MYSQL_TYPE_NULL=6
    MYSQL_TYPE_TIMESTAMP=7
    MYSQL_TYPE_LONGLONG=8
    MYSQL_TYPE_INT24=9
    MYSQL_TYPE_DATE=10
    MYSQL_TYPE_TIME=11
    MYSQL_TYPE_DATETIME=12
    MYSQL_TYPE_YEAR=13
    MYSQL_TYPE_NEWDATE=14
    MYSQL_TYPE_VARCHAR=15
    MYSQL_TYPE_BIT=16
    MYSQL_TYPE_TIMESTAMP2=17
    MYSQL_TYPE_DATETIME2=18
    MYSQL_TYPE_TIME2=19
    MYSQL_TYPE_JSON=245
    MYSQL_TYPE_NEWDECIMAL=246
    MYSQL_TYPE_ENUM=247
    MYSQL_TYPE_SET=248
    MYSQL_TYPE_TINY_BLOB=249
    MYSQL_TYPE_MEDIUM_BLOB=250
    MYSQL_TYPE_LONG_BLOB=251
    MYSQL_TYPE_BLOB=252
    MYSQL_TYPE_VAR_STRING=253
    MYSQL_TYPE_STRING=254
    MYSQL_TYPE_GEOMETRY=255

''''''

'''mysql_binlog_event start GTID_EVENT end XID_EVENT'''
class binlog_events:
    UNKNOWN_EVENT= 0
    START_EVENT_V3= 1
    QUERY_EVENT= 2
    STOP_EVENT= 3
    ROTATE_EVENT= 4
    INTVAR_EVENT= 5
    LOAD_EVENT= 6
    SLAVE_EVENT= 7
    CREATE_FILE_EVENT= 8
    APPEND_BLOCK_EVENT= 9
    EXEC_LOAD_EVENT= 10
    DELETE_FILE_EVENT= 11
    NEW_LOAD_EVENT= 12
    RAND_EVENT= 13
    USER_VAR_EVENT= 14
    FORMAT_DESCRIPTION_EVENT= 15
    XID_EVENT= 16
    BEGIN_LOAD_QUERY_EVENT= 17
    EXECUTE_LOAD_QUERY_EVENT= 18
    TABLE_MAP_EVENT = 19
    PRE_GA_WRITE_ROWS_EVENT = 20
    PRE_GA_UPDATE_ROWS_EVENT = 21
    PRE_GA_DELETE_ROWS_EVENT = 22
    WRITE_ROWS_EVENT = 23
    UPDATE_ROWS_EVENT = 24
    DELETE_ROWS_EVENT = 25
    INCIDENT_EVENT= 26
    HEARTBEAT_LOG_EVENT= 27
    IGNORABLE_LOG_EVENT= 28
    ROWS_QUERY_LOG_EVENT= 29
    WRITE_ROWS_EVENT = 30
    UPDATE_ROWS_EVENT = 31
    DELETE_ROWS_EVENT = 32
    GTID_LOG_EVENT= 33
    ANONYMOUS_GTID_LOG_EVENT= 34
    PREVIOUS_GTIDS_LOG_EVENT= 35
''''''

'''json type'''
class json_type:
    NULL_COLUMN = 251
    UNSIGNED_CHAR_COLUMN = 251
    UNSIGNED_SHORT_COLUMN = 252
    UNSIGNED_INT24_COLUMN = 253
    UNSIGNED_INT64_COLUMN = 254
    UNSIGNED_CHAR_LENGTH = 1
    UNSIGNED_SHORT_LENGTH = 2
    UNSIGNED_INT24_LENGTH = 3
    UNSIGNED_INT64_LENGTH = 8

    JSONB_TYPE_SMALL_OBJECT = 0x0
    JSONB_TYPE_LARGE_OBJECT = 0x1
    JSONB_TYPE_SMALL_ARRAY = 0x2
    JSONB_TYPE_LARGE_ARRAY = 0x3
    JSONB_TYPE_LITERAL = 0x4
    JSONB_TYPE_INT16 = 0x5
    JSONB_TYPE_UINT16 = 0x6
    JSONB_TYPE_INT32 = 0x7
    JSONB_TYPE_UINT32 = 0x8
    JSONB_TYPE_INT64 = 0x9
    JSONB_TYPE_UINT64 = 0xA
    JSONB_TYPE_DOUBLE = 0xB
    JSONB_TYPE_STRING = 0xC
    JSONB_TYPE_OPAQUE = 0xF

    JSONB_LITERAL_NULL = 0x0
    JSONB_LITERAL_TRUE = 0x1
    JSONB_LITERAL_FALSE = 0x2
''''''

BINLOG_FILE_HEADER = b'\xFE\x62\x69\x6E'
binlog_event_header_len = 19
binlog_event_fix_part = 13
binlog_quer_event_stern = 4
binlog_row_event_extra_headers = 2
read_format_desc_event_length = 56
binlog_xid_event_length = 8
table_map_event_fix_length = 8
fix_length = 8

class Echo(object):
    '''
    print binlog
    '''

    def Version(self, source_pos,binlog_ver, server_ver, create_time):
        curr_pos = self.readbinlog.file_seek()
        print(u'从位置{0:^8}，往后移动了{1:^8}个字节，当前位置{2:^8},获得版本信息======》版本信息：{3},数据库版本：{4}，创建时间{5}'
              .format(source_pos,56,curr_pos, binlog_ver, server_ver, create_time))

    def TractionHeader(self,source_pos, thread_id, database_name, sql_statement, timestamp,_pos):
        curr_pos = self.readbinlog.file_seek()
        move_pos = curr_pos - source_pos
        print(u'从位置{0:^8}，往后移动了{1:^8}个字节，当前位置{2:^8},QUERY_EVENT======》{3:^8} sthread id:{4:^8}  at pos:{5:^8}  database:{6:^8}   \
             statement:{7:^8}'.format(source_pos, move_pos, curr_pos,timestamp,thread_id, _pos,database_name, sql_statement ))
        #print '%s%2sthread id : %d  at pos : %d  database : %s   statement : %s' % (timestamp, '', thread_id, _pos,database_name, sql_statement)

    def Xid(self,source_pos, timestamp, xid_num,_pos):
        curr_pos = self.readbinlog.file_seek()
        move_pos = curr_pos - source_pos
        print(u'从位置{0:^8}，往后移动了{1:^8}个字节，当前位置{2:^8},Xid======》{3:^8} statement:COMMIT  xid:{4:^8}  at pos:{5:^8}'
              .format(source_pos, move_pos, curr_pos,timestamp, xid_num,_pos))
        #print '%s%2sstatement : COMMIT  xid : %s  at pos : %d' % (timestamp, '', xid_num,_pos)
        #print ''

    def Tablemap(self,source_pos, timestamp, tablename):
        curr_pos = self.readbinlog.file_seek()
        move_pos = curr_pos - source_pos
        print(u'从位置{0:^8}，往后移动了{1:^8}个字节，当前位置{2:^8},Tablemap======》{3:^8} sstatement:{3:^8}stablename :{4:^8}'
              .format(source_pos, move_pos, curr_pos, timestamp, tablename))
        #print '%s%2stablename : %s' % (timestamp, '', tablename)

    def Gtid(self,source_pos, timestamp, gtid,_pos):
        curr_pos = self.readbinlog.file_seek()
        move_pos = curr_pos - source_pos
        print(u'从位置{0:^8}，往后移动了{1:^8}个字节，当前位置{2:^8},GTID_LOG_EVENT======》{3:^8} GTID_NEXT:{4:<8} at pos : {5:^8}'
              .format(source_pos, move_pos, curr_pos, timestamp,gtid,_pos))
        #print '%s%2sGTID_NEXT : %s at pos : %d' % (timestamp, '', gtid,_pos)

    def TractionVlues(self, before_value=None, after_value=None, type=None):
        if before_value:
            print  '%s%s  before_value : %s  after_value : %s' % (u'======》生成数据', type, before_value, after_value)
        else:
            print  '%s%s  value : %s ' % (u'======》生成执数据', type, after_value)

class Read(Echo):
    def __init__(self,filename=None,pos=0):
        self.file_data = open(filename, 'rb')
        self.tell = self.file_data.tell()
        if pos == 0:
            read_byte = self.read_bytes(4)
            if read_byte != BINLOG_FILE_HEADER:
                print 'error : Is not a standard binlog file format'
                exit()
            else:
                result = struct.unpack('s3s', read_byte)
                print(u'从位置{0:^8}，往后移动了{1:^8}个字节，当前位置{2:^8}，获得魔数======》魔数为:{3}'.format(self.tell,4,self.file_data.tell(),result[1]))
        else:
            self.file_data.seek(pos,1)

    def read_int_be_by_size(self, size ,bytes=None):
        '''Read a big endian integer values based on byte number'''
        if bytes is None:
            if size == 1:
                return struct.unpack('>b', self.read_bytes(size))[0]
            elif size == 2:
                return struct.unpack('>h', self.read_bytes(size))[0]
            elif size == 3:
                return self.read_int24_be()
            elif size == 4:
                return struct.unpack('>i', self.read_bytes(size))[0]
            elif size == 5:
                return self.read_int40_be()
            elif size == 8:
                return struct.unpack('>l', self.read_bytes(size))[0]
        else:
            '''used for read new decimal'''
            if size == 1:
                return struct.unpack('>b', bytes[0:size])[0]
            elif size == 2:
                return struct.unpack('>h', bytes[0:size])[0]
            elif size == 3:
                return self.read_int24_be(bytes)
            elif size == 4:
                return struct.unpack('>i',bytes[0:size])[0]

    def read_int24_be(self,bytes=None):
        if bytes is None:
            a, b, c = struct.unpack('BBB', self.read_bytes(3))
        else:
            a, b, c = struct.unpack('BBB', bytes[0:3])
        res = (a << 16) | (b << 8) | c
        if res >= 0x800000:
            res -= 0x1000000
        return res

    def read_uint_by_size(self, size):
        '''Read a little endian integer values based on byte number'''
        if size == 1:
            return self.read_uint8()
        elif size == 2:
            return self.read_uint16()
        elif size == 3:
            return self.read_uint24()
        elif size == 4:
            return self.read_uint32()
        elif size == 5:
            return self.read_uint40()
        elif size == 6:
            return self.read_uint48()
        elif size == 7:
            return self.read_uint56()
        elif size == 8:
            return self.read_uint64()

    def read_uint24(self):
        a, b, c = struct.unpack("<BBB", self.read_bytes(3))
        return a + (b << 8) + (c << 16)

    def read_int24(self):
        a, b, c = struct.unpack("<bbb", self.read_bytes(3))
        return a + (b << 8) + (c << 16)

    def read_uint40(self):
        a, b = struct.unpack("<BI", self.read_bytes(5))
        return a + (b << 8)

    def read_int40_be(self):
        a, b = struct.unpack(">IB", self.read_bytes(5))
        return b + (a << 8)

    def read_uint48(self):
        a, b, c = struct.unpack("<HHH", self.read_bytes(6))
        return a + (b << 16) + (c << 32)

    def read_uint56(self):
        a, b, c = struct.unpack("<BHI", self.read_bytes(7))
        return a + (b << 8) + (c << 24)

    def read_bytes(self, count):
        try:
            return self.file_data.read(count)
        except:
            return None

    def file_seek(self):
        try:
            return self.file_data.tell()
        except:
            return None

    def read_uint64(self):
        read_byte = self.read_bytes(8)
        result, = struct.unpack('Q', read_byte)
        return result

    def read_int64(self):
        read_byte = self.read_bytes(8)
        result, = struct.unpack('q', read_byte)
        return result

    def read_uint32(self):
        read_byte = self.read_bytes(4)
        result, = struct.unpack('I', read_byte)
        return result

    def read_int32(self):
        read_byte = self.read_bytes(4)
        result, = struct.unpack('i', read_byte)
        return result

    def read_uint16(self):
        read_byte = self.read_bytes(2)
        result, = struct.unpack('H', read_byte)
        return result

    def read_int16(self):
        read_byte = self.read_bytes(2)
        result, = struct.unpack('h', read_byte)
        return result

    def read_uint8(self):
        read_byte = self.read_bytes(1)
        result, = struct.unpack('B', read_byte)
        return result

    def read_int8(self):
        read_byte = self.read_bytes(1)
        result, = struct.unpack('b', read_byte)
        return result

    def read_format_desc_event(self):
        binlog_ver, = struct.unpack('H',self.read_bytes(2))
        server_ver, = struct.unpack('50s',self.read_bytes(50))
        create_time, = struct.unpack('I',self.read_bytes(4))
        return binlog_ver,server_ver,create_time

    def __add_fsp_to_time(self, time, column):
        """Read and add the fractional part of time
        For more details about new date format:
        """
        microsecond,read = self.__read_fsp(column)
        if microsecond > 0:
            time = time.replace(microsecond=microsecond)
        return time,read

    def __read_fsp(self, column):
        read = 0
        if column == 1 or column == 2:
            read = 1
        elif column == 3 or column == 4:
            read = 2
        elif column == 5 or column == 6:
            read = 3
        if read > 0:
            microsecond = self.read_int_be_by_size(read)
            if column % 2:
                return int(microsecond / 10),read
            else:
                return microsecond,read

        return 0,0


    def __read_binary_slice(self, binary, start, size, data_length):
        """
        Read a part of binary data and extract a number
        binary: the data
        start: From which bit (1 to X)
        size: How many bits should be read
        data_length: data size
        """
        binary = binary >> data_length - (start + size)
        mask = ((1 << size) - 1)
        return binary & mask

    def __read_datetime2(self, column):
        """DATETIME
        1 bit  sign           (1= non-negative, 0= negative)
        17 bits year*13+month  (year 0-9999, month 0-12)
         5 bits day            (0-31)
         5 bits hour           (0-23)
         6 bits minute         (0-59)
         6 bits second         (0-59)
        ---------------------------
        40 bits = 5 bytes
        """
        data = self.read_int_be_by_size(5)
        year_month = self.__read_binary_slice(data, 1, 17, 40)
        try:
            t = datetime.datetime(
                year=int(year_month / 13),
                month=year_month % 13,
                day=self.__read_binary_slice(data, 18, 5, 40),
                hour=self.__read_binary_slice(data, 23, 5, 40),
                minute=self.__read_binary_slice(data, 28, 6, 40),
                second=self.__read_binary_slice(data, 34, 6, 40))
        except ValueError:
            return None
        __time,read = self.__add_fsp_to_time(t, column)
        return __time,read

    def __read_time2(self, column):
        """TIME encoding for nonfractional part:
         1 bit sign    (1= non-negative, 0= negative)
         1 bit unused  (reserved for future extensions)
        10 bits hour   (0-838)
         6 bits minute (0-59)
         6 bits second (0-59)
        ---------------------
        24 bits = 3 bytes
        """
        data = self.read_int_be_by_size(3)

        sign = 1 if self.__read_binary_slice(data, 0, 1, 24) else -1
        if sign == -1:
            '''
            negative integers are stored as 2's compliment
            hence take 2's compliment again to get the right value.
            '''
            data = ~data + 1

        microseconds,read = self.__read_fsp(column)
        t = datetime.timedelta(
            hours=sign*self.__read_binary_slice(data, 2, 10, 24),
            minutes=self.__read_binary_slice(data, 12, 6, 24),
            seconds=self.__read_binary_slice(data, 18, 6, 24),
            microseconds= microseconds
        )
        return t,read+3

    def __read_date(self):
        time = self.read_uint24()
        if time == 0:  # nasty mysql 0000-00-00 dates
            return None

        year = (time & ((1 << 15) - 1) << 9) >> 9
        month = (time & ((1 << 4) - 1) << 5) >> 5
        day = (time & ((1 << 5) - 1))
        if year == 0 or month == 0 or day == 0:
            return None

        date = datetime.date(
            year=year,
            month=month,
            day=day
        )
        return date

    def __read_new_decimal(self, precision,decimals):
        """Read MySQL's new decimal format introduced in MySQL 5"""
        '''
        Each multiple of nine digits requires four bytes, and the “leftover” digits require some fraction of four bytes.
        The storage required for excess digits is given by the following table. Leftover Digits	Number of Bytes

        Leftover Digits     Number of Bytes
        0	                0
        1	                1
        2	                1
        3	                2
        4	                2
        5	                3
        6	                3
        7	                4
        8	                4
        '''
        digits_per_integer = 9
        compressed_bytes = [0, 1, 1, 2, 2, 3, 3, 4, 4, 4]
        integral = (precision - decimals)
        uncomp_integral = int(integral / digits_per_integer)
        uncomp_fractional = int(decimals / digits_per_integer)
        comp_integral = integral - (uncomp_integral * digits_per_integer)
        comp_fractional = decimals - (uncomp_fractional
                                             * digits_per_integer)

        _read_bytes = (uncomp_integral*4) + (uncomp_fractional*4) + comp_fractional + comp_integral

        _data = bytearray(self.read_bytes(_read_bytes))
        value = _data[0]
        if value & 0x80 != 0:
            res = ""
            mask = 0
        else:
            mask = -1
            res = "-"
        _data[0] = struct.pack('<B', value ^ 0x80)

        size = compressed_bytes[comp_integral]
        if size > 0:
            value = self.read_int_be_by_size(size=size,bytes=_data) ^ mask
            res += str(value)

        for i in range(0, uncomp_integral):
            offset = 4 + size
            value = struct.unpack('>i', _data[offset-4:offset])[0] ^ mask
            res += '%09d' % value

        res += "."

        for i in range(0, uncomp_fractional):
            offset += 4
            value = struct.unpack('>i', _data[offset-4:offset])[0] ^ mask
            res += '%09d' % value

        size = compressed_bytes[comp_fractional]
        _size = -+(precision - offset)
        if size > 0:
            value = self.read_int_be_by_size(size=size,bytes=_data[_size:]) ^ mask
            res += '%0*d' % (comp_fractional, value)

        return decimal.Decimal(res),_read_bytes

    def __is_null(self, null_bitmap, position):
        bit = null_bitmap[int(position / 8)]
        if type(bit) is str:
            bit = ord(bit)
        return bit & (1 << (position % 8))

    '''parsing for json'''
    '''################################################################'''
    def read_binary_json(self, length):
        t = self.read_uint8()
        return self.read_binary_json_type(t, length)

    def read_binary_json_type(self, t, length):
        large = (t in (json_type.JSONB_TYPE_LARGE_OBJECT, json_type.JSONB_TYPE_LARGE_ARRAY))
        if t in (json_type.JSONB_TYPE_SMALL_OBJECT, json_type.JSONB_TYPE_LARGE_OBJECT):
            return self.read_binary_json_object(length - 1, large)
        elif t in (json_type.JSONB_TYPE_SMALL_ARRAY, json_type.JSONB_TYPE_LARGE_ARRAY):
            return self.read_binary_json_array(length - 1, large)
        elif t in (json_type.JSONB_TYPE_STRING,):
            return self.read_length_coded_pascal_string(1)
        elif t in (json_type.JSONB_TYPE_LITERAL,):
            value = self.read_uint8()
            if value == json_type.JSONB_LITERAL_NULL:
                return None
            elif value == json_type.JSONB_LITERAL_TRUE:
                return True
            elif value == json_type.JSONB_LITERAL_FALSE:
                return False
        elif t == json_type.JSONB_TYPE_INT16:
            return self.read_int16()
        elif t == json_type.JSONB_TYPE_UINT16:
            return self.read_uint16()
        elif t in (json_type.JSONB_TYPE_DOUBLE,):
            return struct.unpack('<d', self.read(8))[0]
        elif t == json_type.JSONB_TYPE_INT32:
            return self.read_int32()
        elif t == json_type.JSONB_TYPE_UINT32:
            return self.read_uint32()
        elif t == json_type.JSONB_TYPE_INT64:
            return self.read_int64()
        elif t == json_type.JSONB_TYPE_UINT64:
            return self.read_uint64()

        raise ValueError('Json type %d is not handled' % t)

    def read_binary_json_type_inlined(self, t):
        if t == json_type.JSONB_TYPE_LITERAL:
            value = self.read_uint16()
            if value == json_type.JSONB_LITERAL_NULL:
                return None
            elif value == json_type.JSONB_LITERAL_TRUE:
                return True
            elif value == json_type.JSONB_LITERAL_FALSE:
                return False
        elif t == json_type.JSONB_TYPE_INT16:
            return self.read_int16()
        elif t == json_type.JSONB_TYPE_UINT16:
            return self.read_uint16()
        elif t == json_type.JSONB_TYPE_INT32:
            return self.read_int32()
        elif t == json_type.JSONB_TYPE_UINT32:
            return self.read_uint32()

        raise ValueError('Json type %d is not handled' % t)

    def read_binary_json_object(self, length, large):
        if large:
            elements = self.read_uint32()
            size = self.read_uint32()
        else:
            elements = self.read_uint16()
            size = self.read_uint16()

        if size > length:
            raise ValueError('Json length is larger than packet length')

        if large:
            key_offset_lengths = [(
                self.read_uint32(),  # offset (we don't actually need that)
                self.read_uint16()   # size of the key
                ) for _ in range(elements)]
        else:
            key_offset_lengths = [(
                self.read_uint16(),  # offset (we don't actually need that)
                self.read_uint16()   # size of key
                ) for _ in range(elements)]

        value_type_inlined_lengths = [self.read_offset_or_inline(large)
                                      for _ in range(elements)]

        keys = [self.__read_decode(x[1]) for x in key_offset_lengths]

        out = {}
        for i in range(elements):
            if value_type_inlined_lengths[i][1] is None:
                data = value_type_inlined_lengths[i][2]
            else:
                t = value_type_inlined_lengths[i][0]
                data = self.read_binary_json_type(t, length)
            out[keys[i]] = data

        return out

    def read_binary_json_array(self, length, large):
        if large:
            elements = self.read_uint32()
            size = self.read_uint32()
        else:
            elements = self.read_uint16()
            size = self.read_uint16()

        if size > length:
            raise ValueError('Json length is larger than packet length')

        values_type_offset_inline = [self.read_offset_or_inline(large) for _ in range(elements)]

        def _read(x):
            if x[1] is None:
                return x[2]
            return self.read_binary_json_type(x[0], length)

        return [_read(x) for x in values_type_offset_inline]

    def read_offset_or_inline(self,large):
        t = self.read_uint8()

        if t in (json_type.JSONB_TYPE_LITERAL,
                 json_type.JSONB_TYPE_INT16, json_type.JSONB_TYPE_UINT16):
            return (t, None, self.read_binary_json_type_inlined(t))
        if large and t in (json_type.JSONB_TYPE_INT32, json_type.JSONB_TYPE_UINT32):
            return (t, None, self.read_binary_json_type_inlined(t))

        if large:
            return (t, self.read_uint32(), None)
        return (t, self.read_uint16(), None)

    def read_length_coded_pascal_string(self, size):
        """Read a string with length coded using pascal style.
        The string start by the size of the string
        """
        length = self.read_uint_by_size(size)
        return self.__read_decode(length)
    '''###################################################'''

    def read_header(self):
        '''binlog_event_header_len = 19
        timestamp : 4bytes
        type_code : 1bytes
        server_id : 4bytes
        event_length : 4bytes
        next_position : 4bytes
        flags : 2bytes
        '''
        read_byte = self.read_bytes(19)
        #print(read_byte)
        if read_byte:
            result = struct.unpack('=IBIIIH',read_byte)
            type_code,event_length,timestamp = result[1],result[3],result[0]
            #print type_code,event_length,timestamp
            return type_code,event_length,time.strftime('%Y-%m-%d %H:%M:%S',time.localtime(timestamp))
        else:
            return None,None,None

    def read_query_event(self,event_length):
        '''fix_part = 13:
                thread_id : 4bytes
                execute_seconds : 4bytes
                database_length : 1bytes
                error_code : 2bytes
                variable_block_length : 2bytes
            variable_part :
                variable_block_length = fix_part.variable_block_length
                database_name = fix_part.database_length
                sql_statement = event_header.event_length - 19 - 13 - variable_block_length - database_length - 4
        '''
        read_byte = self.read_bytes(binlog_event_fix_part)
        fix_result = struct.unpack('=IIBHH',read_byte)
        thread_id = fix_result[0]
        self.read_bytes(fix_result[4])
        read_byte = self.read_bytes(fix_result[2])
        database_name, = struct.unpack('%ds' % fix_result[2],read_byte)
        statement_length = event_length - binlog_event_fix_part - binlog_event_header_len \
                           - fix_result[4] - fix_result[2] - binlog_quer_event_stern
        read_byte = self.read_bytes(statement_length)
        _a,sql_statement, = struct.unpack('1s%ds' % (statement_length-1),read_byte)
        return thread_id,database_name,sql_statement

    def read_table_map_event(self,event_length):
        '''
        fix_part = 8
            table_id : 6bytes
            Reserved : 2bytes
        variable_part:
            database_name_length : 1bytes
            database_name : database_name_length bytes + 1
            table_name_length : 1bytes
            table_name : table_name_length bytes + 1
            cloums_count : 1bytes
            colums_type_array : one byte per column
            mmetadata_lenth : 1bytes
            metadata : .....(only available in the variable length field，varchar:2bytes，text、blob:1bytes,time、timestamp、datetime: 1bytes
                            blob、float、decimal : 1bytes, char、enum、binary、set: 2bytes(column type id :1bytes metadatea: 1bytes))
            bit_filed : 1bytes
            crc : 4bytes
            .........
        :param event_length:
        :return:
        '''
        self.read_bytes(table_map_event_fix_length)
        database_name_length, = struct.unpack('B',self.read_bytes(1))
        database_name,_a, = struct.unpack('%dss' % (database_name_length),self.read_bytes(database_name_length+1))
        table_name_length, = struct.unpack('B',self.read_bytes(1))
        table_name,_a, = struct.unpack('%dss' % table_name_length,self.read_bytes(table_name_length+1))
        colums = self.read_uint8()
        a = '='
        for i in range(colums):
            a += 'B'
        colums_type_id_list = list(struct.unpack(a,self.read_bytes(colums)))
        self.read_bytes(1)
        metadata_dict = {}
        bytes = 1
        for idex in range(len(colums_type_id_list)):
            if colums_type_id_list[idex] in [column_type_dict.MYSQL_TYPE_VAR_STRING,column_type_dict.MYSQL_TYPE_VARCHAR]:
                metadata = self.read_uint16()
                metadata_dict[idex] = 2 if metadata > 255 else 1
                bytes += 2
            elif colums_type_id_list[idex] in [column_type_dict.MYSQL_TYPE_BLOB,column_type_dict.MYSQL_TYPE_MEDIUM_BLOB,column_type_dict.MYSQL_TYPE_LONG_BLOB,
                                               column_type_dict.MYSQL_TYPE_TINY_BLOB,column_type_dict.MYSQL_TYPE_JSON]:
                metadata = self.read_uint8()
                metadata_dict[idex] = metadata
                bytes += 1
            elif colums_type_id_list[idex] in [column_type_dict.MYSQL_TYPE_TIMESTAMP2 ,column_type_dict.MYSQL_TYPE_DATETIME2 ,column_type_dict.MYSQL_TYPE_TIME2]:
                metadata = self.read_uint8()
                metadata_dict[idex] = metadata
                bytes += 1
            elif colums_type_id_list[idex] == column_type_dict.MYSQL_TYPE_NEWDECIMAL:
                precision = self.read_uint8()
                decimals = self.read_uint8()
                metadata_dict[idex] = [precision,decimals]
                bytes += 2
            elif colums_type_id_list[idex] in  [column_type_dict.MYSQL_TYPE_FLOAT ,column_type_dict.MYSQL_TYPE_DOUBLE]:
                metadata = self.read_uint8()
                metadata_dict[idex] = metadata
                bytes += 1
            elif colums_type_id_list[idex] in [column_type_dict.MYSQL_TYPE_STRING]:
                _type,metadata, = struct.unpack('=BB',self.read_bytes(2))
                colums_type_id_list[idex] = _type
                metadata_dict[idex] = metadata
                bytes += 2
        self.read_bytes(event_length - binlog_event_header_len - table_map_event_fix_length - 5 - database_name_length
                        - table_name_length - colums  - bytes)
        return database_name,table_name,colums_type_id_list,metadata_dict

    def read_gtid_event(self,event_length):
        self.read_bytes(1)
        uuid = self.read_bytes(16)
        gtid = "%s%s%s%s-%s%s-%s%s-%s%s-%s%s%s%s%s%s" %\
               tuple("{0:02x}".format(ord(c)) for c in uuid)
        gno_id = struct.unpack('Q',self.read_bytes(8))
        gtid += ":%d" % gno_id
        self.read_bytes(event_length - 1 - 16 - 8 - binlog_event_header_len)
        return gtid

    def read_xid_variable(self):
        read_byte = self.read_bytes(binlog_xid_event_length)
        xid_num, = struct.unpack('Q',read_byte)
        return xid_num

    def __read_decode(self,count):
        _value = self.read_bytes(count)
        return struct.unpack('%ds' % count,_value)[0]

    def read_row_event(self,source_pos,event_length,colums_type_id_list,metadata_dict,type):
        '''
        fixed_part: 10bytes
            table_id: 6bytes
            reserved: 2bytes
            extra: 2bytes
        variable_part:
            columns: 1bytes
            variable_sized: int((n+7)/8) n=columns.value
            variable_sized: int((n+7)/8) (for updata_row_event only)

            variable_sized: int((n+7)/8)
            row_value : variable size

            crc : 4bytes

        The The data first length of the varchar type more than 255 are 2 bytes
        '''
        self.read_bytes(fix_length+binlog_row_event_extra_headers)
        curr_pos = self.file_seek()
        move_pos = curr_pos - source_pos
        print(u"从位置{0:^8}，往后移动了{1:^8}个字节，当前位置{2:^8},fix_length+binlog_row_event_extra_headers======》fix_length:{3}+binlog_row_event_extra_headers:{4}={5}"
              .format(source_pos, move_pos, curr_pos,fix_length,binlog_row_event_extra_headers,fix_length+binlog_row_event_extra_headers))
        curr_pos1 = self.file_seek()
        columns = self.read_uint8()
        curr_pos2 = self.file_seek()
        move_pos = curr_pos2 - curr_pos1
        print(u"从位置{0:^8}，往后移动了{1:^8}个字节，当前位置{2:^8},获得columns字节长度======》columns字节长度:{3}"
        .format(curr_pos1, move_pos, curr_pos2,columns ))
        columns_length = (columns+7)/8
        self.read_bytes(columns_length)
        curr_pos3 = self.file_seek()
        move_pos = curr_pos3 - curr_pos2
        print(u"""从位置{0:^8}，往后移动了{1:^8}个字节，当前位置{2:^8},平移(columns+7)/8字节======》columns_length:{3} """
              .format(curr_pos2, move_pos, curr_pos3, columns_length))
        if type == 'UPDATE_ROWS_EVENT':
            self.read_bytes(columns_length)
            curr_pos4 = self.file_seek()
            move_pos = curr_pos4 - curr_pos3
            bytes = binlog_event_header_len + fix_length + binlog_row_event_extra_headers + 1 + columns_length + columns_length
            print(u"从位置{0:^8}，往后移动了{1:^8}个字节，当前位置{2:^8},发现UPDATE_ROWS_EVENT类型，平移(columns+7)/8字节======》columns_length:{3}"
                .format(curr_pos3, move_pos, curr_pos4, columns_length))
            print(u"{0:^21}获得bytes（binlog_event_header_len + fix_length + binlog_row_event_extra_headers + 1 + columns_length + columns_length）值:{1}"
                .format('',bytes))
        else:
            bytes = binlog_event_header_len + fix_length + binlog_row_event_extra_headers + 1 + columns_length
            print(u"{0:^21}获得bytes（binlog_event_header_len + fix_length + binlog_row_event_extra_headers + 1 + columns_length + columns_length）值:{1}"
                  .format('',bytes))
        __values = []
        while event_length - bytes > binlog_quer_event_stern:
            values = []
            curr_pos5 = self.file_seek()
            null_bit = self.read_bytes(columns_length)
            curr_pos6 = self.file_seek()
            move_pos = curr_pos6 - curr_pos5
            bytes += columns_length
            print(u"从位置{0:^8}，往后移动了{1:^8}个字节，当前位置{2:^8},获取字段类型，平移columns_length=(columns+7)/8字节======》获取字段类型"
            .format(curr_pos5, move_pos, curr_pos6))
            for idex in range(len(colums_type_id_list)):
                if self.__is_null(null_bit, idex):
                    values.append('Null')
                elif colums_type_id_list[idex] == column_type_dict.MYSQL_TYPE_TINY:
                    _curr_pos = self.file_seek()
                    try:
                        result = self.read_uint8()
                        values.append(result)
                    except:
                        result = self.read_int8()
                        values.append(result)
                    __curr_pos = self.file_seek()
                    move_pos = __curr_pos - _curr_pos
                    print(u"从位置{0:^8}，往后移动了{1:^8}个字节，当前位置{2:^8},获取字段类型MYSQL_TYPE_TINY，平移1======》获取字段值{3}"
                          .format(_curr_pos, move_pos, __curr_pos, result))
                    bytes += 1
                elif colums_type_id_list[idex] == column_type_dict.MYSQL_TYPE_SHORT:
                    _curr_pos = self.file_seek()
                    try:
                        result = self.read_uint16()
                        values.append(result)
                    except:
                        result = self.read_int16()
                        values.append(result)
                    __curr_pos = self.file_seek()
                    move_pos = __curr_pos - _curr_pos
                    print(u"从位置{0:^8}，往后移动了{1:^8}个字节，当前位置{2:^8},获取字段类型MYSQL_TYPE_SHORT，平移2======》获取字段值{3}"
                          .format(_curr_pos, move_pos, __curr_pos, result))
                    bytes += 2
                elif colums_type_id_list[idex] == column_type_dict.MYSQL_TYPE_INT24:
                    _curr_pos = self.file_seek()
                    try:
                        result = self.read_uint24()
                        values.append(result)
                    except:
                        result = self.read_int24()
                        values.append(result)
                    __curr_pos = self.file_seek()
                    move_pos = __curr_pos - _curr_pos
                    print(u"从位置{0:^8}，往后移动了{1:^8}个字节，当前位置{2:^8},获取字段类型MYSQL_TYPE_INT24，平移3======》获取字段值{3}"
                          .format(_curr_pos, move_pos, __curr_pos, result))
                    bytes += 3
                elif colums_type_id_list[idex] == column_type_dict.MYSQL_TYPE_LONG:
                    _curr_pos = self.file_seek()
                    try:
                        result = self.read_uint32()
                        values.append(result)
                    except:
                        result = self.read_int32()
                        values.append(result)
                    __curr_pos = self.file_seek()
                    move_pos = __curr_pos - _curr_pos
                    print(u"从位置{0:^8}，往后移动了{1:^8}个字节，当前位置{2:^8},获取字段类型MYSQL_TYPE_LONG，平移4======》获取字段值{3}"
                          .format(_curr_pos, move_pos, __curr_pos, result))
                    bytes += 4
                elif colums_type_id_list[idex] == column_type_dict.MYSQL_TYPE_LONGLONG:
                    _curr_pos = self.file_seek()
                    try:
                        values.append(self.read_uint64())
                    except:
                        values.append(self.read_int64())
                    __curr_pos = self.file_seek()
                    move_pos = __curr_pos - _curr_pos
                    print(u"从位置{0:^8}，往后移动了{1:^8}个字节，当前位置{2:^8},获取字段类型MYSQL_TYPE_LONGLONG，平移2======》获取字段值{3}"
                          .format(_curr_pos, move_pos, __curr_pos, result))
                    bytes += 8

                elif colums_type_id_list[idex] == column_type_dict.MYSQL_TYPE_NEWDECIMAL:
                    _curr_pos = self.file_seek()
                    _list = metadata_dict[idex]
                    decimals,read_bytes = self.__read_new_decimal(precision=_list[0],decimals=_list[1])
                    result = str(decimals)
                    values.append()
                    __curr_pos = self.file_seek()
                    move_pos = __curr_pos - _curr_pos
                    print(u"从位置{0:^8}，往后移动了{1:^8}个字节，当前位置{2:^8},获取字段类型MYSQL_TYPE_NEWDECIMAL======》获取字段值{3}"
                          .format(_curr_pos, move_pos, __curr_pos, result))
                    bytes += read_bytes

                elif colums_type_id_list[idex] in [column_type_dict.MYSQL_TYPE_DOUBLE ,column_type_dict.MYSQL_TYPE_FLOAT]:
                    _curr_pos = self.file_seek()
                    _read_bytes = metadata_dict[idex]
                    if _read_bytes == 8:
                        _values, = struct.unpack('<d',self.read_bytes(_read_bytes))
                    elif _read_bytes == 4:
                        _values, = struct.unpack('<f', self.read_bytes(4))
                    values.append(_values)
                    __curr_pos = self.file_seek()
                    move_pos = __curr_pos - _curr_pos
                    print(u"从位置{0:^8}，往后移动了{1:^8}个字节，当前位置{2:^8},获取字段类型MYSQL_TYPE_NEWDECIMAL======》获取字段值{3}"
                          .format(_curr_pos, move_pos, __curr_pos, _values))
                    bytes += _read_bytes

                elif colums_type_id_list[idex] == column_type_dict.MYSQL_TYPE_TIMESTAMP2:
                    _curr_pos = self.file_seek()
                    _time,read_bytes = self.__add_fsp_to_time(datetime.datetime.fromtimestamp(self.read_int_be_by_size(4)),metadata_dict[idex])
                    values.append(str(_time))
                    __curr_pos = self.file_seek()
                    move_pos = __curr_pos - _curr_pos
                    print(u"从位置{0:^8}，往后移动了{1:^8}个字节，当前位置{2:^8},获取字段类型MYSQL_TYPE_TIMESTAMP2======》获取字段值'{3}'"
                          .format(_curr_pos, move_pos, __curr_pos, str(_time)))
                    bytes += read_bytes + 4
                elif colums_type_id_list[idex] == column_type_dict.MYSQL_TYPE_DATETIME2:
                    _curr_pos = self.file_seek()
                    _time,read_bytes = self.__read_datetime2(metadata_dict[idex])
                    values.append(str(_time))
                    __curr_pos = self.file_seek()
                    move_pos = __curr_pos - _curr_pos
                    print(u"从位置{0:^8}，往后移动了{1:^8}个字节，当前位置{2:^8},获取字段类型MYSQL_TYPE_DATETIME2======》获取字段值'{3}'"
                          .format(_curr_pos, move_pos, __curr_pos, str(_time)))
                    bytes += 5 + read_bytes
                elif colums_type_id_list[idex] == column_type_dict.MYSQL_TYPE_YEAR:
                    _curr_pos = self.file_seek()
                    _date = self.read_uint8() + 1900
                    values.append(_date)
                    __curr_pos = self.file_seek()
                    move_pos = __curr_pos - _curr_pos
                    print(u"从位置{0:^8}，往后移动了{1:^8}个字节，当前位置{2:^8},获取字段类型MYSQL_TYPE_YEAR======》获取字段值'{3}'"
                          .format(_curr_pos, move_pos, __curr_pos, _date))
                    bytes += 1
                elif colums_type_id_list[idex] == column_type_dict.MYSQL_TYPE_DATE:
                    _curr_pos = self.file_seek()
                    _time = self.__read_date()
                    values.append(str(_time))
                    __curr_pos = self.file_seek()
                    move_pos = __curr_pos - _curr_pos
                    print(u"从位置{0:^8}，往后移动了{1:^8}个字节，当前位置{2:^8},获取字段类型MYSQL_TYPE_DATE======》获取字段值'{3}'"
                          .format(_curr_pos, move_pos, __curr_pos, _date))
                    bytes += 3

                elif colums_type_id_list[idex] == column_type_dict.MYSQL_TYPE_TIME2:
                    _curr_pos = self.file_seek()
                    _time,read_bytes = self.__read_time2(metadata_dict[idex])
                    bytes += read_bytes
                    values.append(str(_time))
                    __curr_pos = self.file_seek()
                    move_pos = __curr_pos - _curr_pos
                    print(u"从位置{0:^8}，往后移动了{1:^8}个字节，当前位置{2:^8},获取字段类型MYSQL_TYPE_TIME2======》获取字段值'{3}'"
                          .format(_curr_pos, move_pos, __curr_pos, _date))

                elif colums_type_id_list[idex] in [column_type_dict.MYSQL_TYPE_VARCHAR ,column_type_dict.MYSQL_TYPE_VAR_STRING ,column_type_dict.MYSQL_TYPE_BLOB,
                                                   column_type_dict.MYSQL_TYPE_TINY_BLOB,column_type_dict.MYSQL_TYPE_LONG_BLOB,column_type_dict.MYSQL_TYPE_MEDIUM_BLOB]:
                    _curr_pos = self.file_seek()
                    _metadata = metadata_dict[idex]
                    value_length = self.read_uint_by_size(_metadata)
                    '''
                    if _metadata == 1:
                        value_length = self.read_uint8()
                    elif _metadata == 2:
                        value_length = self.read_uint16()
                    elif _metadata == 3:
                        value_length = self.read_uint24()
                    elif _metadata == 4:
                        value_length = self.read_uint32()
                    '''
                    result = self.__read_decode(value_length)
                    values.append(result)
                    __curr_pos = self.file_seek()
                    move_pos = __curr_pos - _curr_pos
                    print(u"""从位置{0:^8}，往后移动了{1:^8}个字节，当前位置{2:^8},获取字段类型（MYSQL_TYPE_VARCHAR|MYSQL_TYPE_VAR_STRING|MYSQL_TYPE_BLOB|MYSQL_TYPE_TINY_BLOB|MYSQL_TYPE_LONG_BLOB|MYSQL_TYPE_MEDIUM_BLOB）======》获取字段值'{3}'"""
                          .format(_curr_pos, move_pos, __curr_pos, result))
                    bytes += value_length + _metadata
                elif colums_type_id_list[idex] in [column_type_dict.MYSQL_TYPE_JSON]:
                    _curr_pos = self.file_seek()
                    _metadata = metadata_dict[idex]
                    value_length = self.read_uint_by_size(_metadata)
                    result = self.read_binary_json(value_length)
                    values.append(result)
                    __curr_pos = self.file_seek()
                    move_pos = __curr_pos - _curr_pos
                    print(u"""从位置{0:^8}，往后移动了{1:^8}个字节，当前位置{2:^8},获取字段类型MYSQL_TYPE_JSON======》获取字段值'{3}'"""
                    .format(_curr_pos, move_pos, __curr_pos, result))
                    bytes += value_length + _metadata
                elif colums_type_id_list[idex] == column_type_dict.MYSQL_TYPE_STRING:
                    _curr_pos = self.file_seek()
                    _metadata = metadata_dict[idex]
                    if _metadata <= 255:
                        value_length = self.read_uint8()
                        result = self.__read_decode(value_length)
                        values.append(result)
                        _read = 1
                    else:
                        value_length = self.read_uint16()
                        result = self.__read_decode(value_length)
                        values.append(result)
                        _read = 2
                    __curr_pos = self.file_seek()
                    move_pos = __curr_pos - _curr_pos
                    print(u"""从位置{0:^8}，往后移动了{1:^8}个字节，当前位置{2:^8},获取字段类型MYSQL_TYPE_STRING======》获取字段值'{3}'"""
                          .format(_curr_pos, move_pos, __curr_pos, result))
                    bytes += value_length + _read
                elif colums_type_id_list[idex] == column_type_dict.MYSQL_TYPE_ENUM:
                    _curr_pos = self.file_seek()
                    _metadata = metadata_dict[idex]
                    if _metadata == 1:
                        result = '@'+str(self.read_uint8())
                        values.append()
                    elif _metadata == 2:
                        result = '@'+str(self.read_uint16())
                        values.append()
                    __curr_pos = self.file_seek()
                    move_pos = __curr_pos - _curr_pos
                    print(u"""从位置{0:^8}，往后移动了{1:^8}个字节，当前位置{2:^8},获取字段类型MYSQL_TYPE_ENUM======》获取字段值'{3}'"""
                          .format(_curr_pos, move_pos, __curr_pos, result))
                    bytes += _metadata

            if type == 'UPDATE_ROWS_EVENT':
                __values.append(values)
            else:
                super(Read,self).TractionVlues(after_value=values,type=type)
        _curr_pos = self.file_seek()
        self.read_bytes(event_length - bytes)
        __curr_pos = self.file_seek()
        move_pos = __curr_pos - _curr_pos
        print(u"""从位置{0:^8}，往后移动了{1:^8}个字节，当前位置{2:^8}======》无内容""").format(_curr_pos, move_pos, __curr_pos,)
        return __values

    def write_row_event(self,event_length,colums_type_id_list,metadata_dict,type):
        source_pos = self.file_seek()
        self.read_row_event(source_pos,event_length,colums_type_id_list,metadata_dict,type)

    def delete_row_event(self,event_length,colums_type_id_list,metadata_dict,type):
        source_pos = self.file_seek()
        self.read_row_event(source_pos,event_length, colums_type_id_list, metadata_dict,type)

    def update_row_event(self,event_length,colums_type_id_list,metadata_dict,type):
        source_pos = self.file_seek()
        values = self.read_row_event(source_pos,event_length,colums_type_id_list,metadata_dict,type)
        __values = [values[i:i+2] for i in xrange(0,len(values),2)]
        for i in range(len(__values)):
            super(Read,self).TractionVlues(before_value=__values[i][0],after_value=__values[i][1],type=type)

class CheckEvent(Echo):
    def __init__(self,filename=None,start_pos=0):
        self.cloums_type_id_list = None
        self.metadata_dict = None
        self._gtid = None
        self._thread_id_status = None
        self._pos = start_pos

        if filename is None:
            print 'NO SUCH FILE '
            sys.exit()
        pos = self._pos
        while True:
            try:
                self.readbinlog = Read(filename=filename,pos=pos)
                pos = self.__read()
            except Exception as e:
                pass


    def __read_event(self,type_code,event_length,execute_time):
        if type_code == binlog_events.FORMAT_DESCRIPTION_EVENT:
            source_pos = self.readbinlog.file_seek()
            binlog_ver, server_ver, create_time = self.readbinlog.read_format_desc_event()
            #print self.readbinlog.file_seek()
            self.Version(source_pos,binlog_ver, server_ver, create_time)
            source_pos = self.readbinlog.file_seek()
            move_pos = event_length - binlog_event_header_len - read_format_desc_event_length
            self.readbinlog.read_bytes(move_pos)
            curr_pos = self.readbinlog.file_seek()
            print(u"从位置{0:^8}，往后移动了{1:^8}个字节，当前位置{2:^8},保留字节======》无内容".format (source_pos,move_pos,curr_pos))
            #print self.readbinlog.file_seek()
        elif type_code == binlog_events.QUERY_EVENT:
            source_pos = self.readbinlog.file_seek()
            thread_id, database_name, sql_statement = self.readbinlog.read_query_event(event_length)
            self.TractionHeader(source_pos,thread_id, database_name, sql_statement, execute_time, self._pos)
            source_pos = self.readbinlog.file_seek()
            self.readbinlog.read_bytes(4)
            curr_pos = self.readbinlog.file_seek()
            print(u"从位置{0:^8}，往后移动了{1:^8}个字节，当前位置{2:^8},保留字节======》无内容".format(source_pos, 4,curr_pos ))
        elif type_code == binlog_events.XID_EVENT:
            source_pos = self.readbinlog.file_seek()
            xid_num = self.readbinlog.read_xid_variable()
            self.Xid(source_pos,execute_time, xid_num, self._pos)
            source_pos = self.readbinlog.file_seek()
            self.readbinlog.read_bytes(4)
            curr_pos = self.readbinlog.file_seek()
            print(u"从位置{0:^8}，往后移动了{1:^8}个字节，当前位置{2:^8},保留字节======》无内容".format(source_pos, 4, curr_pos))
        elif type_code == binlog_events.TABLE_MAP_EVENT:
            source_pos = self.readbinlog.file_seek()
            database_name, table_name, self.cloums_type_id_list, self.metadata_dict = self.readbinlog.read_table_map_event(
                event_length)
            self.Tablemap(source_pos, execute_time, table_name)
        elif type_code == binlog_events.GTID_LOG_EVENT:
            source_pos = self.readbinlog.file_seek()
            gtid = self.readbinlog.read_gtid_event(event_length)
            self.Gtid(source_pos,execute_time, gtid, self._pos)
            #print self.readbinlog.file_seek()
        elif type_code == binlog_events.WRITE_ROWS_EVENT:
            self.readbinlog.write_row_event(event_length, self.cloums_type_id_list, self.metadata_dict, 'WRITE_ROWS_EVENT')
        elif type_code == binlog_events.DELETE_ROWS_EVENT:
            self.readbinlog.delete_row_event(event_length, self.cloums_type_id_list, self.metadata_dict, 'DELETE_ROWS_EVENT')
        elif type_code == binlog_events.UPDATE_ROWS_EVENT:
            self.readbinlog.update_row_event(event_length, self.cloums_type_id_list, self.metadata_dict, 'UPDATE_ROWS_EVENT')
        else:
            #这里文件游标需要定位到头信息之前,即当前事务长度减去头文件信息。
            #print('event_length',event_length)
            source_pos = self.readbinlog.file_seek()
            move_pos = event_length - binlog_event_header_len
            self.readbinlog.read_bytes(move_pos)
            curr_pos = self.readbinlog.file_seek()
            print(u"从位置{0:^8}，往后移动了{1:^8}个字节，当前位置{2:^8},保留字节======》无内容".format(source_pos, move_pos, curr_pos))

    def __read_binlog(self,type_code=None,event_length=None,execute_time=None):
        if type_code is None and event_length is None and execute_time is None:
            source_pos = self.readbinlog.file_seek()
            type_code, event_length, execute_time, = self.readbinlog.read_header()
            curr_pos = self.readbinlog.file_seek()
            next_pos = curr_pos - binlog_event_header_len + event_length
            print(u'从位置{0:^8}，往后移动了{1:^8}个字节，当前位置{2:^8},获得事件头文件======》数据类型{3:^8},当前事件长度{4:^8}，开始时间{5},下一个位置为{6:^8}'
                  .format(source_pos,binlog_event_header_len,curr_pos, type_code, event_length, execute_time,next_pos))
        while True:
            self.__read_event(type_code=type_code,event_length=event_length,execute_time=execute_time)
            self._pos += event_length
            type_code, event_length, execute_time = self.readbinlog.read_header()
            if type_code is None:
                break
            curr_pos = self._pos + binlog_event_header_len
            next_pos = self._pos + event_length
            print(u'从位置{0:^8}，往后移动了{1:^8}个字节，当前位置{2:^8},获得事件头文件======》数据类型{3:^8},当前事件长度{4:^8}，开始时间{5},下一个位置为{6:^8}'
                   .format(self._pos,binlog_event_header_len,curr_pos,type_code,event_length,execute_time,next_pos))
            #print type_code, event_length, execute_time,self._pos

    def __read(self):
        self.__read_binlog()
        return self.readbinlog.file_seek()


if __name__ == '__main__':
    if len(sys.argv) == 2:
        mysql_binlog = sys.argv[1]
    else:
        print 'Usage : \n./analysis_mysqlbinlg.py <mysql-bin-log>'
        exit()

    CheckEvent(filename=mysql_binlog,start_pos=0)


    '''
    reader = open(mysql_binlog,'rb') #打开binlog文件
    chunk = reader.read(4)    # 往后移动4个字节，4个字节数据为.bin
    result = struct.unpack("=4c",chunk)
    print(result)
    chunk = reader.read(19)   # 往后读取19个字节,常量EVENT_HEADER_LEN
    result = struct.unpack('<IBIIIH', chunk)  #根据IBIIIH格式来读取数据，详细请查看python struct的用法,注意在binlog里面数据是倒序存储的所以使用'<'，这里可以取得日志的开始时间
                                                #数据类型15，server_id，该event的长度119，下一个事件的开始位置123，
    print("head:" ,result)
    chunk = reader.read(56)   # 往后读取56个字节,常量read_format_desc_event_length
    result = struct.unpack("H50sI",chunk)
    print("head:", result)
    chunk = reader.read(119-19-56) # 往后读取44个字节，该event的长度119-头文件长度-常量read_format_desc_event_length
    chunk = reader.read(19)  # 往后读取19个字节,常量EVENT_HEADER_LEN
    result = struct.unpack('<IBIIIH', chunk) #通过读取头文件信息，可以获取当前事件的长度为111,下一个事件开始位置234，当前事件类型为35
    print("head:", result)
    event_length  = int(result[3])
    reader.read(event_length - 19) # 读取该事件的数据信息，注意这里利用该事务的长度减去常量EVENT_HEADER_LEN获得
    chunk = reader.read(19)  # 往后读取19个字节,常量EVENT_HEADER_LEN
    result = struct.unpack('<IBIIIH', chunk)  # 通过读取头文件信息，可以获取当前事件的长度为65,下一个事件开始位置299，当前事件类型为33
    print("data:", result)
    event_length = int(result[3])
    reader.read(1)
    uuid = reader.read(16) # 往后读取16字节，获得uuid
    gtid = "%s%s%s%s-%s%s-%s%s-%s%s-%s%s%s%s%s%s" % tuple("{0:02x}".format(ord(c)) for c in uuid)
    gno_id = struct.unpack('Q', reader.read(8)) # 往后读取8字节
    print("data:%s:%d" % (gtid,gno_id[0]))
    reader.read(event_length - 1 - 16 - 8 - 19)
    chunk = reader.read(19)  # 往后读取19个字节,常量EVENT_HEADER_LEN
    result = struct.unpack('<IBIIIH', chunk)  # 通过读取头文件信息，可以获取当前事件的长度为215,下一个事件开始位置514，当前事件类型为2
    print(result)
    chunk = reader.read(13)                     # 通过常量binlog_event_fix_part=13
    result = struct.unpack('=IIBHH', chunk)    # 获得thread_id = 4 表名长度为8个字节，保留字节为45个
    print(result)
    reader.read(45)                             # 平移45个字节
    chunk = reader.read(8)                      # 根据上面的表名长度
    database_name, = struct.unpack('8s', chunk) # 读取8个字节，获得表名
    print(database_name)
    statement_length = 215 - 13 - 19 - 45 - 8 - 4 # 获得数据段字节长度，event_length215 - binlog_event_fix_part13 - binlog_event_header_len 19
                                                  # - 保留字节45 - 表名8 - 常量binlog_quer_event_stern4
    chunk = reader.read(statement_length)
    _a, sql_statement, = struct.unpack('1s%ds' % (statement_length - 1), chunk)
    print(_a, sql_statement)
    reader.read(4)                                # 平移4字节
    chunk = reader.read(19)                       # 通过读取头文件信息，可以获取当前事件的长度为65,下一个事件开始位置579，当前事件类型为33
    result = struct.unpack('<IBIIIH', chunk)
    print(result)
    event_length = int(result[3])
    reader.read(1)
    uuid = reader.read(16)  # 往后读取16字节，获得uuid
    gtid = "%s%s%s%s-%s%s-%s%s-%s%s-%s%s%s%s%s%s" % tuple("{0:02x}".format(ord(c)) for c in uuid)
    gno_id = struct.unpack('Q', reader.read(8))  # 往后读取8字节
    print("data:%s:%d" % (gtid, gno_id[0]))
    reader.read(event_length - 1 - 16 - 8 - 19)
    chunk = reader.read(19)  # 通过读取头文件信息，可以获取当前事件的长度为76,下一个事件开始位置655，当前事件类型为2
    result = struct.unpack('<IBIIIH', chunk)
    print(result)
    chunk = reader.read(13)  # 通过常量binlog_event_fix_part=13
    result = struct.unpack('=IIBHH', chunk)  # 获得thread_id = 4 表名长度为8个字节，保留字节为26个
    print(result)
    reader.read(26)
    chunk = reader.read(8)  # 根据上面的表名长度
    database_name, = struct.unpack('8s', chunk)  # 读取8个字节，获得表名
    print(database_name)
    statement_length = 76 - 13 - 19 - 26 - 8 - 4
    chunk = reader.read(statement_length)
    _a, sql_statement, = struct.unpack('1s%ds' % (statement_length - 1), chunk)
    print(_a, sql_statement)
    reader.read(4)  # 平移4字节
    chunk = reader.read(19)  # 通过读取头文件信息，可以获取当前事件的长度为77,下一个事件开始位置732，当前事件类型为19
    result = struct.unpack('<IBIIIH', chunk)
    print(result)
    chunk = reader.read(8)    # 平移table_map_event_fix_length=8常量
    database_name_length, = struct.unpack('B', reader.read(1))
    database_name, _a, = struct.unpack('%dss' % (database_name_length), reader.read(database_name_length + 1))
    table_name_length, = struct.unpack('B', reader.read(1))
    table_name, _a, = struct.unpack('%dss' % table_name_length, reader.read(table_name_length + 1))
    colums = struct.unpack('B', reader.read(1))
    a = '='
    for i in range(colums):
        a += 'B'
    colums_type_id_list = list(struct.unpack(a, reader.read(colums)))
    reader.read(1)
    metadata_dict = {}
    bytes = 1
    for idex in range(len(colums_type_id_list)):
        if colums_type_id_list[idex] in [column_type_dict.MYSQL_TYPE_VAR_STRING, column_type_dict.MYSQL_TYPE_VARCHAR]:
            metadata = read_uint16()
            metadata_dict[idex] = 2 if metadata > 255 else 1
            bytes += 2
        elif colums_type_id_list[idex] in [column_type_dict.MYSQL_TYPE_BLOB, column_type_dict.MYSQL_TYPE_MEDIUM_BLOB,
                                           column_type_dict.MYSQL_TYPE_LONG_BLOB,
                                           column_type_dict.MYSQL_TYPE_TINY_BLOB, column_type_dict.MYSQL_TYPE_JSON]:
            metadata = self.read_uint8()
            metadata_dict[idex] = metadata
            bytes += 1
        elif colums_type_id_list[idex] in [column_type_dict.MYSQL_TYPE_TIMESTAMP2,
                                           column_type_dict.MYSQL_TYPE_DATETIME2, column_type_dict.MYSQL_TYPE_TIME2]:
            metadata = self.read_uint8()
            metadata_dict[idex] = metadata
            bytes += 1
        elif colums_type_id_list[idex] == column_type_dict.MYSQL_TYPE_NEWDECIMAL:
            precision = self.read_uint8()
            decimals = self.read_uint8()
            metadata_dict[idex] = [precision, decimals]
            bytes += 2
        elif colums_type_id_list[idex] in [column_type_dict.MYSQL_TYPE_FLOAT, column_type_dict.MYSQL_TYPE_DOUBLE]:
            metadata = self.read_uint8()
            metadata_dict[idex] = metadata
            bytes += 1
        elif colums_type_id_list[idex] in [column_type_dict.MYSQL_TYPE_STRING]:
            _type, metadata, = struct.unpack('=BB', self.read_bytes(2))
            colums_type_id_list[idex] = _type
            metadata_dict[idex] = metadata
            bytes += 2
        reader.read(event_length - 19 - 8 - 5 - database_name_length
                        - table_name_length - colums - bytes)
            
'''


    '''
    reader = BinFileReader(mysql_binlog)
    binlog_header = reader.chars(Constant.BINLOG_HEADER_LEN)
    while True:
        event_header = EventHeader(reader)
        last_event_header = event_header
        if event_header.type_code == EventType.FORMAT_DESCRIPTION_EVENT:
            event_body = FormatDescEventData(reader, event_header)
            #print(str(event_body)+'_ff')
            retval['start_time'] = event_header.timestamp
        elif event_header.type_code == EventType.ROTATE_EVENT:
            event_body = RotateEvent(reader, event_header)
            #print(str(event_body) + '_fa')
            retval['end_time'] = event_header.timestamp
            retval['next_binlog'] = event_body.next_binlog
            break
        elif event_header.type_code == EventType.STOP_EVENT:
           event_body = StopEvent(reader, event_header)
           print(event_body)
           break
        else:
            reader.seek(event_header.event_length - 19, 1)
         '''

