

```
- 自建ca放入系统池
- 内置几种 证书域名是 docker.io, quay.io, 代理程序监听 12443 端口，使用这几个证书提供服务
- docker pull  --->  ebpf ---> 代理程序   // ebpf ,iptables
- 代理程序 ---> (dockerproxy.zetyun.cn)
- 然后将代理程序获得数据 返回 docker pull
```



- bpf_printk 5.8
- guard_ringbuf 待定
- tcx  6.6
