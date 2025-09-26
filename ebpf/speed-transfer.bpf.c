

static inline void bpf_sock_ops_ipv4(struct bpf_sock_ops *skops) {
    struct sock_key key = {};
    int ret;

    extract_key4_from_ops(skops, &key);

    ret = sock_hash_update(skops, &sock_ops_map, &key, BPF_NOEXIST);
    if (ret != 0) {
        printk("sock_hash_update() failed, ret: %d\n", ret);
    }

    printk("sockmap: op %d, port %d --> %d\n", skops->op, skops->local_port, bpf_ntohl(skops->remote_port));
}

SEC("sockops")
int bpf_sockmap(struct bpf_sock_ops *skops) {
    switch (skops->op) {
        case BPF_SOCK_OPS_PASSIVE_ESTABLISHED_CB: // 被动建连
        case BPF_SOCK_OPS_ACTIVE_ESTABLISHED_CB:  // 主动建连
            if (skops->family == 2) {             // AF_INET
                bpf_sock_ops_ipv4(skops);         // 将 socket 信息记录到到 sockmap
            }
            break;
        default:
            break;
    }
    return 0;
}

// https://arthurchiao.art/blog/cracking-k8s-node-proxy/
// https://github.com/ArthurChiao/socket-acceleration-with-ebpf
// https://blog.csdn.net/lianhunqianr1/article/details/117937251
// https://www.cnblogs.com/haoee/p/16209788.html
// https://github.com/ArthurChiao/arthurchiao.github.io/blob/master/assets/code/cracking-k8s-node-proxy/
// file:///Users/acejilam/Desktop/blog/arthurchiao.art/blog/customize-tcp-initial-rto-with-bpf/index.html

#method 1
iptables -t nat -A OUTPUT -p tcp -d 1.1.1.1 --dport 80 -j REDIRECT --to-port 12345 -m comment --comment "docker-proxy"
for i in $(sudo iptables -t nat -L OUTPUT -n --line-numbers | grep docker-proxy | awk '{print $1}' | sort -r);
do
    sudo iptables -t nat -D OUTPUT $i
done
#method 2
iptables -t nat -A OUTPUT -p tcp -d 1.1.1.1 --dport 80 -j DNAT --to-destination 127.0.0.1:12345 -m comment --comment "docker-proxy"
for i in $(sudo iptables -t nat -L OUTPUT -n --line-numbers | grep docker-proxy | awk '{print $1}' | sort -r);
do
sudo iptables - t nat -
    D OUTPUT $i done
#method 3
        apt install -
    y ipvsadm ipvsadm - ln ipvsadm - D - t 1.1.1.1 : 80 ipvsadm - A - t 1.1.1.1 : 80 - s rr ipvsadm - a - t 1.1.1.1 : 80 - r 127.0.0.1 : 12345 - g
