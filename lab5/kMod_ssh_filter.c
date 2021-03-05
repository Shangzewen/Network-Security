#include <linux/module.h>
#include <linux/kernel.h>
#include <linux/netfilter.h>
#include <linux/init.h>
#include <linux/netfilter_ipv4.h>
#include <linux/ip.h>
#include <linux/tcp.h>

static struct nf_hook_ops firewallHook;

unsigned int sshFilter(void *priv, struct sk_buff *skb, const struct nf_hook_state *state)
{
    struct iphdr *iph;
    struct tcphdr *tcph;
    iph = ip_hdr(skb);
    tcph = (void *)iph + iph->ihl * 4;

    // hardcode filter logic
    // only allow 10.0.2.8 to ssh to machine A
    if (tcph->dest == htons(22) && ((unsigned char *)&iph->daddr)[0] == 10 && ((unsigned char *)&iph->daddr)[1] == 0 && ((unsigned char *)&iph->daddr)[2] == 2 && ((unsigned char *)&iph->daddr)[3] == 8)
    {
        printk(KERN_INFO "Accepting packet from %d.%d.%d.%d\n", ((unsigned char *)&iph->daddr)[0], ((unsigned char *)&iph->daddr)[1], ((unsigned char *)&iph->daddr)[2], ((unsigned char *)&iph->daddr)[3]);
        return NF_ACCEPT;
    }
    else
    {
        printk(KERN_INFO "Drop packet from %d.%d.%d.%d\n", ((unsigned char *)&iph->daddr)[0], ((unsigned char *)&iph->daddr)[1], ((unsigned char *)&iph->daddr)[2], ((unsigned char *)&iph->daddr)[3]);
        return NF_DROP;
    }
}

int setUpFilter(void)
{
    printk(KERN_INFO "Registering a ssh filter. \n");
    firewallHook.hook = sshFilter;
    // use the netfilter hook
    firewallHook.hooknum = NF_INET_PRE_ROUTING;
    firewallHook.pf = PF_INET;
    firewallHook.priority = NF_IP_PRI_FIRST;

    // register the hook
    nf_register_hook(&firewallHook);
    return 0;
}
void removeFilter(void)
{
    printk(KERN_INFO "ssh filter has been removed. \n");
    nf_unregister_hook(&firewallHook);
}

module_init(setUpFilter);
module_exit(removeFilter);

MODULE_LICENSE("GPL");