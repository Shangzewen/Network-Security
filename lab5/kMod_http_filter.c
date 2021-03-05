#include <linux/module.h>
#include <linux/kernel.h>
#include <linux/netfilter.h>
#include <linux/init.h>
#include <linux/netfilter_ipv4.h>
#include <linux/ip.h>
#include <linux/tcp.h>

static struct nf_hook_ops firewallHook;

unsigned int httpFilter(void *priv, struct sk_buff *skb, const struct nf_hook_state *state)
{
    struct iphdr *iph;
    struct tcphdr *tcph;
    iph = ip_hdr(skb);
    tcph = (void *)iph + iph->ihl * 4;

    // hardcode filter logic
    if (iph->protocol == IPPROTO_TCP && tcph->dest == htons(80) && ((unsigned char *)&iph->daddr)[0] == 157 && ((unsigned char *)&iph->daddr)[1] == 240 && ((unsigned char *)&iph->daddr)[2] == 13 && ((unsigned char *)&iph->daddr)[3] == 35)
    {
        printk(KERN_INFO "Dropping http packet to %d.%d.%d.%d\n", ((unsigned char *)&iph->daddr)[0], ((unsigned char *)&iph->daddr)[1], ((unsigned char *)&iph->daddr)[2], ((unsigned char *)&iph->daddr)[3]);
        return NF_DROP;
    }
    else
    {
        return NF_ACCEPT;
    }
}

int setUpFilter(void)
{
    printk(KERN_INFO "Registering a http filter. \n");
    firewallHook.hook = httpFilter;
    // use the netfilter hook
    firewallHook.hooknum = NF_INET_LOCAL_OUT;
    firewallHook.pf = PF_INET;
    firewallHook.priority = NF_IP_PRI_FIRST;

    // register the hook
    nf_register_hook(&firewallHook);
    return 0;
}
void removeFilter(void)
{
    printk(KERN_INFO "Http filter has been removed. \n");
    nf_unregister_hook(&firewallHook);
}

module_init(setUpFilter);
module_exit(removeFilter);

MODULE_LICENSE("GPL");