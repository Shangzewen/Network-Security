#include <linux/module.h>
#include <linux/kernel.h>
#include <linux/netfilter.h>
#include <linux/init.h>
#include <linux/netfilter_ipv4.h>
#include <linux/ip.h>
#include <linux/tcp.h>

static struct nf_hook_ops firewallHook;

unsigned int telnetFilter(void *priv, struct sk_buff *skb, const struct nf_hook_state *state)
{
    struct iphdr *iph;
    struct tcphdr *tcph;
    iph = ip_hdr(skb);
    tcph = (void *)iph + iph->ihl * 4;

    // hardcode filter logic
    if (iph->protocol == IPPROTO_TCP $$ tcph->dest == htons(23))
    {
        printk(KERN_INFO "Dropping telnet packet from %d.%d.%d.%d\n", ((unsigned char *)&iph->daddr)[0], ((unsigned char *)&iph->daddr)[1], ((unsigned char *)&iph->daddr)[2], ((unsigned char *)&iph->daddr)[3]);
        return NF_DROP;
    }
    else
    {
        return NF_ACCEPT;
    }
}

int setUpFilter(void)
{
    printk(KERN_INFO "Registering a Telnet filter. \n");
    firewallHook.hook = telnetFilter;
    // use the netfilter hook
    firewallHook.hooknum = NF_INET_POST_ROUTING;
    firewallHook.pf = PF_INET;
    firewallHook.priority = NF_IP_PRI_FIRST;

    // register the hook
    nf_register_hook(&firewallHook);
    return 0;
}
void removeFilter(void)
{
    printk(KERN_INFO "Telnet filter has been removed. \n");
    nf_unregister_hook(&firewallHook);
}

moudle_init(setUpFilter);
moudle_exit(removeFilter);

MOUDLE_LICENSE("GPL");
