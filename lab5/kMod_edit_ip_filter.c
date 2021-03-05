#include <linux/module.h>
#include <linux/kernel.h>
#include <linux/netfilter.h>
#include <linux/init.h>
#include <linux/netfilter_ipv4.h>
#include <linux/ip.h>
#include <linux/tcp.h>

static struct nf_hook_ops firewallHook;

unsigned int editipFilter(void *priv, struct sk_buff *skb, const struct nf_hook_state *state)
{
    struct iphdr *iph;
    struct tcphdr *tcph;
    iph = ip_hdr(skb);
    tcph = (void *)iph + iph->ihl * 4;

    // hardcode filter logic
    // edit all the src ip address to 1.2.3.4
    if (iph->protocol == IPPROTO_ICMP)
    {
        printk(KERN_INFO "Editing ICMP packet from %d.%d.%d.%d\n", ((unsigned char *)&iph->saddr)[0], ((unsigned char *)&iph->saddr)[1], ((unsigned char *)&iph->saddr)[2], ((unsigned char *)&iph->saddr)[3]);
        ((unsigned char *)&iph->saddr)[0] = 1;
        ((unsigned char *)&iph->saddr)[1] = 2;
        ((unsigned char *)&iph->saddr)[2] = 3;
        ((unsigned char *)&iph->saddr)[3] = 4;
        skb->ip_summed = 1;
        return NF_ACCEPT;
    }
    else
    {
        return NF_DROP;
    }
}

int setUpFilter(void)
{
    printk(KERN_INFO "Registering a editip filter. \n");
    firewallHook.hook = editipFilter;
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
    printk(KERN_INFO "Editip filter has been removed. \n");
    nf_unregister_hook(&firewallHook);
}

module_init(setUpFilter);
module_exit(removeFilter);

MODULE_LICENSE("GPL");
