# Consul Auto Pwning
Python script for auto pwning consul service and integrate with https://app.interactsh.com/

## Usage
```
./consul_pwn.py -l ip.txt
```

## Flow: 
- Get Consul Information
- Dump Stored Key/Value (KV)
- Dump Snapshot 
- RCE !

![Flow](https://github.com/mirfansulaiman/consul_auto_pwning/blob/main/Consul_Auto_Pwning_Flow.png)

## Reference
- https://www.hashicorp.com/blog/protecting-consul-from-rce-risk-in-specific-configurations
