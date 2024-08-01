## Requirements

- Wazuh Manager 4.x (https://documentation.wazuh.com/current/installation-guide/index.html)

## Summary

Wazuh integration for analyzing IP addresses using Focsec, identifying associations with VPNs, proxies, TOR, or malicious bots.
In this example, the integration will be triggered by rule 5760, which is received when the sshd authentication fails. It will take the source IP address from the event and query the Focsec API to analyze it.
The integration can be triggered by rule level, rule id, rule groups, and event locations parameters. (https://documentation.wazuh.com/current/user-manual/reference/ossec-conf/integration.html) 

## Implementation

- Add `custom-focsec` and `custom-focsec.py` files to the `/var/ossec/integrations/` directory.

- Set the permissions and ownership for the files:

```
chmod 750 /var/ossec/integrations/custom-focsec*
chown root:ossec /var/ossec/integrations/custom-focsec*
```

Add the required configuration to the `/var/ossec/etc/ossec.conf` file and modify the `api_key`:

```
  <integration>
      <name>custom-focsec</name>
      <hook_url>https://api.focsec.com/v1/ip/</hook_url>
      <api_key>...</api_key>
      <rule_id>5760</rule_id>
      <alert_format>json</alert_format>
  </integration>
```
![image](https://github.com/user-attachments/assets/a33b2a0f-f299-46b9-b967-219a7b36f69b)

- Add the following rules to your /var/ossec/etc/rules/local_rules.xml or custom rule file:

```
<group name="focsec,">

  <rule id="100101" level="0">
    <decoded_as>json</decoded_as>
    <field name="integration">focsec</field>
    <description>General rule for Focsec integration.</description>
  </rule>

  <rule id="100102" level="3">
    <if_sid>100101</if_sid>
    <regex>\pis_\w+\p+\strue</regex>
    <field name="is_bot">false</field>
    <description>Focsec - IP matched: proxy: $(is_proxy), vpn: $(is_vpn), tor: $(is_tor), in european union: $(is_in_european_union), datacenter: $(is_datacenter).</description>
    <group>gdpr_IV_35.7.d,gdpr_IV_32.2,gpg13_7.1,hipaa_164.312.b,nist_800_53_AU.14,nist_800_53_AC.7,pci_dss_10.2.4,pci_dss_10.2.5,tsc_CC6.1,tsc_CC6.8,tsc_CC7.2,tsc_CC7.3,</group>
  </rule>

  <rule id="100103" level="7">
    <if_sid>100101</if_sid>
    <field name="is_bot">true</field>
    <description>Focsec - IP matched: bot: $(is_bot).</description>
    <group>gdpr_IV_35.7.d,gdpr_IV_32.2,gpg13_7.1,hipaa_164.312.b,nist_800_53_AU.14,nist_800_53_AC.7,pci_dss_10.2.4,pci_dss_10.2.5,tsc_CC6.1,tsc_CC6.8,tsc_CC7.2,tsc_CC7.3,</group>
  </rule>

</group>
```
![image](https://github.com/user-attachments/assets/8bf00eb0-6435-4e04-91ed-cf45ca08cc05)

- Restart the Wazuh Manager to apply the changes:

`/var/ossec/bin/wazuh-control restart`

Samples:

![image](https://github.com/user-attachments/assets/2be8a722-ba4c-41e4-9232-50a02c3f3d80)

![image](https://github.com/user-attachments/assets/44de492d-1ccf-4cc8-b943-7681226f1362)

