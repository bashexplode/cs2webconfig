### Automatically Generate Rulesets for IIS for Intelligent HTTP/S C2 Redirection
This project converts a Cobalt Strike profile to a functional web.config file to support HTTP/S reverse proxy redirection from IIS to a Cobalt Strike teamserver.  

This is a spiritual counterpart to [cs2modrewrite](https://github.com/threatexpress/cs2modrewrite).

---------------------------------------------------
#### cs2webconfig.py
Script to generate web.config files for IIS servers based on Cobalt Strike malleable profiles.  

**Usage:**

`python cs2webconfig.py -t <teamserveraddress> -p <c2profile> -r <redirectoraddress> -o <outputfile>`  


---------------------------------------------------
#### applicationHost.xdt  
Template file needed by IIS servers to enable proxying similar to apache2 mod_proxy. Upload to the `site` parent folder of the IIS server, then restart the IIS service.  


---------------------------------------------------
#### Final Thoughts

Once redirection is configured and functioning, ensure your C2 servers only allow ingress from the redirector and your trusted IPs (VPN, office ranges, etc).  

For a quick walkthrough on how to use this with Azure Application Services, check out the [wiki](https://github.com/bashexplode/cs2webconfig/wiki/Azure-Web-Application-Service-Usage)!
