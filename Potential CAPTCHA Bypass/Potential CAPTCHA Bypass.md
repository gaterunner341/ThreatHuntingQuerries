Analysis: Web scrapers are always trolling the web, look for traffic specific to potential scrapers hitting CAPTCHA pages. Further investigation should be performed on IP addresses found.

Splunk
```
TERM(captcha) index=[proxy_index] url_domain=[domain_of_interest]
| bucket _time spam=10m
| stats count by _time c_ip action cs_method http_user_agent url
| where count > 5
| sort - count
```