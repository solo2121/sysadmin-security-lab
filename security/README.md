# Security Directory

This directory contains security-focused tools, scripts, and resources for offensive security training and testing. All materials are designed for educational purposes and authorized security assessments only.

## Directory Contents

Organization by security domain:

### Reconnaissance Tools

Network scanning and information gathering utilities:
- Network enumeration and port scanning scripts
- DNS and subdomain discovery tools
- Service fingerprinting utilities
- WHOIS and metadata extraction tools

### Credential Attacks

Tools and techniques for credential-based attacks:
- Brute force attack frameworks
- Dictionary and wordlist utilities
- Hash cracking and verification tools
- Password spray and credential stuffing templates

### Active Directory Exploitation

AD-specific attack tools and frameworks:
- Kerberos exploitation utilities
- LDAP query and enumeration scripts
- Certificate Services (AD CS) exploitation tools
- Group Policy analysis tools
- Account enumeration and dumping utilities

### Web Application Exploitation

Web-based vulnerability assessment tools:
- SQL injection testing frameworks
- Cross-Site Scripting (XSS) testing tools
- Authentication bypass techniques
- API exploitation utilities
- File upload and path traversal tools

### Post-Exploitation

Tools for maintaining access and lateral movement:
- Persistence establishment scripts
- Lateral movement utilities
- Data exfiltration tools
- Credential harvesting and Pass-the-Hash frameworks
- C2 communication templates

### Wireless Security Testing

Wireless network assessment tools:
- Wi-Fi scanning and analysis utilities
- WPA/WPA2 attack frameworks
- Rogue access point tools
- Packet capture and analysis scripts

## Organized By Attack Phase

```
security/
├── reconnaissance/
│   ├── scanning/
│   ├── enumeration/
│   └── fingerprinting/
├── credential-attacks/
│   ├── brute-force/
│   ├── password-spray/
│   └── hash-cracking/
├── active-directory/
│   ├── enumeration/
│   ├── kerberos-attacks/
│   ├── lateral-movement/
│   └── privilege-escalation/
├── web-exploitation/
│   ├── injection/
│   ├── authentication/
│   └── api-attacks/
├── post-exploitation/
│   ├── persistence/
│   ├── lateral-movement/
│   └── exfiltration/
└── wireless/
    ├── wifi-assessment/
    └── rogue-ap/
```

## Usage Guidelines

### Authorization

- All tools must be used only in authorized environments
- Obtain explicit written permission before testing any systems
- Do not use these tools on systems you do not own or have permission to test
- Always follow applicable laws and regulations

### Documentation

Each tool or script should include:
- Clear description of purpose and functionality
- Usage examples and command-line syntax
- Output format and interpretation guide
- Known limitations and caveats
- Legal and ethical considerations

### Best Practices

1. Test in isolated lab environments first
2. Document all tool usage and results
3. Clean up and remove tools after testing
4. Follow proper escalation procedures
5. Maintain chain of custody for evidence

## Tool Categories

### Active Directory Exploitation Techniques

Tools and scripts for AD attack chains:
- User and computer enumeration
- Kerberoasting and AS-REP roasting
- Certificate Services exploitation
- SMB relay attacks
- Privilege escalation vectors
- Persistence mechanisms

### Network Reconnaissance

Tools for external and internal reconnaissance:
- Port scanning and service enumeration
- Network mapping and topology discovery
- WHOIS and DNS information gathering
- Shodan queries and passive reconnaissance
- Metadata extraction from public sources

### Credential Attacks

Frameworks for credential-based attacks:
- Dictionary attacks
- Brute force attacks
- Hybrid attacks (dictionary + rules)
- Credential stuffing techniques
- Default credential checking

### Post-Exploitation

Tools for maintaining access and pivoting:
- Privilege escalation techniques
- Persistence establishment
- Lateral movement utilities
- Data collection and exfiltration
- Log manipulation and evasion

## Contributing

To contribute security tools or scripts:

1. Ensure the tool serves an educational purpose
2. Include comprehensive documentation
3. Add usage examples and expected output
4. Document any external dependencies
5. Include appropriate disclaimers and warnings
6. Follow ethical guidelines and legal requirements

See CONTRIBUTING.md for detailed guidelines.

## Ethical and Legal Considerations

These tools are powerful and can cause significant harm if misused:

- Unauthorized access to computer systems is illegal
- Always obtain proper authorization before testing
- Respect privacy and confidentiality
- Follow responsible disclosure practices
- Report vulnerabilities through proper channels
- Do not use for personal gain or malicious purposes

For security-related concerns, see SECURITY.md

## Resources and References

- MITRE ATT&CK Framework: https://attack.mitre.org/
- OWASP Top 10: https://owasp.org/Top10/
- CIS Controls: https://www.cisecurity.org/controls/
- NIST Cybersecurity Framework: https://www.nist.gov/cyberframework/

## Support and Questions

For questions about specific tools or techniques:
- Check tool documentation and README files
- Review tutorials/ directory for guides
- Consult TROUBLESHOOTING.md
- Open an issue on GitHub for bugs or improvements

## License

All tools and scripts are licensed under the MIT License. See LICENSE file for details.
